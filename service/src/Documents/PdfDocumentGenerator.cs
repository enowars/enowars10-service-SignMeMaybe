using System.Text;

namespace SignMeMaybe.Documents;

public static class PdfDocumentGenerator
{
    private const int PageWidth = 612;
    private const int PageHeight = 792;
    private const int LinesPerPage = 48;
    private const int MaxLineLength = 88;

    public static void WriteContractPdf(string filePath, string title, string content)
    {
        var lines = BuildLines(title, content);
        var pages = lines.Chunk(LinesPerPage).ToList();
        if (pages.Count == 0)
        {
            pages.Add(Array.Empty<string>());
        }

        File.WriteAllBytes(filePath, BuildPdf(pages));
    }

    private static List<string> BuildLines(string title, string content)
    {
        var lines = new List<string>
        {
            "SignMeMaybe Contract Record",
            $"Title: {title}",
            $"Generated: {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC",
            "",
            "Content:"
        };

        foreach (var paragraph in content.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            lines.AddRange(WrapLine(paragraph, MaxLineLength));
        }

        return lines;
    }

    private static IEnumerable<string> WrapLine(string line, int maxLength)
    {
        if (line.Length == 0)
        {
            yield return "";
            yield break;
        }

        var remaining = line;
        while (remaining.Length > maxLength)
        {
            var splitAt = remaining.LastIndexOf(' ', maxLength);
            if (splitAt <= 0)
            {
                splitAt = maxLength;
            }

            yield return remaining[..splitAt].TrimEnd();
            remaining = remaining[splitAt..].TrimStart();
        }

        yield return remaining;
    }

    private static byte[] BuildPdf(IReadOnlyList<string[]> pages)
    {
        var objects = new List<(int Id, byte[] Bytes)>();
        var pageObjectIds = Enumerable.Range(0, pages.Count)
            .Select(index => 4 + index * 2)
            .ToList();

        objects.Add((1, PdfBytes("<< /Type /Catalog /Pages 2 0 R >>")));
        objects.Add((2, PdfBytes($"<< /Type /Pages /Kids [{string.Join(" ", pageObjectIds.Select(id => $"{id} 0 R"))}] /Count {pages.Count} >>")));
        objects.Add((3, PdfBytes("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")));

        for (var index = 0; index < pages.Count; index++)
        {
            var pageObjectId = 4 + index * 2;
            var contentObjectId = pageObjectId + 1;
            var stream = BuildPageStream(pages[index]);

            objects.Add((pageObjectId, PdfBytes($"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PageWidth} {PageHeight}] /Resources << /Font << /F1 3 0 R >> >> /Contents {contentObjectId} 0 R >>")));
            objects.Add((contentObjectId, PdfBytes($"<< /Length {stream.Length} >>\nstream\n{stream}\nendstream")));
        }

        using var output = new MemoryStream();
        WriteAscii(output, "%PDF-1.4\n");

        var offsets = new Dictionary<int, long>();
        foreach (var (id, bytes) in objects.OrderBy(item => item.Id))
        {
            offsets[id] = output.Position;
            WriteAscii(output, $"{id} 0 obj\n");
            output.Write(bytes);
            WriteAscii(output, "\nendobj\n");
        }

        var xrefOffset = output.Position;
        var maxObjectId = objects.Max(item => item.Id);
        WriteAscii(output, $"xref\n0 {maxObjectId + 1}\n");
        WriteAscii(output, "0000000000 65535 f \n");

        for (var id = 1; id <= maxObjectId; id++)
        {
            WriteAscii(output, $"{offsets[id]:0000000000} 00000 n \n");
        }

        WriteAscii(output, $"trailer\n<< /Size {maxObjectId + 1} /Root 1 0 R >>\nstartxref\n{xrefOffset}\n%%EOF\n");
        return output.ToArray();
    }

    private static string BuildPageStream(IEnumerable<string> lines)
    {
        var builder = new StringBuilder();
        builder.AppendLine("BT");
        builder.AppendLine("/F1 11 Tf");
        builder.AppendLine("50 750 Td");
        builder.AppendLine("14 TL");

        foreach (var line in lines)
        {
            builder.AppendLine($"({EscapePdfText(ToPdfText(line))}) Tj");
            builder.AppendLine("T*");
        }

        builder.Append("ET");
        return builder.ToString();
    }

    private static string ToPdfText(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            builder.Append(c <= 255 ? c : '?');
        }

        return builder.ToString();
    }

    private static string EscapePdfText(string value)
    {
        return value
            .Replace("\\", "\\\\")
            .Replace("(", "\\(")
            .Replace(")", "\\)");
    }

    private static byte[] PdfBytes(string value)
    {
        return Encoding.ASCII.GetBytes(value);
    }

    private static void WriteAscii(Stream stream, string value)
    {
        stream.Write(Encoding.ASCII.GetBytes(value));
    }
}
