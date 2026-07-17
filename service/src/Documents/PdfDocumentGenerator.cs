using System.Text;

namespace SignMeMaybe.Documents;

public sealed record PdfAttachment(
    string FileName,
    string MimeType,
    byte[] Content);

public static class PdfDocumentGenerator
{
    private const int PageWidth = 612;
    private const int PageHeight = 792;
    private const int LinesPerPage = 48;
    private const int MaxLineLength = 88;

    public static void WriteContractPdf(
        string filePath,
        string title,
        string content,
        IReadOnlyList<PdfAttachment>? attachments = null)
    {
        File.WriteAllBytes(filePath, CreateContractPdf(title, content, attachments));
    }

    public static byte[] CreateContractPdf(
        string title,
        string content,
        IReadOnlyList<PdfAttachment>? attachments = null)
    {
        var lines = BuildLines(title, content);
        var pages = lines.Chunk(LinesPerPage).ToList();
        if (pages.Count == 0)
        {
            pages.Add(Array.Empty<string>());
        }

        return BuildPdf(pages, attachments);
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

    private static byte[] BuildPdf(
        IReadOnlyList<string[]> pages,
        IReadOnlyList<PdfAttachment>? attachments)
    {
        var objects = new List<(int Id, byte[] Bytes)>();
        var pageObjectIds = Enumerable.Range(0, pages.Count)
            .Select(index => 4 + index * 2)
            .ToList();
        var normalizedAttachments = NormalizeAttachments(attachments);
        var firstAttachmentObjectId = 4 + pages.Count * 2;
        var embeddedFilesNameTreeId = normalizedAttachments.Count > 0
            ? firstAttachmentObjectId + normalizedAttachments.Count * 2
            : 0;

        var catalog = normalizedAttachments.Count > 0
            ? $"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles {embeddedFilesNameTreeId} 0 R >> >>"
            : "<< /Type /Catalog /Pages 2 0 R >>";

        objects.Add((1, PdfBytes(catalog)));
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

        if (normalizedAttachments.Count > 0)
        {
            var nameEntries = new List<string>();
            for (var index = 0; index < normalizedAttachments.Count; index++)
            {
                var attachment = normalizedAttachments[index];
                var filespecObjectId = firstAttachmentObjectId + index * 2;
                var embeddedFileObjectId = filespecObjectId + 1;
                var fileName = EscapePdfString(attachment.FileName);
                var subtype = EscapePdfName(attachment.MimeType);

                objects.Add((filespecObjectId, PdfBytes(
                    $"<< /Type /Filespec /F ({fileName}) /UF ({fileName}) /EF << /F {embeddedFileObjectId} 0 R >> /Desc (Certified contract annex) >>")));
                objects.Add((embeddedFileObjectId, BuildStreamObject(
                    $"<< /Type /EmbeddedFile /Subtype /{subtype} /Length {attachment.Content.Length} >>",
                    attachment.Content)));
                nameEntries.Add($"({fileName}) {filespecObjectId} 0 R");
            }

            objects.Add((embeddedFilesNameTreeId, PdfBytes($"<< /Names [{string.Join(" ", nameEntries)}] >>")));
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

    private static byte[] BuildStreamObject(string dictionary, byte[] streamBytes)
    {
        using var output = new MemoryStream();
        WriteAscii(output, dictionary);
        WriteAscii(output, "\nstream\n");
        output.Write(streamBytes);
        WriteAscii(output, "\nendstream");
        return output.ToArray();
    }

    private static IReadOnlyList<PdfAttachment> NormalizeAttachments(IReadOnlyList<PdfAttachment>? attachments)
    {
        if (attachments is null || attachments.Count == 0)
        {
            return Array.Empty<PdfAttachment>();
        }

        return attachments
            .Where(attachment => attachment.Content.Length > 0)
            .Select(attachment => new PdfAttachment(
                SanitizeAttachmentName(attachment.FileName),
                string.IsNullOrWhiteSpace(attachment.MimeType)
                    ? "application/octet-stream"
                    : attachment.MimeType.Trim(),
                attachment.Content))
            .ToList();
    }

    private static string EscapePdfString(string value)
    {
        return value
            .Replace("\\", "\\\\")
            .Replace("(", "\\(")
            .Replace(")", "\\)");
    }

    private static string EscapePdfName(string value)
    {
        return value
            .Replace("#", "#23")
            .Replace("/", "#2F")
            .Replace(" ", "#20");
    }

    private static string SanitizeAttachmentName(string value)
    {
        var name = Path.GetFileName(value.Trim());

        if (string.IsNullOrWhiteSpace(name))
        {
            return "annex.bin";
        }

        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(name.Select(c => invalid.Contains(c) ? '_' : c).ToArray());

        if (string.IsNullOrWhiteSpace(cleaned))
        {
            return "annex.bin";
        }

        return cleaned.Length > 128 ? cleaned[..128] : cleaned;
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
