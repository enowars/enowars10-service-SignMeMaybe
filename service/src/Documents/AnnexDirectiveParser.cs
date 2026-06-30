using System.Text.RegularExpressions;

namespace SignMeMaybe.Documents;

public sealed record AnnexDirective(
    Uri Uri,
    string FileName);

public static class AnnexDirectiveParser
{
    private const int MaxDirectives = 2;

    private static readonly Regex LinkTagPattern = new(
        @"<\s*link\b(?<attributes>[^<>]*)>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex AttributePattern = new(
        "(?<name>[A-Za-z_:][A-Za-z0-9_:\\-.]*)\\s*(?:=\\s*(?:\"(?<double>[^\"]*)\"|'(?<single>[^']*)'|(?<bare>[^\\s\"'=<>`]+)))?",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static IReadOnlyList<AnnexDirective> Parse(string content)
    {
        var directives = new List<AnnexDirective>();

        foreach (Match tagMatch in LinkTagPattern.Matches(content))
        {
            if (directives.Count >= MaxDirectives)
            {
                break;
            }

            var attributes = ParseAttributes(tagMatch.Groups["attributes"].Value);
            if (!attributes.TryGetValue("rel", out var rel)
                || !string.Equals(rel, "attachment", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!attributes.TryGetValue("href", out var href)
                || !Uri.TryCreate(href, UriKind.Absolute, out var uri))
            {
                continue;
            }

            var fileName = attributes.TryGetValue("title", out var title)
                ? SanitizeAttachmentName(title)
                : "annex.bin";

            directives.Add(new AnnexDirective(uri, fileName));
        }

        return directives;
    }

    private static Dictionary<string, string> ParseAttributes(string value)
    {
        var attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (Match match in AttributePattern.Matches(value))
        {
            var name = match.Groups["name"].Value;
            var attributeValue = match.Groups["double"].Success
                ? match.Groups["double"].Value
                : match.Groups["single"].Success
                    ? match.Groups["single"].Value
                    : match.Groups["bare"].Success
                        ? match.Groups["bare"].Value
                        : "";

            attributes[name] = attributeValue;
        }

        return attributes;
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
}
