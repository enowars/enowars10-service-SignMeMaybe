namespace SignMeMaybe.Documents;

public static class RemoteAnnexFetcher
{
    private const int MaxAnnexes = 2;
    private const int MaxAnnexBytes = 32 * 1024;
    private const string RenderWorkerHeaderName = "X-SignMeMaybe-Render-Worker";
    private const string RenderWorkerHeaderValue = "certified-pdf-v2";
    private static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(2);

    public static async Task<IReadOnlyList<PdfAttachment>> FetchAsync(
        IReadOnlyList<AnnexDirective> directives,
        CancellationToken cancellationToken = default)
    {
        if (directives.Count == 0)
        {
            return Array.Empty<PdfAttachment>();
        }

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5
        };
        using var client = new HttpClient(handler)
        {
            Timeout = FetchTimeout
        };

        var attachments = new List<PdfAttachment>();
        foreach (var directive in directives.Take(MaxAnnexes))
        {
            if (!IsAllowedInitialUri(directive.Uri))
            {
                continue;
            }

            var attachment = await FetchOneAsync(client, directive, cancellationToken);
            if (attachment is not null)
            {
                attachments.Add(attachment);
            }
        }

        return attachments;
    }

    private static async Task<PdfAttachment?> FetchOneAsync(
        HttpClient client,
        AnnexDirective directive,
        CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, directive.Uri);
            request.Headers.TryAddWithoutValidation(RenderWorkerHeaderName, RenderWorkerHeaderValue);

            using var response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            if (response.Content.Headers.ContentLength is > MaxAnnexBytes)
            {
                return null;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            var content = await ReadLimitedAsync(stream, cancellationToken);
            if (content is null)
            {
                return null;
            }

            return new PdfAttachment(
                directive.FileName,
                SafeMimeType(response.Content.Headers.ContentType?.MediaType),
                content);
        }
        catch (Exception ex) when (ex is HttpRequestException
            or TaskCanceledException
            or OperationCanceledException
            or IOException
            or InvalidOperationException)
        {
            return null;
        }
    }

    private static async Task<byte[]?> ReadLimitedAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[8192];

        while (true)
        {
            var remaining = MaxAnnexBytes + 1 - (int)output.Length;
            if (remaining <= 0)
            {
                return null;
            }

            var read = await stream.ReadAsync(
                buffer.AsMemory(0, Math.Min(buffer.Length, remaining)),
                cancellationToken);
            if (read == 0)
            {
                break;
            }

            output.Write(buffer, 0, read);
            if (output.Length > MaxAnnexBytes)
            {
                return null;
            }
        }

        return output.ToArray();
    }

    private static bool IsAllowedInitialUri(Uri uri)
    {
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var host = uri.Host.Trim().Trim('[', ']').ToLowerInvariant();
        return host is not "localhost"
            and not "127.0.0.1"
            and not "::1"
            and not "0.0.0.0"
            && !host.StartsWith("127.", StringComparison.Ordinal);
    }

    private static string SafeMimeType(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "application/octet-stream";
        }

        var trimmed = value.Trim().ToLowerInvariant();
        return trimmed.All(c => char.IsLetterOrDigit(c) || c is '/' or '.' or '-' or '+')
            ? trimmed
            : "application/octet-stream";
    }
}
