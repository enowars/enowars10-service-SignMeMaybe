using System.Net;
using System.Net.Sockets;

namespace SignMeMaybe.Documents;

public static class RemoteAnnexFetcher
{
    private const int MaxAnnexes = 2;
    private const int MaxAnnexBytes = 32 * 1024;
    private const int MaxRedirects = 5;
    private const string InternalNotaryPathPrefix = "/internal/notary/sealed/";
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

        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler)
        {
            Timeout = FetchTimeout
        };

        var attachments = new List<PdfAttachment>();
        foreach (var directive in directives.Take(MaxAnnexes))
        {
            if (!await IsAllowedInitialUriAsync(directive.Uri, cancellationToken))
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
            var currentUri = directive.Uri;

            for (var redirectCount = 0; redirectCount <= MaxRedirects; redirectCount++)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, currentUri);
                if (IsAllowedInternalNotaryUri(currentUri))
                {
                    request.Headers.TryAddWithoutValidation(RenderWorkerHeaderName, RenderWorkerHeaderValue);
                }

                using var response = await client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);

                if (IsRedirectStatus(response.StatusCode))
                {
                    if (redirectCount == MaxRedirects)
                    {
                        return null;
                    }

                    var redirectUri = ResolveRedirectUri(currentUri, response.Headers.Location);
                    if (redirectUri is null || !await IsAllowedRedirectUriAsync(redirectUri, cancellationToken))
                    {
                        return null;
                    }

                    currentUri = redirectUri;
                    continue;
                }

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

            return null;
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

    private static async Task<bool> IsAllowedInitialUriAsync(Uri uri, CancellationToken cancellationToken)
    {
        if (!IsHttpUri(uri))
        {
            return false;
        }

        var host = uri.Host.Trim().Trim('[', ']').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        if (host == "localhost" || host.EndsWith(".localhost", StringComparison.Ordinal))
        {
            return false;
        }

        return await HostResolvesSafelyAsync(host, cancellationToken);
    }

    private static async Task<bool> IsAllowedRedirectUriAsync(Uri uri, CancellationToken cancellationToken)
    {
        if (IsAllowedInternalNotaryUri(uri))
        {
            return true;
        }

        return await IsAllowedInitialUriAsync(uri, cancellationToken);
    }

    private static bool IsAllowedInternalNotaryUri(Uri uri)
    {
        return string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && string.Equals(uri.Host, "127.0.0.1", StringComparison.Ordinal)
            && uri.Port > 0
            && uri.AbsolutePath.StartsWith(InternalNotaryPathPrefix, StringComparison.Ordinal)
            && uri.AbsolutePath.Length > InternalNotaryPathPrefix.Length
            && string.IsNullOrEmpty(uri.Query)
            && string.IsNullOrEmpty(uri.Fragment);
    }

    private static bool IsHttpUri(Uri uri)
    {
        return string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            || string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<bool> HostResolvesSafelyAsync(string host, CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(host, out var address))
        {
            return !IsBlockedAddress(address);
        }

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(host).WaitAsync(cancellationToken);
            return addresses.Length > 0 && addresses.All(resolved => !IsBlockedAddress(resolved));
        }
        catch (Exception ex) when (ex is SocketException
            or ArgumentException
            or OperationCanceledException)
        {
            return false;
        }
    }

    private static bool IsRedirectStatus(HttpStatusCode statusCode)
    {
        var code = (int)statusCode;
        return code is >= 300 and <= 399;
    }

    private static Uri? ResolveRedirectUri(Uri currentUri, Uri? location)
    {
        if (location is null)
        {
            return null;
        }

        return location.IsAbsoluteUri
            ? location
            : new Uri(currentUri, location);
    }

    private static bool IsBlockedAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return IPAddress.IsLoopback(address)
            || address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.IPv6Any);
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
