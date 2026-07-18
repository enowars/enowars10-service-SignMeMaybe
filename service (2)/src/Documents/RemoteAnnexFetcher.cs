using System.Net;
using System.Net.Sockets;

namespace SignMeMaybe.Documents;

public static class RemoteAnnexFetcher
{
    private const int MaxAnnexes = 2;
    private const int MaxAnnexBytes = 32 * 1024;
    private const int MaxRedirects = 5;
    private const string InternalArchivePathPrefix = "/internal/archive/packets/";
    private const string LeavePath = "/api/links/leave";
    private const string PdfWorkerHeaderName = "X-SignMeMaybe-Pdf-Worker";
    private const string PdfWorkerHeaderValue = "annex-worker-v2";
    private static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(2);
    private static readonly HttpRequestOptionsKey<IPAddress> ApprovedAddressOption = new("SignMeMaybe.ApprovedAnnexAddress");

    public static async Task<IReadOnlyList<PdfAttachment>> FetchAsync(
        IReadOnlyList<AnnexDirective> directives,
        string serviceHost,
        CancellationToken cancellationToken = default)
    {
        if (directives.Count == 0)
        {
            return Array.Empty<PdfAttachment>();
        }

        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectCallback = ConnectPinnedAsync
        };
        using var client = new HttpClient(handler)
        {
            Timeout = FetchTimeout
        };

        var attachments = new List<PdfAttachment>();
        foreach (var directive in directives.Take(MaxAnnexes))
        {
            var target = await ResolveInitialTargetAsync(directive.Uri, serviceHost, cancellationToken);
            if (target is null)
            {
                continue;
            }

            var attachment = await FetchOneAsync(client, directive, target, serviceHost, cancellationToken);
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
        ResolvedAnnexTarget initialTarget,
        string serviceHost,
        CancellationToken cancellationToken)
    {
        try
        {
            var currentTarget = initialTarget;

            for (var redirectCount = 0; redirectCount <= MaxRedirects; redirectCount++)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, currentTarget.Uri);
                request.Options.Set(ApprovedAddressOption, currentTarget.Address);
                if (currentTarget.IsInternalArchivePacket)
                {
                    request.Headers.TryAddWithoutValidation(PdfWorkerHeaderName, PdfWorkerHeaderValue);
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

                    var redirectUri = ResolveRedirectUri(currentTarget.Uri, response.Headers.Location);
                    if (redirectUri is null)
                    {
                        return null;
                    }

                    var redirectTarget = await ResolveRedirectTargetAsync(redirectUri, serviceHost, cancellationToken);
                    if (redirectTarget is null)
                    {
                        return null;
                    }

                    currentTarget = redirectTarget;
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

    private static async Task<ResolvedAnnexTarget?> ResolveInitialTargetAsync(
        Uri uri,
        string serviceHost,
        CancellationToken cancellationToken)
    {
        if (!IsHttpUri(uri))
        {
            return null;
        }

        var sameServiceLeave = IsSameServiceLeaveUri(uri, serviceHost);
        var address = await ResolveApprovedAddressAsync(uri, allowServiceAddress: sameServiceLeave, cancellationToken);
        if (address is null)
        {
            return null;
        }

        return new ResolvedAnnexTarget(uri, address, IsInternalArchivePacket: false);
    }

    private static async Task<ResolvedAnnexTarget?> ResolveRedirectTargetAsync(
        Uri uri,
        string serviceHost,
        CancellationToken cancellationToken)
    {
        if (IsAllowedInternalArchivePacketUri(uri, serviceHost))
        {
            return new ResolvedAnnexTarget(uri, IPAddress.Loopback, IsInternalArchivePacket: true);
        }

        return await ResolveInitialTargetAsync(uri, serviceHost, cancellationToken);
    }

    private static bool IsAllowedInternalArchivePacketUri(Uri uri, string serviceHost)
    {
        var expectedPort = TryParseServicePort(serviceHost);
        return string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && string.Equals(uri.Host, "127.0.0.1", StringComparison.Ordinal)
            && uri.Port > 0
            && (expectedPort is null || uri.Port == expectedPort.Value)
            && uri.AbsolutePath.StartsWith(InternalArchivePathPrefix, StringComparison.Ordinal)
            && uri.AbsolutePath.Length > InternalArchivePathPrefix.Length
            && string.IsNullOrEmpty(uri.Query)
            && string.IsNullOrEmpty(uri.Fragment);
    }

    private static bool IsHttpUri(Uri uri)
    {
        return string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            || string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSameServiceLeaveUri(Uri uri, string serviceHost)
    {
        if (!IsHttpUri(uri)
            || !string.Equals(uri.AbsolutePath, LeavePath, StringComparison.Ordinal)
            || string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            return false;
        }

        return HostMatches(uri, serviceHost);
    }

    private static bool HostMatches(Uri uri, string serviceHost)
    {
        if (string.IsNullOrWhiteSpace(serviceHost)
            || !Uri.TryCreate("http://" + serviceHost, UriKind.Absolute, out var serviceUri))
        {
            return false;
        }

        return string.Equals(uri.Host, serviceUri.Host, StringComparison.OrdinalIgnoreCase)
            && EffectivePort(uri) == EffectivePort(serviceUri);
    }

    private static int? TryParseServicePort(string serviceHost)
    {
        if (string.IsNullOrWhiteSpace(serviceHost)
            || !Uri.TryCreate("http://" + serviceHost, UriKind.Absolute, out var serviceUri))
        {
            return null;
        }

        return EffectivePort(serviceUri);
    }

    private static int EffectivePort(Uri uri)
    {
        if (!uri.IsDefaultPort)
        {
            return uri.Port;
        }

        return string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            ? 443
            : 80;
    }

    private static async Task<IPAddress?> ResolveApprovedAddressAsync(
        Uri uri,
        bool allowServiceAddress,
        CancellationToken cancellationToken)
    {
        var host = uri.Host.Trim().Trim('[', ']').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(host))
        {
            return null;
        }

        if (!allowServiceAddress
            && (host == "localhost" || host.EndsWith(".localhost", StringComparison.Ordinal)))
        {
            return null;
        }

        if (IPAddress.TryParse(host, out var address))
        {
            address = NormalizeAddress(address);
            return IsAddressAllowed(address, allowServiceAddress) ? address : null;
        }

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(host).WaitAsync(cancellationToken);
            if (addresses.Length == 0)
            {
                return null;
            }

            var normalized = addresses.Select(NormalizeAddress).ToArray();
            return normalized.All(resolved => IsAddressAllowed(resolved, allowServiceAddress))
                ? normalized[0]
                : null;
        }
        catch (Exception ex) when (ex is SocketException
            or ArgumentException
            or OperationCanceledException)
        {
            return null;
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

    private static async ValueTask<Stream> ConnectPinnedAsync(
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        if (!context.InitialRequestMessage.Options.TryGetValue(ApprovedAddressOption, out var address))
        {
            throw new HttpRequestException("annex target was not resolved");
        }

        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static IPAddress NormalizeAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4();
        }

        return address;
    }

    private static bool IsAddressAllowed(IPAddress address, bool allowServiceAddress)
    {
        address = NormalizeAddress(address);

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return allowServiceAddress
                ? !IsInvalidServiceAddress(address)
                : !IsBlockedPublicAddress(address);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return allowServiceAddress
                ? !IsInvalidServiceAddress(address)
                : !IsBlockedPublicAddress(address);
        }

        return false;
    }

    private static bool IsInvalidServiceAddress(IPAddress address)
    {
        return address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.IPv6Any)
            || IsMulticastAddress(address);
    }

    private static bool IsBlockedPublicAddress(IPAddress address)
    {
        return IsInvalidServiceAddress(address)
            || IPAddress.IsLoopback(address)
            || IsLinkLocalAddress(address)
            || IsPrivateAddress(address)
            || IsMulticastAddress(address);
    }

    private static bool IsLinkLocalAddress(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] == 169 && bytes[1] == 254;
        }

        return address.IsIPv6LinkLocal;
    }

    private static bool IsMulticastAddress(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return address.GetAddressBytes()[0] >= 224;
        }

        return address.IsIPv6Multicast;
    }

    private static bool IsPrivateAddress(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] == 10
                || bytes[0] == 0
                || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 100 && bytes[1] is >= 64 and <= 127);
        }

        var ipv6Bytes = address.GetAddressBytes();
        return (ipv6Bytes[0] & 0xfe) == 0xfc;
    }

    private sealed record ResolvedAnnexTarget(
        Uri Uri,
        IPAddress Address,
        bool IsInternalArchivePacket);

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
