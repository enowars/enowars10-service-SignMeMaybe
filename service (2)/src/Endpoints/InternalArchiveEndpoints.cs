using System.Net;
using SignMeMaybe.Configuration;
using SignMeMaybe.Data;

namespace SignMeMaybe.Endpoints;

public static class InternalArchiveEndpoints
{
    private const string PdfWorkerHeaderName = "X-SignMeMaybe-Pdf-Worker";
    private const string PdfWorkerHeaderValue = "annex-worker-v2";

    public static void MapInternalArchiveEndpoints(this WebApplication app, ServiceOptions options)
    {
        app.MapGet("/internal/archive/packets/{ticket}", (HttpContext httpContext, string ticket) =>
            GetArchivePacket(httpContext, ticket, options));
    }

    private static IResult GetArchivePacket(
        HttpContext httpContext,
        string ticket,
        ServiceOptions options)
    {
        var remoteAddress = httpContext.Connection.RemoteIpAddress;
        if (remoteAddress is null || !IPAddress.IsLoopback(remoteAddress))
        {
            return Results.NotFound();
        }

        if (!httpContext.Request.Headers.TryGetValue(PdfWorkerHeaderName, out var header)
            || !string.Equals(header.ToString(), PdfWorkerHeaderValue, StringComparison.Ordinal))
        {
            return Results.NotFound();
        }

        using var connection = Database.OpenConnection(options.DbPath);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT file_path, display_name
            FROM contract_packets
            WHERE public_ticket = $public_ticket
            LIMIT 1;
            """;
        Database.AddParameter(command, "$public_ticket", ticket);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return Results.NotFound();
        }

        var packetPath = reader.GetString(0);
        var displayName = reader.GetString(1);
        if (!File.Exists(packetPath))
        {
            return Results.NotFound();
        }

        return Results.File(packetPath, "application/octet-stream", displayName);
    }
}
