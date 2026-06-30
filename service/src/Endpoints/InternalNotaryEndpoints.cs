using System.Net;
using SignMeMaybe.Configuration;
using SignMeMaybe.Data;

namespace SignMeMaybe.Endpoints;

public static class InternalNotaryEndpoints
{
    private const string RenderWorkerHeaderName = "X-SignMeMaybe-Render-Worker";
    private const string RenderWorkerHeaderValue = "certified-pdf-v2";

    public static void MapInternalNotaryEndpoints(this WebApplication app, ServiceOptions options)
    {
        app.MapGet("/internal/notary/sealed/{publicStamp}", (HttpContext httpContext, string publicStamp) =>
            GetSealedRecord(httpContext, publicStamp, options));
    }

    private static IResult GetSealedRecord(
        HttpContext httpContext,
        string publicStamp,
        ServiceOptions options)
    {
        var remoteAddress = httpContext.Connection.RemoteIpAddress;
        if (remoteAddress is null || !IPAddress.IsLoopback(remoteAddress))
        {
            return Results.NotFound();
        }

        if (!httpContext.Request.Headers.TryGetValue(RenderWorkerHeaderName, out var header)
            || !string.Equals(header.ToString(), RenderWorkerHeaderValue, StringComparison.Ordinal))
        {
            return Results.NotFound();
        }

        using var connection = Database.OpenConnection(options.DbPath);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT secret_path, display_name
            FROM notary_secrets
            WHERE public_stamp = $public_stamp
            LIMIT 1;
            """;
        Database.AddParameter(command, "$public_stamp", publicStamp);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return Results.NotFound();
        }

        var secretPath = reader.GetString(0);
        var displayName = reader.GetString(1);
        if (!File.Exists(secretPath))
        {
            return Results.NotFound();
        }

        return Results.File(secretPath, "application/octet-stream", displayName);
    }
}
