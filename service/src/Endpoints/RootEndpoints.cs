using SignMeMaybe.Configuration;

namespace SignMeMaybe.Endpoints;

public static class RootEndpoints
{
    public static void MapRootEndpoints(this WebApplication app, ServiceOptions options)
    {
        app.MapGet("/api/info", () => Results.Json(new
        {
            service = "SignMeMaybe",
            message = "Tiny contract signing service for A/D CTF testing.",
            endpoints = new[]
            {
                "GET /",
                "GET /api/info",
                "GET /health",
                "POST /api/register",
                "POST /api/login",
                "GET /api/me",
                "POST /api/contracts",
                "GET /api/contracts",
                "GET /api/links/leave",
                "GET /api/users/{username}/contracts",
                "GET /api/contracts/{reference}/notary/sealed",
                "GET /api/contracts/{reference}/versions/latest",
                "GET /api/contracts/{reference}/versions/latest/pdf"
            }
        }));

        app.MapGet("/health", () => Results.Json(new
        {
            status = "ok",
            service = "SignMeMaybe"
        }));

        if (app.Environment.IsDevelopment())
        {
            app.MapGet("/debug/persistence", () =>
            {
                return Results.Json(new
                {
                    dbPath = options.DbPath,
                    dbExists = File.Exists(options.DbPath),
                    pdfRoot = options.PdfRoot,
                    pdfRootExists = Directory.Exists(options.PdfRoot),
                    exportRoot = options.ExportRoot,
                    exportRootExists = Directory.Exists(options.ExportRoot),
                    notaryVaultRootExists = Directory.Exists(options.NotaryVaultRoot),
                    maxUploadBytes = options.MaxUploadBytes
                });
            });
        }
    }
}
