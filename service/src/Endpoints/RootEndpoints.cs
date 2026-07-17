using SignMeMaybe.Configuration;

namespace SignMeMaybe.Endpoints;

public static class RootEndpoints
{
    public static void MapRootEndpoints(this WebApplication app)
    {
        app.MapGet("/api/info", () => Results.Json(new
        {
            service = "SignMeMaybe",
            message = "Departmental contract registry.",
            status = "online"
        }));

        app.MapGet("/health", () => Results.Json(new
        {
            status = "ok",
            service = "SignMeMaybe"
        }));
    }
}
