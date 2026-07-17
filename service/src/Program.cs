using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SignMeMaybe.Configuration;
using SignMeMaybe.Data;
using SignMeMaybe.Endpoints;
using SignMeMaybe.Maintenance;

if (args.Any(arg => string.Equals(arg, "--cleanup-once", StringComparison.OrdinalIgnoreCase)))
{
    var cleanupOptions = ServiceOptions.LoadFromEnvironment();
    cleanupOptions.EnsureStorageExists();

    if (!File.Exists(cleanupOptions.DbPath))
    {
        Console.WriteLine("cleanup skipped: database does not exist yet");
        return;
    }

    CleanupResult result;
    var cleanupStopwatch = Stopwatch.StartNew();
    try
    {
        result = CleanupRunner.Run(cleanupOptions);
    }
    catch (SqliteException ex) when (Database.IsBusyOrLocked(ex))
    {
        cleanupStopwatch.Stop();
        Console.WriteLine($"cleanup skipped: database is busy elapsedMs={cleanupStopwatch.ElapsedMilliseconds}");
        return;
    }
    cleanupStopwatch.Stop();

    Console.WriteLine(
        "cleanup complete: " +
        $"files={result.DeletedFiles} " +
        $"sessions={result.DeletedSessions} " +
        $"contracts={result.DeletedContracts} " +
        $"exports={result.DeletedExports} " +
        $"users={result.DeletedUsers} " +
        $"elapsedMs={cleanupStopwatch.ElapsedMilliseconds}");
    return;
}

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.SerializerOptions.WriteIndented = false;
});

var app = builder.Build();

var options = ServiceOptions.LoadFromEnvironment();
options.EnsureStorageExists();

Database.Initialize(options.DbPath);

var slowRequestThresholdMsRaw = Environment.GetEnvironmentVariable("SIGNMEMAYBE_SLOW_REQUEST_MS");
var slowRequestThresholdMs = int.TryParse(slowRequestThresholdMsRaw, out var parsedSlowRequestThresholdMs)
    && parsedSlowRequestThresholdMs > 0
        ? parsedSlowRequestThresholdMs
        : 1_000;

app.Use(async (context, next) =>
{
    var stopwatch = Stopwatch.StartNew();
    try
    {
        await next();
    }
    finally
    {
        stopwatch.Stop();
        if (stopwatch.ElapsedMilliseconds >= slowRequestThresholdMs)
        {
            Console.WriteLine(
                "slow request: " +
                $"method={context.Request.Method} " +
                $"path={context.Request.Path} " +
                $"status={context.Response.StatusCode} " +
                $"elapsedMs={stopwatch.ElapsedMilliseconds}");
        }
    }
});

app.UseStaticFiles();

app.MapRootEndpoints();
app.MapAuthEndpoints(options);
app.MapContractEndpoints(options);
app.MapInternalArchiveEndpoints(options);
app.MapSigningEndpoints(options);
app.MapRazorPages();

app.Run();

public partial class Program;
