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
    try
    {
        result = CleanupRunner.Run(cleanupOptions);
    }
    catch (SqliteException ex) when (Database.IsBusyOrLocked(ex))
    {
        Console.WriteLine("cleanup skipped: database is busy");
        return;
    }

    Console.WriteLine(
        "cleanup complete: " +
        $"files={result.DeletedFiles} " +
        $"sessions={result.DeletedSessions} " +
        $"contracts={result.DeletedContracts} " +
        $"exports={result.DeletedExports} " +
        $"users={result.DeletedUsers}");
    return;
}

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.SerializerOptions.WriteIndented = true;
});

var app = builder.Build();

var options = ServiceOptions.LoadFromEnvironment();
options.EnsureStorageExists();

Database.Initialize(options.DbPath);

app.UseStaticFiles();

app.MapRootEndpoints(options);
app.MapAuthEndpoints(options);
app.MapContractEndpoints(options);
app.MapInternalNotaryEndpoints(options);
app.MapSigningEndpoints(options);
app.MapRazorPages();

app.Run();

public partial class Program;
