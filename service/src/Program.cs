using System.Text.Json;
using SignMeMaybe.Configuration;
using SignMeMaybe.Data;
using SignMeMaybe.Endpoints;
using SignMeMaybe.Maintenance;

if (args.Any(arg => string.Equals(arg, "--cleanup-once", StringComparison.OrdinalIgnoreCase)))
{
    var cleanupOptions = ServiceOptions.LoadFromEnvironment();
    cleanupOptions.EnsureStorageExists();

    Database.Initialize(cleanupOptions.DbPath);
    var result = CleanupRunner.Run(cleanupOptions);
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
app.MapRazorPages();

app.Run();

public partial class Program;
