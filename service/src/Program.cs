using System.Text.Json;
using SignMeMaybe.Configuration;
using SignMeMaybe.Data;
using SignMeMaybe.Endpoints;

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
