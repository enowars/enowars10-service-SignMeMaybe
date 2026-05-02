using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/", () => "Hello World!\n");

app.MapGet("/health", () =>
{
    var response = new
    {
        status = "ok",
        service = "SignMeMaybe"
    };

    return Results.Text(
        JsonSerializer.Serialize(response) + "\n",
        contentType: "application/json"
    );
});

app.Run();