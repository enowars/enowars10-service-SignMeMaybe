using Microsoft.Data.Sqlite;
using SignMeMaybe.Configuration;
using SignMeMaybe.Data;
using SignMeMaybe.Models;
using SignMeMaybe.Security;

namespace SignMeMaybe.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this WebApplication app, ServiceOptions options)
    {
        app.MapPost("/api/register", async (HttpRequest httpRequest, RegisterRequest request) =>
            await Register(httpRequest, request, options));
        app.MapPost("/api/login", async (HttpRequest httpRequest, LoginRequest request) =>
            await Login(httpRequest, request, options));
        app.MapGet("/api/me", (HttpRequest httpRequest) => Me(httpRequest, options));
    }

    private static async Task<IResult> Register(
        HttpRequest httpRequest,
        RegisterRequest request,
        ServiceOptions options)
    {
        var validationError = AuthService.ValidateCredentials(request.Username, request.Password);
        if (validationError is not null)
        {
            return Results.BadRequest(new { error = validationError });
        }

        var username = request.Username.Trim();
        var passwordHash = Hashing.HashPassword(request.Password);

        using var writeLease = await DatabaseWriteGate.EnterAsync(httpRequest.HttpContext.RequestAborted);
        using var connection = Database.OpenConnection(options.DbPath);

        try
        {
            using var insertUser = connection.CreateCommand();
            insertUser.CommandText = """
                INSERT INTO users (username, password_hash)
                VALUES ($username, $password_hash);
                SELECT last_insert_rowid();
                """;
            Database.AddParameter(insertUser, "$username", username);
            Database.AddParameter(insertUser, "$password_hash", passwordHash);

            var userId = Convert.ToInt64(insertUser.ExecuteScalar());
            var token = AuthService.CreateSession(connection, userId);

            return Results.Ok(new
            {
                userId,
                username,
                token
            });
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            return Results.Conflict(new { error = "username already exists" });
        }
    }

    private static async Task<IResult> Login(
        HttpRequest httpRequest,
        LoginRequest request,
        ServiceOptions options)
    {
        var requestedUsername = request.Username.Trim();

        long userId;
        string username;
        string expectedPasswordHash;

        using (var readConnection = Database.OpenConnection(options.DbPath))
        {
            using var command = readConnection.CreateCommand();
            command.CommandText = """
                SELECT id, username, password_hash
                FROM users
                WHERE username = $username
                LIMIT 1;
                """;
            Database.AddParameter(command, "$username", requestedUsername);

            using var reader = command.ExecuteReader();
            if (!reader.Read())
            {
                return Results.Unauthorized();
            }

            userId = reader.GetInt64(0);
            username = reader.GetString(1);
            expectedPasswordHash = reader.GetString(2);
        }

        if (!Hashing.VerifyPassword(request.Password, expectedPasswordHash, out var needsUpgrade))
        {
            return Results.Unauthorized();
        }

        var upgradedPasswordHash = needsUpgrade
            ? Hashing.HashPassword(request.Password)
            : null;

        using var writeLease = await DatabaseWriteGate.EnterAsync(httpRequest.HttpContext.RequestAborted);
        using var connection = Database.OpenConnection(options.DbPath);

        if (needsUpgrade)
        {
            using var upgrade = connection.CreateCommand();
            upgrade.CommandText = """
                UPDATE users
                SET password_hash = $password_hash
                WHERE id = $id;
                """;
            Database.AddParameter(upgrade, "$password_hash", upgradedPasswordHash);
            Database.AddParameter(upgrade, "$id", userId);
            upgrade.ExecuteNonQuery();
        }

        var token = AuthService.CreateSession(connection, userId);

        return Results.Ok(new
        {
            userId,
            username,
            token
        });
    }

    private static IResult Me(HttpRequest httpRequest, ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);

        if (!AuthService.TryGetUser(connection, httpRequest, out var user))
        {
            return Results.Unauthorized();
        }

        return Results.Ok(user);
    }
}
