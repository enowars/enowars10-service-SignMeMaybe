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
        app.MapPost("/api/register", (RegisterRequest request) => Register(request, options));
        app.MapPost("/api/login", (LoginRequest request) => Login(request, options));
        app.MapGet("/api/me", (HttpRequest httpRequest) => Me(httpRequest, options));
    }

    private static IResult Register(RegisterRequest request, ServiceOptions options)
    {
        var validationError = AuthService.ValidateCredentials(request.Username, request.Password);
        if (validationError is not null)
        {
            return Results.BadRequest(new { error = validationError });
        }

        using var connection = Database.OpenConnection(options.DbPath);

        try
        {
            using var insertUser = connection.CreateCommand();
            insertUser.CommandText = """
                INSERT INTO users (username, password_hash)
                VALUES ($username, $password_hash);
                SELECT last_insert_rowid();
                """;
            Database.AddParameter(insertUser, "$username", request.Username.Trim());
            Database.AddParameter(insertUser, "$password_hash", Hashing.HashPassword(request.Password));

            var userId = Convert.ToInt64(insertUser.ExecuteScalar());
            var token = AuthService.CreateSession(connection, userId);

            return Results.Ok(new
            {
                userId,
                username = request.Username.Trim(),
                token
            });
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            return Results.Conflict(new { error = "username already exists" });
        }
    }

    private static IResult Login(LoginRequest request, ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, username, password_hash
            FROM users
            WHERE username = $username
            LIMIT 1;
            """;
        Database.AddParameter(command, "$username", request.Username.Trim());

        long userId;
        string username;
        string expectedPasswordHash;

        using (var reader = command.ExecuteReader())
        {
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

        if (needsUpgrade)
        {
            using var upgrade = connection.CreateCommand();
            upgrade.CommandText = """
                UPDATE users
                SET password_hash = $password_hash
                WHERE id = $id;
                """;
            Database.AddParameter(upgrade, "$password_hash", Hashing.HashPassword(request.Password));
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
