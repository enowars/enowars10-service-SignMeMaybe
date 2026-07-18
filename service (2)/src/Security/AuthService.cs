using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SignMeMaybe.Data;
using SignMeMaybe.Models;

namespace SignMeMaybe.Security;

public static class AuthService
{
    public static string? ValidateCredentials(string username, string password)
    {
        username = username.Trim();

        if (username.Length is < 3 or > 40)
        {
            return "username must be between 3 and 40 characters";
        }

        if (!username.All(c => char.IsLetterOrDigit(c) || c is '_' or '-'))
        {
            return "username may only contain letters, digits, underscores, and dashes";
        }

        if (password.Length is < 6 or > 200)
        {
            return "password must be between 6 and 200 characters";
        }

        return null;
    }

    public static string CreateSession(SqliteConnection connection, long userId)
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO sessions (token, user_id)
            VALUES ($token, $user_id);
            """;
        Database.AddParameter(command, "$token", token);
        Database.AddParameter(command, "$user_id", userId);
        command.ExecuteNonQuery();

        return token;
    }

    public static bool TryGetUser(SqliteConnection connection, HttpRequest request, out AuthenticatedUser user)
    {
        user = new AuthenticatedUser(0, "");

        if (!request.Headers.TryGetValue("X-Session-Token", out var tokenValues))
        {
            return false;
        }

        var token = tokenValues.ToString();
        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT users.id, users.username
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = $token
            LIMIT 1;
            """;
        Database.AddParameter(command, "$token", token);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return false;
        }

        user = new AuthenticatedUser(reader.GetInt64(0), reader.GetString(1));
        return true;
    }
}
