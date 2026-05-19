using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.SerializerOptions.WriteIndented = true;
});

var app = builder.Build();

var dbPath = Environment.GetEnvironmentVariable("SIGNMEMAYBE_DB_PATH")
    ?? "/data/signmemaybe.sqlite3";

var pdfRoot = Environment.GetEnvironmentVariable("SIGNMEMAYBE_PDF_ROOT")
    ?? "/data/pdfs";

var exportRoot = Environment.GetEnvironmentVariable("SIGNMEMAYBE_EXPORT_ROOT")
    ?? "/data/exports";

var maxUploadBytesRaw = Environment.GetEnvironmentVariable("SIGNMEMAYBE_MAX_UPLOAD_BYTES")
    ?? "10485760";

var maxUploadBytes = long.TryParse(maxUploadBytesRaw, out var parsedMaxUploadBytes)
    ? parsedMaxUploadBytes
    : 10_485_760;

Directory.CreateDirectory(Path.GetDirectoryName(dbPath) ?? "/data");
Directory.CreateDirectory(pdfRoot);
Directory.CreateDirectory(exportRoot);

InitializeDatabase(dbPath);

app.MapGet("/", () => Results.Json(new
{
    service = "SignMeMaybe",
    message = "Tiny contract signing service for A/D CTF testing.",
    endpoints = new[]
    {
        "GET /health",
        "POST /api/register",
        "POST /api/login",
        "GET /api/me",
        "POST /api/contracts",
        "GET /api/contracts",
        "GET /api/contracts/{contractId}/versions/latest"
    }
}));

app.MapGet("/health", () => Results.Json(new
{
    status = "ok",
    service = "SignMeMaybe"
}));

app.MapGet("/debug/persistence", () =>
{
    return Results.Json(new
    {
        dbPath,
        dbExists = File.Exists(dbPath),
        pdfRoot,
        pdfRootExists = Directory.Exists(pdfRoot),
        exportRoot,
        exportRootExists = Directory.Exists(exportRoot),
        maxUploadBytes
    });
});

app.MapPost("/api/register", (RegisterRequest request) =>
{
    var validationError = ValidateCredentials(request.Username, request.Password);
    if (validationError is not null)
    {
        return Results.BadRequest(new { error = validationError });
    }

    using var connection = OpenConnection(dbPath);

    try
    {
        using var insertUser = connection.CreateCommand();
        insertUser.CommandText = """
            INSERT INTO users (username, password_hash)
            VALUES ($username, $password_hash);
            SELECT last_insert_rowid();
            """;
        AddParameter(insertUser, "$username", request.Username.Trim());
        AddParameter(insertUser, "$password_hash", HashPassword(request.Password));

        var userId = Convert.ToInt64(insertUser.ExecuteScalar());
        var token = CreateSession(connection, userId);

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
});

app.MapPost("/api/login", (LoginRequest request) =>
{
    using var connection = OpenConnection(dbPath);

    using var command = connection.CreateCommand();
    command.CommandText = """
        SELECT id, username, password_hash
        FROM users
        WHERE username = $username
        LIMIT 1;
        """;
    AddParameter(command, "$username", request.Username.Trim());

    using var reader = command.ExecuteReader();
    if (!reader.Read())
    {
        return Results.Unauthorized();
    }

    var userId = reader.GetInt64(0);
    var username = reader.GetString(1);
    var expectedPasswordHash = reader.GetString(2);

    if (!FixedTimeEquals(expectedPasswordHash, HashPassword(request.Password)))
    {
        return Results.Unauthorized();
    }

    var token = CreateSession(connection, userId);

    return Results.Ok(new
    {
        userId,
        username,
        token
    });
});

app.MapGet("/api/me", (HttpRequest httpRequest) =>
{
    using var connection = OpenConnection(dbPath);

    if (!TryGetUser(connection, httpRequest, out var user))
    {
        return Results.Unauthorized();
    }

    return Results.Ok(user);
});

app.MapPost("/api/contracts", (HttpRequest httpRequest, ContractCreateRequest request) =>
{
    using var connection = OpenConnection(dbPath);

    if (!TryGetUser(connection, httpRequest, out var user))
    {
        return Results.Unauthorized();
    }

    var title = request.Title.Trim();
    if (title.Length is < 1 or > 120)
    {
        return Results.BadRequest(new { error = "title must be between 1 and 120 characters" });
    }

    var contentBytes = Encoding.UTF8.GetBytes(request.Content);
    if (contentBytes.Length == 0)
    {
        return Results.BadRequest(new { error = "content must not be empty" });
    }

    if (contentBytes.Length > maxUploadBytes)
    {
        return Results.BadRequest(new { error = $"content exceeds max upload size of {maxUploadBytes} bytes" });
    }

    using var transaction = connection.BeginTransaction();

    using var insertContract = connection.CreateCommand();
    insertContract.Transaction = transaction;
    insertContract.CommandText = """
        INSERT INTO contracts (owner_user_id, title)
        VALUES ($owner_user_id, $title);
        SELECT last_insert_rowid();
        """;
    AddParameter(insertContract, "$owner_user_id", user.Id);
    AddParameter(insertContract, "$title", title);

    var contractId = Convert.ToInt64(insertContract.ExecuteScalar());

    var storedFileName = $"{contractId}-{Guid.NewGuid():N}.txt";
    var storedFilePath = Path.Combine(pdfRoot, storedFileName);
    File.WriteAllText(storedFilePath, request.Content, Encoding.UTF8);

    var checksum = Sha256Hex(contentBytes);

    using var insertVersion = connection.CreateCommand();
    insertVersion.Transaction = transaction;
    insertVersion.CommandText = """
        INSERT INTO contract_versions
            (contract_id, version_number, approval_state, file_path, checksum)
        VALUES
            ($contract_id, 1, 'draft', $file_path, $checksum);
        SELECT last_insert_rowid();
        """;
    AddParameter(insertVersion, "$contract_id", contractId);
    AddParameter(insertVersion, "$file_path", storedFilePath);
    AddParameter(insertVersion, "$checksum", checksum);

    var versionId = Convert.ToInt64(insertVersion.ExecuteScalar());

    transaction.Commit();

    return Results.Created($"/api/contracts/{contractId}/versions/latest", new
    {
        contractId,
        versionId,
        ownerUserId = user.Id,
        title,
        versionNumber = 1,
        approvalState = "draft",
        checksum
    });
});

app.MapGet("/api/contracts", (HttpRequest httpRequest) =>
{
    using var connection = OpenConnection(dbPath);

    if (!TryGetUser(connection, httpRequest, out var user))
    {
        return Results.Unauthorized();
    }

    using var command = connection.CreateCommand();
    command.CommandText = """
        SELECT
            c.id,
            c.title,
            c.created_at,
            v.id,
            v.version_number,
            v.approval_state,
            v.checksum,
            v.created_at
        FROM contracts c
        JOIN contract_versions v ON v.contract_id = c.id
        WHERE c.owner_user_id = $owner_user_id
          AND v.version_number = (
              SELECT MAX(version_number)
              FROM contract_versions
              WHERE contract_id = c.id
          )
        ORDER BY c.id ASC;
        """;
    AddParameter(command, "$owner_user_id", user.Id);

    var contracts = new List<object>();

    using var reader = command.ExecuteReader();
    while (reader.Read())
    {
        contracts.Add(new
        {
            contractId = reader.GetInt64(0),
            title = reader.GetString(1),
            createdAt = reader.GetString(2),
            latestVersion = new
            {
                versionId = reader.GetInt64(3),
                versionNumber = reader.GetInt32(4),
                approvalState = reader.GetString(5),
                checksum = reader.GetString(6),
                createdAt = reader.GetString(7)
            }
        });
    }

    return Results.Ok(new
    {
        ownerUserId = user.Id,
        contracts
    });
});

app.MapGet("/api/contracts/{contractId:long}/versions/latest", (HttpRequest httpRequest, long contractId) =>
{
    using var connection = OpenConnection(dbPath);

    if (!TryGetUser(connection, httpRequest, out var user))
    {
        return Results.Unauthorized();
    }

    using var command = connection.CreateCommand();

    /*
     * INTENTIONAL CTF VULNERABILITY: IDOR / missing authorization.
     *
     * This endpoint only checks that the caller has a valid session.
     * It does NOT check:
     *
     *     c.owner_user_id = authenticated_user_id
     *
     * Therefore, any logged-in user can enumerate sequential contract IDs
     * and read other users' latest contract versions.
     */
    command.CommandText = """
        SELECT
            c.id,
            c.owner_user_id,
            c.title,
            v.id,
            v.version_number,
            v.approval_state,
            v.file_path,
            v.checksum,
            v.created_at
        FROM contracts c
        JOIN contract_versions v ON v.contract_id = c.id
        WHERE c.id = $contract_id
          AND v.version_number = (
              SELECT MAX(version_number)
              FROM contract_versions
              WHERE contract_id = c.id
          )
        LIMIT 1;
        """;
    AddParameter(command, "$contract_id", contractId);

    using var reader = command.ExecuteReader();
    if (!reader.Read())
    {
        return Results.NotFound(new { error = "contract not found" });
    }

    var storedFilePath = reader.GetString(6);
    var content = File.Exists(storedFilePath)
        ? File.ReadAllText(storedFilePath, Encoding.UTF8)
        : "";

    return Results.Ok(new
    {
        contractId = reader.GetInt64(0),
        ownerUserId = reader.GetInt64(1),
        title = reader.GetString(2),
        versionId = reader.GetInt64(3),
        versionNumber = reader.GetInt32(4),
        approvalState = reader.GetString(5),
        checksum = reader.GetString(7),
        createdAt = reader.GetString(8),
        requestedByUserId = user.Id,
        content
    });
});

app.Run();

public partial class Program
{
    private static SqliteConnection OpenConnection(string dbPath)
    {
        var connection = new SqliteConnection($"Data Source={dbPath}");
        connection.Open();

        using var pragma = connection.CreateCommand();
        pragma.CommandText = """
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            """;
        pragma.ExecuteNonQuery();

        return connection;
    }

    private static void InitializeDatabase(string dbPath)
    {
        using var connection = OpenConnection(dbPath);

        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS contracts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS contract_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_id INTEGER NOT NULL,
                version_number INTEGER NOT NULL,
                approval_state TEXT NOT NULL DEFAULT 'draft',
                file_path TEXT NOT NULL,
                checksum TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (contract_id) REFERENCES contracts(id) ON DELETE CASCADE,
                UNIQUE(contract_id, version_number)
            );

            CREATE TABLE IF NOT EXISTS annotations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_version_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                page_number INTEGER NOT NULL,
                x REAL NOT NULL,
                y REAL NOT NULL,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (contract_version_id) REFERENCES contract_versions(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_version_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (contract_version_id) REFERENCES contract_versions(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS signature_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_version_id INTEGER NOT NULL,
                requester_user_id INTEGER NOT NULL,
                signer_user_id INTEGER NOT NULL,
                state TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (contract_version_id) REFERENCES contract_versions(id) ON DELETE CASCADE,
                FOREIGN KEY (requester_user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (signer_user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature_request_id INTEGER NOT NULL UNIQUE,
                signer_user_id INTEGER NOT NULL,
                signature_text TEXT NOT NULL,
                signed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (signature_request_id) REFERENCES signature_requests(id) ON DELETE CASCADE,
                FOREIGN KEY (signer_user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS exports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_version_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                checksum TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (contract_version_id) REFERENCES contract_versions(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_user
                ON sessions(user_id);

            CREATE INDEX IF NOT EXISTS idx_contracts_owner
                ON contracts(owner_user_id);

            CREATE INDEX IF NOT EXISTS idx_contract_versions_contract
                ON contract_versions(contract_id);

            CREATE INDEX IF NOT EXISTS idx_annotations_contract_version
                ON annotations(contract_version_id);

            CREATE INDEX IF NOT EXISTS idx_comments_contract_version
                ON comments(contract_version_id);

            CREATE INDEX IF NOT EXISTS idx_signature_requests_contract_version
                ON signature_requests(contract_version_id);

            CREATE INDEX IF NOT EXISTS idx_signature_requests_signer
                ON signature_requests(signer_user_id);

            CREATE INDEX IF NOT EXISTS idx_exports_contract_version
                ON exports(contract_version_id);
            """;
        command.ExecuteNonQuery();
    }

    private static string? ValidateCredentials(string username, string password)
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

    private static string CreateSession(SqliteConnection connection, long userId)
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO sessions (token, user_id)
            VALUES ($token, $user_id);
            """;
        AddParameter(command, "$token", token);
        AddParameter(command, "$user_id", userId);
        command.ExecuteNonQuery();

        return token;
    }

    private static bool TryGetUser(SqliteConnection connection, HttpRequest request, out AuthenticatedUser user)
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
        AddParameter(command, "$token", token);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return false;
        }

        user = new AuthenticatedUser(reader.GetInt64(0), reader.GetString(1));
        return true;
    }

    private static void AddParameter(SqliteCommand command, string name, object? value)
    {
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);
    }

    private static string HashPassword(string password)
    {
        return Sha256Hex(Encoding.UTF8.GetBytes("SignMeMaybe::" + password));
    }

    private static string Sha256Hex(byte[] bytes)
    {
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static bool FixedTimeEquals(string leftHex, string rightHex)
    {
        var leftBytes = Encoding.UTF8.GetBytes(leftHex);
        var rightBytes = Encoding.UTF8.GetBytes(rightHex);

        return leftBytes.Length == rightBytes.Length
            && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }
}

public sealed record RegisterRequest(string Username, string Password);

public sealed record LoginRequest(string Username, string Password);

public sealed record ContractCreateRequest(string Title, string Content);

public sealed record AuthenticatedUser(long Id, string Username);