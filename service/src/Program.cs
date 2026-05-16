using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using System.Security.Cryptography;


var builder = WebApplication.CreateBuilder(args);
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

Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);
Directory.CreateDirectory(pdfRoot);
Directory.CreateDirectory(exportRoot);

InitializeDatabase(dbPath);

app.MapGet("/", () => "Hello World!\n");

app.MapGet("/service", () => "Hello World!\n");

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

app.Run();

static void InitializeDatabase(string dbPath)
{
    using var connection = new SqliteConnection($"Data Source={dbPath}");
    connection.Open();

    using (var pragma = connection.CreateCommand())
    {
        pragma.CommandText = """
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            """;
        pragma.ExecuteNonQuery();
    }

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