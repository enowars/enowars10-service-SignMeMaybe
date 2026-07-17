using Microsoft.Data.Sqlite;
using System.Security.Cryptography;

namespace SignMeMaybe.Data;

public static class Database
{
    public static SqliteConnection OpenConnection(string dbPath, int busyTimeoutMs = 5000)
    {
        var connection = new SqliteConnection($"Data Source={dbPath}");
        connection.Open();

        busyTimeoutMs = Math.Max(0, busyTimeoutMs);

        using var pragma = connection.CreateCommand();
        pragma.CommandText = $"""
            PRAGMA busy_timeout = {busyTimeoutMs};
            PRAGMA foreign_keys = ON;
            """;
        pragma.ExecuteNonQuery();

        return connection;
    }

    public static void Initialize(string dbPath)
    {
        using var connection = OpenConnection(dbPath);

        using var initializationPragma = connection.CreateCommand();
        initializationPragma.CommandText = """
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            """;
        initializationPragma.ExecuteNonQuery();

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
                public_reference TEXT NOT NULL UNIQUE,
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
                content_text TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (contract_id) REFERENCES contracts(id) ON DELETE CASCADE,
                UNIQUE(contract_id, version_number)
            );

            CREATE TABLE IF NOT EXISTS contract_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER NOT NULL,
                contract_id INTEGER NOT NULL,
                public_ticket TEXT NOT NULL UNIQUE,
                file_path TEXT NOT NULL,
                display_name TEXT NOT NULL,
                checksum TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (contract_id) REFERENCES contracts(id) ON DELETE CASCADE
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

            CREATE TABLE IF NOT EXISTS signing_authorities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT NOT NULL UNIQUE,
                owner_user_id INTEGER NOT NULL,
                display_name TEXT NOT NULL,
                curve_name TEXT NOT NULL,
                private_scalar TEXT NOT NULL,
                public_key_x TEXT NOT NULL,
                public_key_y TEXT NOT NULL,
                secret_blob TEXT,
                secret_checksum TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS signature_ceremonies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT NOT NULL UNIQUE,
                authority_id INTEGER NOT NULL,
                requester_user_id INTEGER NOT NULL,
                contract_version_id INTEGER NOT NULL,
                curve_name TEXT NOT NULL,
                base_point_x TEXT NOT NULL,
                base_point_y TEXT NOT NULL,
                signature_point_x TEXT,
                signature_point_y TEXT,
                signature_point_infinity INTEGER NOT NULL DEFAULT 0,
                receipt_tag TEXT NOT NULL,
                validation_state TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (authority_id) REFERENCES signing_authorities(id) ON DELETE CASCADE,
                FOREIGN KEY (requester_user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (contract_version_id) REFERENCES contract_versions(id) ON DELETE CASCADE
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

            CREATE INDEX IF NOT EXISTS idx_sessions_created_at
                ON sessions(created_at);

            CREATE INDEX IF NOT EXISTS idx_users_created_at
                ON users(created_at);

            CREATE INDEX IF NOT EXISTS idx_contracts_owner
                ON contracts(owner_user_id);

            CREATE INDEX IF NOT EXISTS idx_contracts_created_at
                ON contracts(created_at);

            CREATE INDEX IF NOT EXISTS idx_contract_versions_contract
                ON contract_versions(contract_id);

            CREATE INDEX IF NOT EXISTS idx_contract_versions_contract_version
                ON contract_versions(contract_id, version_number DESC);

            CREATE INDEX IF NOT EXISTS idx_contract_versions_created_at
                ON contract_versions(created_at);

            CREATE INDEX IF NOT EXISTS idx_contract_packets_owner
                ON contract_packets(owner_user_id);

            CREATE INDEX IF NOT EXISTS idx_contract_packets_contract
                ON contract_packets(contract_id);

            CREATE INDEX IF NOT EXISTS idx_contract_packets_public_ticket
                ON contract_packets(public_ticket);

            CREATE INDEX IF NOT EXISTS idx_contract_packets_created_at
                ON contract_packets(created_at);

            CREATE INDEX IF NOT EXISTS idx_annotations_contract_version
                ON annotations(contract_version_id);

            CREATE INDEX IF NOT EXISTS idx_comments_contract_version
                ON comments(contract_version_id);

            CREATE INDEX IF NOT EXISTS idx_signature_requests_contract_version
                ON signature_requests(contract_version_id);

            CREATE INDEX IF NOT EXISTS idx_signature_requests_signer
                ON signature_requests(signer_user_id);

            CREATE INDEX IF NOT EXISTS idx_signing_authorities_owner
                ON signing_authorities(owner_user_id);

            CREATE INDEX IF NOT EXISTS idx_signing_authorities_public_id
                ON signing_authorities(public_id);

            CREATE INDEX IF NOT EXISTS idx_signing_authorities_created_at
                ON signing_authorities(created_at);

            CREATE INDEX IF NOT EXISTS idx_signature_ceremonies_authority
                ON signature_ceremonies(authority_id);

            CREATE INDEX IF NOT EXISTS idx_signature_ceremonies_requester
                ON signature_ceremonies(requester_user_id);

            CREATE INDEX IF NOT EXISTS idx_signature_ceremonies_public_id
                ON signature_ceremonies(public_id);

            CREATE INDEX IF NOT EXISTS idx_signature_ceremonies_created_at
                ON signature_ceremonies(created_at);

            CREATE INDEX IF NOT EXISTS idx_exports_contract_version
                ON exports(contract_version_id);

            CREATE INDEX IF NOT EXISTS idx_exports_created_at
                ON exports(created_at);
            """;
        command.ExecuteNonQuery();

        EnsureSignatureCeremoniesSchema(connection);

        EnsureColumn(
            connection,
            "contract_versions",
            "content_text",
            "ALTER TABLE contract_versions ADD COLUMN content_text TEXT NOT NULL DEFAULT '';");

        EnsureColumn(
            connection,
            "contracts",
            "public_reference",
            "ALTER TABLE contracts ADD COLUMN public_reference TEXT;");

        BackfillContractReferences(connection);

        using var index = connection.CreateCommand();
        index.CommandText = """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_contracts_public_reference
                ON contracts(public_reference);
            """;
        index.ExecuteNonQuery();
    }

    public static void AddParameter(SqliteCommand command, string name, object? value)
    {
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);
    }

    public static bool IsBusyOrLocked(SqliteException exception)
    {
        return exception.SqliteErrorCode is 5 or 6;
    }

    public static string CreateUniqueContractReference(
        SqliteConnection connection,
        SqliteTransaction? transaction = null)
    {
        for (var attempt = 0; attempt < 16; attempt++)
        {
            var reference = CreateContractReference();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                SELECT 1
                FROM contracts
                WHERE public_reference = $public_reference
                LIMIT 1;
                """;
            AddParameter(command, "$public_reference", reference);

            if (command.ExecuteScalar() is null)
            {
                return reference;
            }
        }

        throw new InvalidOperationException("Could not generate a unique contract reference.");
    }

    private static void EnsureColumn(
        SqliteConnection connection,
        string tableName,
        string columnName,
        string alterSql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info({tableName});";

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (string.Equals(reader.GetString(1), columnName, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
        }

        using var alter = connection.CreateCommand();
        alter.CommandText = alterSql;
        alter.ExecuteNonQuery();
    }

    private static void BackfillContractReferences(SqliteConnection connection)
    {
        var contractIds = new List<long>();

        using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT id
                FROM contracts
                WHERE public_reference IS NULL
                   OR public_reference = '';
                """;

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                contractIds.Add(reader.GetInt64(0));
            }
        }

        foreach (var contractId in contractIds)
        {
            using var update = connection.CreateCommand();
            update.CommandText = """
                UPDATE contracts
                SET public_reference = $public_reference
                WHERE id = $id;
                """;
            AddParameter(update, "$public_reference", CreateUniqueContractReference(connection));
            AddParameter(update, "$id", contractId);
            update.ExecuteNonQuery();
        }
    }

    private static void EnsureSignatureCeremoniesSchema(SqliteConnection connection)
    {
        var columnNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "PRAGMA table_info(signature_ceremonies);";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                columnNames.Add(reader.GetString(1));
            }
        }

        if (columnNames.Contains("contract_version_id")
            && !columnNames.Contains("message")
            && !columnNames.Contains("contract_reference"))
        {
            EnsureSignatureCeremonyIndexes(connection);
            return;
        }

        using (var drop = connection.CreateCommand())
        {
            drop.CommandText = "DROP TABLE IF EXISTS signature_ceremonies;";
            drop.ExecuteNonQuery();
        }

        using var create = connection.CreateCommand();
        create.CommandText = """
            CREATE TABLE signature_ceremonies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT NOT NULL UNIQUE,
                authority_id INTEGER NOT NULL,
                requester_user_id INTEGER NOT NULL,
                contract_version_id INTEGER NOT NULL,
                curve_name TEXT NOT NULL,
                base_point_x TEXT NOT NULL,
                base_point_y TEXT NOT NULL,
                signature_point_x TEXT,
                signature_point_y TEXT,
                signature_point_infinity INTEGER NOT NULL DEFAULT 0,
                receipt_tag TEXT NOT NULL,
                validation_state TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (authority_id) REFERENCES signing_authorities(id) ON DELETE CASCADE,
                FOREIGN KEY (requester_user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (contract_version_id) REFERENCES contract_versions(id) ON DELETE CASCADE
            );

            """;
        create.ExecuteNonQuery();

        EnsureSignatureCeremonyIndexes(connection);
    }

    private static void EnsureSignatureCeremonyIndexes(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE INDEX IF NOT EXISTS idx_signature_ceremonies_authority
                ON signature_ceremonies(authority_id);

            CREATE INDEX IF NOT EXISTS idx_signature_ceremonies_requester
                ON signature_ceremonies(requester_user_id);

            CREATE INDEX IF NOT EXISTS idx_signature_ceremonies_contract_version
                ON signature_ceremonies(contract_version_id);

            CREATE INDEX IF NOT EXISTS idx_signature_ceremonies_public_id
                ON signature_ceremonies(public_id);

            CREATE INDEX IF NOT EXISTS idx_signature_ceremonies_created_at
                ON signature_ceremonies(created_at);
            """;
        command.ExecuteNonQuery();
    }

    private static string CreateContractReference()
    {
        return "CNTR-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
    }
}
