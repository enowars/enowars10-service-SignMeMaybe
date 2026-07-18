using System.Globalization;
using Microsoft.Data.Sqlite;
using SignMeMaybe.Configuration;
using SignMeMaybe.Data;

namespace SignMeMaybe.Maintenance;

public static class CleanupRunner
{
    private const int CleanupBusyTimeoutMs = 100;
    private const int DeleteBatchSize = 250;

    public static CleanupResult Run(ServiceOptions options)
    {
        var cutoffUtc = DateTimeOffset.UtcNow.AddSeconds(-options.CleanupRetentionSeconds).UtcDateTime;
        var cutoffText = cutoffUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        using var connection = Database.OpenConnection(options.DbPath, CleanupBusyTimeoutMs);

        if (!HasRuntimeSchema(connection))
        {
            return CleanupResult.Skipped;
        }

        using var transaction = connection.BeginTransaction();

        var staleFilePaths = LoadFilePathsForDeleteBatch(
            connection,
            transaction,
            "exports",
            "file_path",
            cutoffText);
        var deletedExports = ExecuteDeleteBatch(
            connection,
            transaction,
            "exports",
            cutoffText);

        var deletedSessions = ExecuteDeleteBatch(
            connection,
            transaction,
            "sessions",
            cutoffText);

        ExecuteDeleteBatch(
            connection,
            transaction,
            "signature_ceremonies",
            cutoffText);

        ExecuteDeleteBatch(
            connection,
            transaction,
            "signing_authorities",
            cutoffText);

        staleFilePaths.AddRange(LoadContractFilePathsForDeleteBatch(connection, transaction, cutoffText));
        var deletedContracts = ExecuteDeleteBatch(
            connection,
            transaction,
            "contracts",
            cutoffText);

        var deletedUsers = ExecuteDeleteUsersBatch(connection, transaction, cutoffText);

        transaction.Commit();

        var deletedFiles = 0;
        foreach (var filePath in staleFilePaths)
        {
            if (IsInManagedRoot(filePath, options) && TryDeleteFile(filePath))
            {
                deletedFiles++;
            }
        }

        if (ShouldSweepOrphanFiles())
        {
            deletedFiles += DeleteOldFiles(options.PdfRoot, cutoffUtc, options);
            deletedFiles += DeleteOldFiles(options.ExportRoot, cutoffUtc, options);
            deletedFiles += DeleteOldFiles(options.PacketRoot, cutoffUtc, options);
        }

        return new CleanupResult(
            deletedFiles,
            deletedSessions,
            deletedContracts,
            deletedExports,
            deletedUsers);
    }

    private static List<string> LoadFilePathsForDeleteBatch(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string tableName,
        string columnName,
        string cutoffText)
    {
        var filePaths = new List<string>();

        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"""
            SELECT {columnName}
            FROM {tableName}
            WHERE rowid IN (
                SELECT rowid
                FROM {tableName}
                WHERE created_at < $cutoff
                ORDER BY rowid ASC
                LIMIT $limit
            );
            """;
        Database.AddParameter(command, "$cutoff", cutoffText);
        Database.AddParameter(command, "$limit", DeleteBatchSize);

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            filePaths.Add(reader.GetString(0));
        }

        return filePaths;
    }

    private static List<string> LoadContractFilePathsForDeleteBatch(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string cutoffText)
    {
        var filePaths = new List<string>();

        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT file_path
            FROM contract_versions
            WHERE contract_id IN (
                SELECT id
                FROM contracts
                WHERE created_at < $cutoff
                ORDER BY id ASC
                LIMIT $limit
            )
            UNION
            SELECT file_path
            FROM contract_packets
            WHERE contract_id IN (
                SELECT id
                FROM contracts
                WHERE created_at < $cutoff
                ORDER BY id ASC
                LIMIT $limit
            );
            """;
        Database.AddParameter(command, "$cutoff", cutoffText);
        Database.AddParameter(command, "$limit", DeleteBatchSize);

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            filePaths.Add(reader.GetString(0));
        }

        return filePaths;
    }

    private static int ExecuteDeleteBatch(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string tableName,
        string cutoffText)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"""
            DELETE FROM {tableName}
            WHERE rowid IN (
                SELECT rowid
                FROM {tableName}
                WHERE created_at < $cutoff
                ORDER BY rowid ASC
                LIMIT $limit
            );
            """;
        Database.AddParameter(command, "$cutoff", cutoffText);
        Database.AddParameter(command, "$limit", DeleteBatchSize);
        return command.ExecuteNonQuery();
    }

    private static int ExecuteDeleteUsersBatch(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string cutoffText)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            DELETE FROM users
            WHERE rowid IN (
                SELECT rowid
                FROM users
                WHERE created_at < $cutoff
                  AND NOT EXISTS (
                      SELECT 1
                      FROM sessions
                      WHERE sessions.user_id = users.id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM contracts
                      WHERE contracts.owner_user_id = users.id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM signing_authorities
                      WHERE signing_authorities.owner_user_id = users.id
                  )
                ORDER BY rowid ASC
                LIMIT $limit
            );
            """;
        Database.AddParameter(command, "$cutoff", cutoffText);
        Database.AddParameter(command, "$limit", DeleteBatchSize);
        return command.ExecuteNonQuery();
    }

    private static bool ShouldSweepOrphanFiles()
    {
        var value = Environment.GetEnvironmentVariable("SIGNMEMAYBE_CLEANUP_SWEEP_FILES");
        return string.Equals(value, "1", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasRuntimeSchema(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table'
              AND name IN (
                  'users',
                  'sessions',
                  'contracts',
                  'contract_versions',
                  'contract_packets',
                  'signing_authorities',
                  'signature_ceremonies'
              )
            GROUP BY type
            HAVING COUNT(*) = 7;
            """;

        return command.ExecuteScalar() is not null;
    }

    private static int DeleteOldFiles(string root, DateTime cutoffUtc, ServiceOptions options)
    {
        if (!Directory.Exists(root))
        {
            return 0;
        }

        var deletedFiles = 0;
        foreach (var filePath in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            if (Path.GetFileName(filePath).Equals(".gitkeep", StringComparison.Ordinal))
            {
                continue;
            }

            if (IsDatabaseFile(filePath, options))
            {
                continue;
            }

            if (File.GetLastWriteTimeUtc(filePath) < cutoffUtc && TryDeleteFile(filePath))
            {
                deletedFiles++;
            }
        }

        return deletedFiles;
    }

    private static bool TryDeleteFile(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
            {
                return false;
            }

            File.Delete(filePath);
            return true;
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine($"Could not delete runtime file '{filePath}': {ex.Message}");
            return false;
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine($"Could not delete runtime file '{filePath}': {ex.Message}");
            return false;
        }
    }

    private static bool IsInManagedRoot(string filePath, ServiceOptions options)
    {
        return IsUnderRoot(filePath, options.PdfRoot)
            || IsUnderRoot(filePath, options.ExportRoot)
            || IsUnderRoot(filePath, options.PacketRoot);
    }

    private static bool IsDatabaseFile(string filePath, ServiceOptions options)
    {
        var fullPath = Path.GetFullPath(filePath);
        var fullDbPath = Path.GetFullPath(options.DbPath);
        return string.Equals(fullPath, fullDbPath, StringComparison.Ordinal)
            || string.Equals(fullPath, fullDbPath + "-journal", StringComparison.Ordinal)
            || string.Equals(fullPath, fullDbPath + "-shm", StringComparison.Ordinal)
            || string.Equals(fullPath, fullDbPath + "-wal", StringComparison.Ordinal);
    }

    private static bool IsUnderRoot(string filePath, string root)
    {
        var fullPath = Path.GetFullPath(filePath);
        var fullRoot = Path.GetFullPath(root);
        if (!fullRoot.EndsWith(Path.DirectorySeparatorChar))
        {
            fullRoot += Path.DirectorySeparatorChar;
        }

        return fullPath.StartsWith(fullRoot, StringComparison.Ordinal);
    }
}

public sealed record CleanupResult(
    int DeletedFiles,
    int DeletedSessions,
    int DeletedContracts,
    int DeletedExports,
    int DeletedUsers)
{
    public static CleanupResult Skipped { get; } = new(0, 0, 0, 0, 0);
}
