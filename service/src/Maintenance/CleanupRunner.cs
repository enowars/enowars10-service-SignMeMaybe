using System.Globalization;
using Microsoft.Data.Sqlite;
using SignMeMaybe.Configuration;
using SignMeMaybe.Data;

namespace SignMeMaybe.Maintenance;

public static class CleanupRunner
{
    public static CleanupResult Run(ServiceOptions options)
    {
        var cutoffUtc = DateTimeOffset.UtcNow.AddSeconds(-options.CleanupRetentionSeconds).UtcDateTime;
        var cutoffText = cutoffUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        using var connection = Database.OpenConnection(options.DbPath);

        if (!HasRuntimeSchema(connection))
        {
            return CleanupResult.Skipped;
        }

        using var transaction = connection.BeginTransaction();

        var staleFilePaths = LoadStaleFilePaths(connection, transaction, cutoffText);
        var deletedExports = ExecuteDelete(
            connection,
            transaction,
            "DELETE FROM exports WHERE created_at < $cutoff;",
            cutoffText);
        var deletedSessions = ExecuteDelete(
            connection,
            transaction,
            "DELETE FROM sessions WHERE created_at < $cutoff;",
            cutoffText);
        ExecuteDelete(
            connection,
            transaction,
            "DELETE FROM signature_ceremonies WHERE created_at < $cutoff;",
            cutoffText);
        ExecuteDelete(
            connection,
            transaction,
            "DELETE FROM signing_authorities WHERE created_at < $cutoff;",
            cutoffText);
        var deletedContracts = ExecuteDelete(
            connection,
            transaction,
            "DELETE FROM contracts WHERE created_at < $cutoff;",
            cutoffText);
        var deletedUsers = ExecuteDelete(
            connection,
            transaction,
            """
            DELETE FROM users
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
              );
            """,
            cutoffText);

        transaction.Commit();

        var deletedFiles = 0;
        foreach (var filePath in staleFilePaths)
        {
            if (IsInManagedRoot(filePath, options) && TryDeleteFile(filePath))
            {
                deletedFiles++;
            }
        }

        deletedFiles += DeleteOldFiles(options.PdfRoot, cutoffUtc, options);
        deletedFiles += DeleteOldFiles(options.ExportRoot, cutoffUtc, options);
        deletedFiles += DeleteOldFiles(options.NotaryVaultRoot, cutoffUtc, options);

        return new CleanupResult(
            deletedFiles,
            deletedSessions,
            deletedContracts,
            deletedExports,
            deletedUsers);
    }

    private static List<string> LoadStaleFilePaths(
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
            WHERE created_at < $cutoff
            UNION
            SELECT file_path
            FROM exports
            WHERE created_at < $cutoff
            UNION
            SELECT secret_path
            FROM notary_secrets
            WHERE created_at < $cutoff;
            """;
        Database.AddParameter(command, "$cutoff", cutoffText);

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            filePaths.Add(reader.GetString(0));
        }

        return filePaths;
    }

    private static int ExecuteDelete(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string commandText,
        string cutoffText)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = commandText;
        Database.AddParameter(command, "$cutoff", cutoffText);
        return command.ExecuteNonQuery();
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
                  'notary_secrets',
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
            || IsUnderRoot(filePath, options.NotaryVaultRoot);
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
