using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SignMeMaybe.Configuration;
using SignMeMaybe.Data;
using SignMeMaybe.Documents;
using SignMeMaybe.Models;
using SignMeMaybe.Security;

namespace SignMeMaybe.Endpoints;

public static class ContractEndpoints
{
    private const int MaxNotarySecretBytes = 4096;
    private const string NotaryDisplayName = "sealed-record.txt";

    public static void MapContractEndpoints(this WebApplication app, ServiceOptions options)
    {
        app.MapPost("/api/contracts", async (HttpRequest httpRequest, ContractCreateRequest request) =>
            await CreateContract(httpRequest, request, options));

        app.MapGet("/api/contracts", (HttpRequest httpRequest) =>
            ListContracts(httpRequest, options));

        app.MapGet("/api/users/{username}/contracts", (string username) =>
            ListPublicContractsByUsername(username, options));

        app.MapGet("/api/contracts/{reference}/notary/sealed", (HttpRequest httpRequest, string reference) =>
            GetOwnerSealedRecord(httpRequest, reference, options));

        app.MapGet("/api/contracts/{reference}/versions/latest", (HttpRequest httpRequest, string reference) =>
            GetLatestContractVersion(httpRequest, reference, options));

        app.MapGet("/api/contracts/{reference}/versions/latest/pdf", (HttpRequest httpRequest, string reference) =>
            GetLatestContractPdf(httpRequest, reference, options));

        app.MapGet("/api/links/leave", (string to) => RedirectExternalLink(to));
    }

    private static async Task<IResult> CreateContract(
        HttpRequest httpRequest,
        ContractCreateRequest request,
        ServiceOptions options)
    {
        AuthenticatedUser user;
        using (var authConnection = Database.OpenConnection(options.DbPath))
        {
            if (!AuthService.TryGetUser(authConnection, httpRequest, out user))
            {
                return Results.Unauthorized();
            }
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

        if (contentBytes.Length > options.MaxUploadBytes)
        {
            return Results.BadRequest(new { error = $"content exceeds max upload size of {options.MaxUploadBytes} bytes" });
        }

        var checksum = Hashing.Sha256Hex(contentBytes);

        byte[]? notarySecretBytes = null;
        if (!string.IsNullOrEmpty(request.NotarySecret))
        {
            notarySecretBytes = Encoding.UTF8.GetBytes(request.NotarySecret);
            if (notarySecretBytes.Length > MaxNotarySecretBytes)
            {
                return Results.BadRequest(new { error = $"sealed record exceeds max size of {MaxNotarySecretBytes} bytes" });
            }
        }

        var directives = AnnexDirectiveParser.Parse(request.Content);
        var attachments = await RemoteAnnexFetcher.FetchAsync(directives, httpRequest.HttpContext.RequestAborted);

        string? notaryFilePath = null;
        string? storedFilePath = null;
        var committed = false;

        try
        {
            using var connection = Database.OpenConnection(options.DbPath);
            using var transaction = connection.BeginTransaction();

            var reference = CreateMetadataDerivedContractReference(
                connection,
                transaction,
                user.Username,
                title,
                checksum);

            using var insertContract = connection.CreateCommand();
            insertContract.Transaction = transaction;
            insertContract.CommandText = """
                INSERT INTO contracts (public_reference, owner_user_id, title)
                VALUES ($public_reference, $owner_user_id, $title);
                SELECT last_insert_rowid();
                """;
            Database.AddParameter(insertContract, "$public_reference", reference);
            Database.AddParameter(insertContract, "$owner_user_id", user.Id);
            Database.AddParameter(insertContract, "$title", title);

            var contractId = Convert.ToInt64(insertContract.ExecuteScalar());
            string? publicStamp = null;

            if (notarySecretBytes is { Length: > 0 })
            {
                Directory.CreateDirectory(options.NotaryVaultRoot);
                publicStamp = CreateUniquePublicStamp(connection, transaction);
                notaryFilePath = CreateNotarySecretPath(options.NotaryVaultRoot);
                File.WriteAllBytes(notaryFilePath, notarySecretBytes);

                using var insertNotary = connection.CreateCommand();
                insertNotary.Transaction = transaction;
                insertNotary.CommandText = """
                    INSERT INTO notary_secrets
                        (owner_user_id, contract_id, public_stamp, secret_path, display_name, checksum)
                    VALUES
                        ($owner_user_id, $contract_id, $public_stamp, $secret_path, $display_name, $checksum);
                    """;
                Database.AddParameter(insertNotary, "$owner_user_id", user.Id);
                Database.AddParameter(insertNotary, "$contract_id", contractId);
                Database.AddParameter(insertNotary, "$public_stamp", publicStamp);
                Database.AddParameter(insertNotary, "$secret_path", notaryFilePath);
                Database.AddParameter(insertNotary, "$display_name", NotaryDisplayName);
                Database.AddParameter(insertNotary, "$checksum", Hashing.Sha256Hex(notarySecretBytes));
                insertNotary.ExecuteNonQuery();
            }

            var storedFileName = $"{reference}-{Guid.NewGuid():N}.pdf";
            storedFilePath = Path.Combine(options.PdfRoot, storedFileName);
            PdfDocumentGenerator.WriteContractPdf(storedFilePath, title, request.Content, attachments);

            using var insertVersion = connection.CreateCommand();
            insertVersion.Transaction = transaction;
            insertVersion.CommandText = """
                INSERT INTO contract_versions
                    (contract_id, version_number, approval_state, file_path, checksum, content_text)
                VALUES
                    ($contract_id, 1, 'draft', $file_path, $checksum, $content_text);
                SELECT last_insert_rowid();
                """;
            Database.AddParameter(insertVersion, "$contract_id", contractId);
            Database.AddParameter(insertVersion, "$file_path", storedFilePath);
            Database.AddParameter(insertVersion, "$checksum", checksum);
            Database.AddParameter(insertVersion, "$content_text", request.Content);

            insertVersion.ExecuteScalar();

            transaction.Commit();
            committed = true;

            return Results.Created($"/api/contracts/{Uri.EscapeDataString(reference)}/versions/latest", new
            {
                reference,
                ownerUsername = user.Username,
                title,
                versionNumber = 1,
                approvalState = "draft",
                checksum,
                notaryStamp = publicStamp
            });
        }
        finally
        {
            if (!committed)
            {
                TryDeleteFile(notaryFilePath);
                TryDeleteFile(storedFilePath);
            }
        }
    }

    private static IResult ListContracts(HttpRequest httpRequest, ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);

        if (!AuthService.TryGetUser(connection, httpRequest, out var user))
        {
            return Results.Unauthorized();
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                c.public_reference,
                c.title,
                c.created_at,
                v.version_number,
                v.approval_state,
                v.checksum,
                v.created_at,
                ns.public_stamp
            FROM contracts c
            JOIN contract_versions v ON v.contract_id = c.id
            LEFT JOIN notary_secrets ns ON ns.contract_id = c.id
            WHERE c.owner_user_id = $owner_user_id
              AND v.version_number = (
                  SELECT MAX(version_number)
                  FROM contract_versions
                  WHERE contract_id = c.id
              )
            ORDER BY c.id ASC;
            """;
        Database.AddParameter(command, "$owner_user_id", user.Id);

        var contracts = new List<object>();

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            contracts.Add(new
            {
                reference = reader.GetString(0),
                title = reader.GetString(1),
                createdAt = reader.GetString(2),
                latestVersion = new
                {
                    versionNumber = reader.GetInt32(3),
                    approvalState = reader.GetString(4),
                    checksum = reader.GetString(5),
                    createdAt = reader.GetString(6)
                },
                notaryStamp = reader.IsDBNull(7) ? null : reader.GetString(7)
            });
        }

        return Results.Ok(new
        {
            ownerUsername = user.Username,
            contracts
        });
    }

    private static IResult ListPublicContractsByUsername(string username, ServiceOptions options)
    {
        username = username.Trim();
        if (username.Length == 0)
        {
            return Results.BadRequest(new { error = "username must not be empty" });
        }

        using var connection = Database.OpenConnection(options.DbPath);

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                u.username,
                c.public_reference,
                c.title,
                c.created_at,
                v.version_number,
                v.approval_state,
                v.checksum,
                v.created_at,
                ns.public_stamp
            FROM users u
            JOIN contracts c ON c.owner_user_id = u.id
            JOIN contract_versions v ON v.contract_id = c.id
            LEFT JOIN notary_secrets ns ON ns.contract_id = c.id
            WHERE u.username = $username
              AND v.version_number = (
                  SELECT MAX(version_number)
                  FROM contract_versions
                  WHERE contract_id = c.id
              )
            ORDER BY c.created_at ASC, c.public_reference ASC;
            """;
        Database.AddParameter(command, "$username", username);

        var contracts = new List<object>();
        string? canonicalUsername = null;

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            canonicalUsername ??= reader.GetString(0);
            contracts.Add(new
            {
                title = reader.GetString(2),
                createdAt = reader.GetString(3),
                latestVersion = new
                {
                    versionNumber = reader.GetInt32(4),
                    approvalState = reader.GetString(5),
                    checksum = reader.GetString(6),
                    createdAt = reader.GetString(7)
                },
                notaryStamp = reader.IsDBNull(8) ? null : reader.GetString(8)
            });
        }

        if (canonicalUsername is null)
        {
            using var userExists = connection.CreateCommand();
            userExists.CommandText = """
                SELECT username
                FROM users
                WHERE username = $username
                LIMIT 1;
                """;
            Database.AddParameter(userExists, "$username", username);
            canonicalUsername = userExists.ExecuteScalar() as string;
        }

        if (canonicalUsername is null)
        {
            return Results.NotFound(new { error = "user not found" });
        }

        return Results.Ok(new
        {
            username = canonicalUsername,
            contracts
        });
    }

    private static IResult GetOwnerSealedRecord(
        HttpRequest httpRequest,
        string reference,
        ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);

        if (!AuthService.TryGetUser(connection, httpRequest, out var user))
        {
            return Results.Unauthorized();
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                c.owner_user_id,
                ns.secret_path,
                ns.display_name
            FROM contracts c
            LEFT JOIN notary_secrets ns ON ns.contract_id = c.id
            WHERE c.public_reference = $public_reference
            LIMIT 1;
            """;
        Database.AddParameter(command, "$public_reference", reference);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return Results.NotFound(new { error = "contract not found" });
        }

        if (reader.GetInt64(0) != user.Id)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        if (reader.IsDBNull(1))
        {
            return Results.NotFound(new { error = "sealed record not found" });
        }

        var secretPath = reader.GetString(1);
        var displayName = reader.GetString(2);
        if (!File.Exists(secretPath))
        {
            return Results.NotFound(new { error = "sealed record not found" });
        }

        return Results.File(secretPath, "text/plain", displayName);
    }

    private static IResult GetLatestContractVersion(
        HttpRequest httpRequest,
        string reference,
        ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);

        if (!AuthService.TryGetUser(connection, httpRequest, out var user))
        {
            return Results.Unauthorized();
        }

        using var command = connection.CreateCommand();

        command.CommandText = """
            SELECT
                c.public_reference,
                u.username,
                c.title,
                v.version_number,
                v.approval_state,
                v.file_path,
                v.checksum,
                v.content_text,
                v.created_at
            FROM contracts c
            JOIN users u ON u.id = c.owner_user_id
            JOIN contract_versions v ON v.contract_id = c.id
            WHERE c.public_reference = $public_reference
              AND v.version_number = (
                  SELECT MAX(version_number)
                  FROM contract_versions
                  WHERE contract_id = c.id
              )
            LIMIT 1;
            """;
        Database.AddParameter(command, "$public_reference", reference);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return Results.NotFound(new { error = "contract not found" });
        }

        var content = reader.GetString(7);

        return Results.Ok(new
        {
            reference = reader.GetString(0),
            ownerUsername = reader.GetString(1),
            title = reader.GetString(2),
            versionNumber = reader.GetInt32(3),
            approvalState = reader.GetString(4),
            checksum = reader.GetString(6),
            createdAt = reader.GetString(8),
            requestedByUsername = user.Username,
            content,
            pdfUrl = $"/api/contracts/{Uri.EscapeDataString(reference)}/versions/latest/pdf"
        });
    }

    private static IResult GetLatestContractPdf(
        HttpRequest httpRequest,
        string reference,
        ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);

        if (!AuthService.TryGetUser(connection, httpRequest, out _))
        {
            return Results.Unauthorized();
        }

        using var command = connection.CreateCommand();

        command.CommandText = """
            SELECT v.file_path
            FROM contracts c
            JOIN contract_versions v ON v.contract_id = c.id
            WHERE c.public_reference = $public_reference
              AND v.version_number = (
                  SELECT MAX(version_number)
                  FROM contract_versions
                  WHERE contract_id = c.id
              )
            LIMIT 1;
            """;
        Database.AddParameter(command, "$public_reference", reference);

        var storedFilePath = command.ExecuteScalar() as string;
        if (storedFilePath is null || !File.Exists(storedFilePath))
        {
            return Results.NotFound(new { error = "contract PDF not found" });
        }

        if (!Path.GetExtension(storedFilePath).Equals(".pdf", StringComparison.OrdinalIgnoreCase))
        {
            return Results.NotFound(new { error = "contract PDF not found" });
        }

        return Results.File(storedFilePath, "application/pdf", $"{reference}-latest.pdf");
    }

    private static string CreateMetadataDerivedContractReference(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string username,
        string title,
        string checksum)
    {
        var normalizedChecksum = checksum.ToLowerInvariant();
        var normalizedTitle = title.Trim();
        var derivationMaterial = Encoding.UTF8.GetBytes($"{username}:{normalizedTitle}:{normalizedChecksum}");
        var derivedChecksum = Hashing.Sha256Hex(derivationMaterial);
        var preferredReference = $"CNTR-{derivedChecksum[..24]}";
        if (IsContractReferenceAvailable(connection, transaction, preferredReference))
        {
            return preferredReference;
        }

        return Database.CreateUniqueContractReference(connection, transaction);
    }

    private static bool IsContractReferenceAvailable(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string reference)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT 1
            FROM contracts
            WHERE public_reference = $public_reference
            LIMIT 1;
            """;
        Database.AddParameter(command, "$public_reference", reference);

        return command.ExecuteScalar() is null;
    }

    private static IResult RedirectExternalLink(string to)
    {
        if (!Uri.TryCreate(to, UriKind.Absolute, out var uri))
        {
            return Results.BadRequest(new { error = "link target must be an absolute URI" });
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return Results.BadRequest(new { error = "link target must use http or https" });
        }

        return Results.Redirect(uri.ToString(), permanent: false);
    }

    private static string CreateUniquePublicStamp(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        for (var attempt = 0; attempt < 16; attempt++)
        {
            var publicStamp = CreatePublicStamp();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                SELECT 1
                FROM notary_secrets
                WHERE public_stamp = $public_stamp
                LIMIT 1;
                """;
            Database.AddParameter(command, "$public_stamp", publicStamp);

            if (command.ExecuteScalar() is null)
            {
                return publicStamp;
            }
        }

        throw new InvalidOperationException("Could not generate a unique notary stamp.");
    }

    private static string CreatePublicStamp()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(24))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string CreateNotarySecretPath(string notaryVaultRoot)
    {
        var fileName = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant() + ".sealed";
        return Path.Combine(notaryVaultRoot, fileName);
    }

    private static void TryDeleteFile(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return;
        }

        try
        {
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
