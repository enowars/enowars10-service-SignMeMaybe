using System.Text;
using SignMeMaybe.Configuration;
using SignMeMaybe.Data;
using SignMeMaybe.Documents;
using SignMeMaybe.Models;
using SignMeMaybe.Security;

namespace SignMeMaybe.Endpoints;

public static class ContractEndpoints
{
    public static void MapContractEndpoints(this WebApplication app, ServiceOptions options)
    {
        app.MapPost("/api/contracts", (HttpRequest httpRequest, ContractCreateRequest request) =>
            CreateContract(httpRequest, request, options));

        app.MapGet("/api/contracts", (HttpRequest httpRequest) =>
            ListContracts(httpRequest, options));

        app.MapGet("/api/contracts/{contractId:long}/versions/latest", (HttpRequest httpRequest, long contractId) =>
            GetLatestContractVersion(httpRequest, contractId, options));

        app.MapGet("/api/contracts/{contractId:long}/versions/latest/pdf", (HttpRequest httpRequest, long contractId) =>
            GetLatestContractPdf(httpRequest, contractId, options));
    }

    private static IResult CreateContract(
        HttpRequest httpRequest,
        ContractCreateRequest request,
        ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);

        if (!AuthService.TryGetUser(connection, httpRequest, out var user))
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

        if (contentBytes.Length > options.MaxUploadBytes)
        {
            return Results.BadRequest(new { error = $"content exceeds max upload size of {options.MaxUploadBytes} bytes" });
        }

        using var transaction = connection.BeginTransaction();

        using var insertContract = connection.CreateCommand();
        insertContract.Transaction = transaction;
        insertContract.CommandText = """
            INSERT INTO contracts (owner_user_id, title)
            VALUES ($owner_user_id, $title);
            SELECT last_insert_rowid();
            """;
        Database.AddParameter(insertContract, "$owner_user_id", user.Id);
        Database.AddParameter(insertContract, "$title", title);

        var contractId = Convert.ToInt64(insertContract.ExecuteScalar());

        var storedFileName = $"{contractId}-{Guid.NewGuid():N}.pdf";
        var storedFilePath = Path.Combine(options.PdfRoot, storedFileName);
        PdfDocumentGenerator.WriteContractPdf(storedFilePath, title, request.Content);

        var checksum = Hashing.Sha256Hex(contentBytes);

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
        Database.AddParameter(command, "$owner_user_id", user.Id);

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
    }

    private static IResult GetLatestContractVersion(
        HttpRequest httpRequest,
        long contractId,
        ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);

        if (!AuthService.TryGetUser(connection, httpRequest, out var user))
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
                v.content_text,
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
        Database.AddParameter(command, "$contract_id", contractId);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return Results.NotFound(new { error = "contract not found" });
        }

        var storedFilePath = reader.GetString(6);
        var storedContent = reader.GetString(8);
        var content = storedContent.Length > 0
            ? storedContent
            : File.Exists(storedFilePath) && Path.GetExtension(storedFilePath).Equals(".txt", StringComparison.OrdinalIgnoreCase)
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
            createdAt = reader.GetString(9),
            requestedByUserId = user.Id,
            content,
            pdfUrl = $"/api/contracts/{contractId}/versions/latest/pdf"
        });
    }

    private static IResult GetLatestContractPdf(
        HttpRequest httpRequest,
        long contractId,
        ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);

        if (!AuthService.TryGetUser(connection, httpRequest, out _))
        {
            return Results.Unauthorized();
        }

        using var command = connection.CreateCommand();

        /*
         * INTENTIONAL CTF VULNERABILITY: IDOR / missing authorization.
         *
         * This mirrors the latest-version JSON endpoint: a valid session is enough
         * to fetch any generated PDF by contract ID.
         */
        command.CommandText = """
            SELECT v.file_path
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
        Database.AddParameter(command, "$contract_id", contractId);

        var storedFilePath = command.ExecuteScalar() as string;
        if (storedFilePath is null || !File.Exists(storedFilePath))
        {
            return Results.NotFound(new { error = "contract PDF not found" });
        }

        if (!Path.GetExtension(storedFilePath).Equals(".pdf", StringComparison.OrdinalIgnoreCase))
        {
            return Results.NotFound(new { error = "contract PDF not found" });
        }

        return Results.File(storedFilePath, "application/pdf", $"{contractId}-latest.pdf");
    }
}
