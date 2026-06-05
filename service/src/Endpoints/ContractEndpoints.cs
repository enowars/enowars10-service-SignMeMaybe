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

        app.MapGet("/api/users/{username}/contracts", (string username) =>
            ListPublicContractsByUsername(username, options));

        app.MapGet("/api/contracts/{reference}/versions/latest", (HttpRequest httpRequest, string reference) =>
            GetLatestContractVersion(httpRequest, reference, options));

        app.MapGet("/api/contracts/{reference}/versions/latest/pdf", (HttpRequest httpRequest, string reference) =>
            GetLatestContractPdf(httpRequest, reference, options));
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

        var reference = Database.CreateUniqueContractReference(connection, transaction);

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

        var storedFileName = $"{reference}-{Guid.NewGuid():N}.pdf";
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

        insertVersion.ExecuteScalar();

        transaction.Commit();

        return Results.Created($"/api/contracts/{Uri.EscapeDataString(reference)}/versions/latest", new
        {
            reference,
            ownerUsername = user.Username,
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
                c.public_reference,
                c.title,
                c.created_at,
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
                reference = reader.GetString(0),
                title = reader.GetString(1),
                createdAt = reader.GetString(2),
                latestVersion = new
                {
                    versionNumber = reader.GetInt32(3),
                    approvalState = reader.GetString(4),
                    checksum = reader.GetString(5),
                    createdAt = reader.GetString(6)
                }
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
                v.created_at
            FROM users u
            JOIN contracts c ON c.owner_user_id = u.id
            JOIN contract_versions v ON v.contract_id = c.id
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
                reference = reader.GetString(1),
                title = reader.GetString(2),
                createdAt = reader.GetString(3),
                latestVersion = new
                {
                    versionNumber = reader.GetInt32(4),
                    approvalState = reader.GetString(5),
                    checksum = reader.GetString(6),
                    createdAt = reader.GetString(7)
                }
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

        var storedFilePath = reader.GetString(5);
        var storedContent = reader.GetString(7);
        var content = storedContent.Length > 0
            ? storedContent
            : File.Exists(storedFilePath) && Path.GetExtension(storedFilePath).Equals(".txt", StringComparison.OrdinalIgnoreCase)
            ? File.ReadAllText(storedFilePath, Encoding.UTF8)
            : "";

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
}
