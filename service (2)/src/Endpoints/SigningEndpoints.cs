using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SignMeMaybe.Configuration;
using SignMeMaybe.Data;
using SignMeMaybe.Models;
using SignMeMaybe.Security;
using SignMeMaybe.Signing;

namespace SignMeMaybe.Endpoints;

public static class SigningEndpoints
{
    private const int MaxSigningSecretBytes = 4096;

    public static void MapSigningEndpoints(this WebApplication app, ServiceOptions options)
    {
        app.MapGet("/api/signing/curves", () => Results.Ok(new
        {
            curves = SigningCurves.All.Select(SigningCurves.ToPublicCurve)
        }));

        app.MapPost("/api/signing/authorities", (HttpRequest httpRequest, SigningAuthorityCreateRequest request) =>
            CreateSigningAuthority(httpRequest, request, options));

        app.MapGet("/api/signing/authorities", (HttpRequest httpRequest) =>
            ListOwnSigningAuthorities(httpRequest, options));

        app.MapGet("/api/users/{username}/signing-authorities", (string username) =>
            ListPublicSigningAuthorities(username, options));

        app.MapGet("/api/signing/authorities/{authorityId}/secret", (HttpRequest httpRequest, string authorityId) =>
            GetOwnerSigningSecret(httpRequest, authorityId, options));

        app.MapPost("/api/signing/authorities/{authorityId}/ceremonies", (HttpRequest httpRequest, string authorityId, SignatureCeremonyCreateRequest request) =>
            CreateSignatureCeremony(httpRequest, authorityId, request, options));

        app.MapGet("/api/signing/ceremonies/{ceremonyId}", (HttpRequest httpRequest, string ceremonyId) =>
            GetSignatureCeremony(httpRequest, ceremonyId, options));

        app.MapPost("/api/signing/ceremonies/{ceremonyId}/validate", (HttpRequest httpRequest, string ceremonyId) =>
            ValidateSignatureCeremony(httpRequest, ceremonyId, options));
    }

    private static IResult CreateSigningAuthority(
        HttpRequest httpRequest,
        SigningAuthorityCreateRequest request,
        ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);
        if (!AuthService.TryGetUser(connection, httpRequest, out var user))
        {
            return Results.Unauthorized();
        }

        var displayName = request.DisplayName.Trim();
        if (displayName.Length is < 1 or > 120)
        {
            return Results.BadRequest(new { error = "displayName must be between 1 and 120 characters" });
        }

        var curveName = string.IsNullOrWhiteSpace(request.CurveName)
            ? SigningCurves.DefaultCurveName
            : request.CurveName.Trim();
        if (!SigningCurves.TryGet(curveName, out var curve))
        {
            return Results.BadRequest(new { error = "unknown signing curve" });
        }

        if (request.SigningSecret is not null
            && Encoding.UTF8.GetByteCount(request.SigningSecret) > MaxSigningSecretBytes)
        {
            return Results.BadRequest(new { error = $"signingSecret exceeds max size of {MaxSigningSecretBytes} bytes" });
        }

        var authorityId = CreateUniquePublicId(connection, "SIG-");
        var privateScalar = SigningSecretBox.CreatePrivateScalar(curve);
        var publicKey = curve.Multiply(privateScalar, curve.Generator);
        var secretBlob = string.IsNullOrEmpty(request.SigningSecret)
            ? null
            : SigningSecretBox.Encrypt(authorityId, curve, privateScalar, request.SigningSecret);
        var profileDigest = string.IsNullOrEmpty(request.SigningSecret)
            ? null
            : Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(request.SigningSecret))).ToLowerInvariant();

        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO signing_authorities
                (public_id, owner_user_id, display_name, curve_name, private_scalar,
                 public_key_x, public_key_y, secret_blob, secret_checksum)
            VALUES
                ($public_id, $owner_user_id, $display_name, $curve_name, $private_scalar,
                 $public_key_x, $public_key_y, $secret_blob, $secret_checksum);
            """;
        Database.AddParameter(command, "$public_id", authorityId);
        Database.AddParameter(command, "$owner_user_id", user.Id);
        Database.AddParameter(command, "$display_name", displayName);
        Database.AddParameter(command, "$curve_name", curve.Name);
        Database.AddParameter(command, "$private_scalar", EcCurve.ToFixedHex(privateScalar, curve.ScalarBytes));
        Database.AddParameter(command, "$public_key_x", EcCurve.ToHex(publicKey.X));
        Database.AddParameter(command, "$public_key_y", EcCurve.ToHex(publicKey.Y));
        Database.AddParameter(command, "$secret_blob", secretBlob);
        Database.AddParameter(command, "$secret_checksum", profileDigest);
        command.ExecuteNonQuery();

        return Results.Created($"/api/signing/authorities/{Uri.EscapeDataString(authorityId)}", new
        {
            authorityId,
            ownerUsername = user.Username,
            displayName,
            curveName = curve.Name,
            publicKey = SigningCurves.ToPublicPoint(publicKey),
            secretBlob
        });
    }

    private static IResult ListOwnSigningAuthorities(HttpRequest httpRequest, ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);
        if (!AuthService.TryGetUser(connection, httpRequest, out var user))
        {
            return Results.Unauthorized();
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT public_id, display_name, curve_name, public_key_x, public_key_y,
                   secret_blob, created_at
            FROM signing_authorities
            WHERE owner_user_id = $owner_user_id
            ORDER BY id ASC;
            """;
        Database.AddParameter(command, "$owner_user_id", user.Id);

        return Results.Ok(new
        {
            ownerUsername = user.Username,
            authorities = ReadAuthorities(command)
        });
    }

    private static IResult ListPublicSigningAuthorities(string username, ServiceOptions options)
    {
        username = username.Trim();
        if (username.Length == 0)
        {
            return Results.BadRequest(new { error = "username must not be empty" });
        }

        using var connection = Database.OpenConnection(options.DbPath);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT u.username, sa.public_id, sa.display_name, sa.curve_name,
                   sa.public_key_x, sa.public_key_y, sa.secret_blob,
                   sa.created_at
            FROM users u
            JOIN signing_authorities sa ON sa.owner_user_id = u.id
            WHERE u.username = $username
            ORDER BY sa.created_at ASC, sa.public_id ASC;
            """;
        Database.AddParameter(command, "$username", username);

        var authorities = new List<object>();
        string? canonicalUsername = null;
        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                canonicalUsername ??= reader.GetString(0);
                authorities.Add(ToAuthorityResponse(
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.GetString(3),
                    reader.GetString(4),
                    reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetString(6),
                    reader.GetString(7)));
            }
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
            authorities
        });
    }

    private static IResult GetOwnerSigningSecret(
        HttpRequest httpRequest,
        string authorityId,
        ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);
        if (!AuthService.TryGetUser(connection, httpRequest, out var user))
        {
            return Results.Unauthorized();
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT owner_user_id, curve_name, private_scalar, secret_blob
            FROM signing_authorities
            WHERE public_id = $public_id
            LIMIT 1;
            """;
        Database.AddParameter(command, "$public_id", authorityId);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return Results.NotFound(new { error = "signing authority not found" });
        }

        if (reader.GetInt64(0) != user.Id)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        if (reader.IsDBNull(3))
        {
            return Results.NotFound(new { error = "signing secret not found" });
        }

        if (!SigningCurves.TryGet(reader.GetString(1), out var curve))
        {
            return Results.BadRequest(new { error = "signing authority uses an unknown curve" });
        }

        var scalar = EcCurve.ParseHex(reader.GetString(2));
        var secret = SigningSecretBox.Decrypt(authorityId, curve, scalar, reader.GetString(3));
        return Results.Ok(new
        {
            authorityId,
            secret
        });
    }

    private static IResult CreateSignatureCeremony(
        HttpRequest httpRequest,
        string authorityId,
        SignatureCeremonyCreateRequest request,
        ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);
        if (!AuthService.TryGetUser(connection, httpRequest, out var user))
        {
            return Results.Unauthorized();
        }

        if (string.IsNullOrWhiteSpace(request.ContractReference))
        {
            return Results.BadRequest(new { error = "contractReference must not be empty" });
        }

        var contractReference = request.ContractReference.Trim();
        var contract = LoadLatestContractVersion(connection, contractReference);
        if (contract is null)
        {
            return Results.NotFound(new { error = "contract not found" });
        }

        if (contract.OwnerUserId != user.Id)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var authority = LoadAuthority(connection, authorityId);
        if (authority is null)
        {
            return Results.NotFound(new { error = "signing authority not found" });
        }

        var requestedCurveName = string.IsNullOrWhiteSpace(request.CurveName)
            ? authority.CurveName
            : request.CurveName.Trim();
        if (!string.Equals(requestedCurveName, authority.CurveName, StringComparison.OrdinalIgnoreCase))
        {
            return Results.BadRequest(new { error = "ceremony curve must match the signing authority curve" });
        }

        if (!SigningCurves.TryGet(authority.CurveName, out var curve))
        {
            return Results.BadRequest(new { error = "signing authority uses an unknown curve" });
        }

        if (!TryReadBasePoint(curve, request.BasePoint, out var basePoint, out var pointError))
        {
            return Results.BadRequest(new { error = pointError });
        }

        var privateScalar = EcCurve.ParseHex(authority.PrivateScalar);
        var signaturePoint = curve.Multiply(privateScalar, basePoint);
        var ceremonyId = CreateUniquePublicId(connection, "SGC-");
        var receiptTag = ComputeReceiptTag(authorityId, ceremonyId, contract, basePoint, signaturePoint);

        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO signature_ceremonies
                (public_id, authority_id, requester_user_id, contract_version_id,
                 curve_name, base_point_x, base_point_y, signature_point_x,
                 signature_point_y, signature_point_infinity, receipt_tag)
            VALUES
                ($public_id, $authority_id, $requester_user_id, $contract_version_id,
                 $curve_name, $base_point_x, $base_point_y, $signature_point_x,
                 $signature_point_y, $signature_point_infinity, $receipt_tag);
            """;
        Database.AddParameter(command, "$public_id", ceremonyId);
        Database.AddParameter(command, "$authority_id", authority.Id);
        Database.AddParameter(command, "$requester_user_id", user.Id);
        Database.AddParameter(command, "$contract_version_id", contract.Id);
        Database.AddParameter(command, "$curve_name", curve.Name);
        Database.AddParameter(command, "$base_point_x", EcCurve.ToHex(basePoint.X));
        Database.AddParameter(command, "$base_point_y", EcCurve.ToHex(basePoint.Y));
        Database.AddParameter(command, "$signature_point_x", signaturePoint.IsInfinity ? null : EcCurve.ToHex(signaturePoint.X));
        Database.AddParameter(command, "$signature_point_y", signaturePoint.IsInfinity ? null : EcCurve.ToHex(signaturePoint.Y));
        Database.AddParameter(command, "$signature_point_infinity", signaturePoint.IsInfinity ? 1 : 0);
        Database.AddParameter(command, "$receipt_tag", receiptTag);
        command.ExecuteNonQuery();

        return Results.Created($"/api/signing/ceremonies/{Uri.EscapeDataString(ceremonyId)}", ToCeremonyResponse(
            ceremonyId,
            authority.PublicId,
            user.Username,
            contract,
            curve.Name,
            basePoint,
            signaturePoint,
            receiptTag,
            "pending"));
    }

    private static IResult GetSignatureCeremony(
        HttpRequest httpRequest,
        string ceremonyId,
        ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);
        if (!AuthService.TryGetUser(connection, httpRequest, out var user))
        {
            return Results.Unauthorized();
        }

        var loaded = LoadCeremony(connection, ceremonyId);
        if (loaded is null)
        {
            return Results.NotFound(new { error = "signature ceremony not found" });
        }

        if (loaded.RequesterUserId != user.Id && loaded.AuthorityOwnerUserId != user.Id)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        return Results.Ok(ToCeremonyResponse(
            loaded.CeremonyId,
            loaded.AuthorityPublicId,
            loaded.RequesterUsername,
            loaded.Contract,
            loaded.CurveName,
            loaded.BasePoint,
            loaded.SignaturePoint,
            loaded.ReceiptTag,
            loaded.ValidationState));
    }

    private static IResult ValidateSignatureCeremony(
        HttpRequest httpRequest,
        string ceremonyId,
        ServiceOptions options)
    {
        using var connection = Database.OpenConnection(options.DbPath);
        if (!AuthService.TryGetUser(connection, httpRequest, out var user))
        {
            return Results.Unauthorized();
        }

        var loaded = LoadCeremony(connection, ceremonyId);
        if (loaded is null)
        {
            return Results.NotFound(new { error = "signature ceremony not found" });
        }

        if (loaded.RequesterUserId != user.Id && loaded.AuthorityOwnerUserId != user.Id)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var valid = false;
        if (SigningCurves.TryGet(loaded.CurveName, out var curve))
        {
            var expected = curve.Multiply(EcCurve.ParseHex(loaded.PrivateScalar), loaded.BasePoint);
            var expectedTag = ComputeReceiptTag(
                loaded.AuthorityPublicId,
                loaded.CeremonyId,
                loaded.Contract,
                loaded.BasePoint,
                expected);
            valid = PointsEqual(expected, loaded.SignaturePoint)
                && string.Equals(expectedTag, loaded.ReceiptTag, StringComparison.Ordinal);
        }

        var validationState = valid ? "valid" : "invalid";
        using (var update = connection.CreateCommand())
        {
            update.CommandText = """
                UPDATE signature_ceremonies
                SET validation_state = $validation_state
                WHERE public_id = $public_id;
                """;
            Database.AddParameter(update, "$validation_state", validationState);
            Database.AddParameter(update, "$public_id", ceremonyId);
            update.ExecuteNonQuery();
        }

        if (valid)
        {
            using var updateContract = connection.CreateCommand();
            updateContract.CommandText = """
                UPDATE contract_versions
                SET approval_state = 'signed'
                WHERE id = $contract_version_id;
                """;
            Database.AddParameter(updateContract, "$contract_version_id", loaded.Contract.Id);
            updateContract.ExecuteNonQuery();
        }

        return Results.Ok(new
        {
            ceremonyId = loaded.CeremonyId,
            authorityId = loaded.AuthorityPublicId,
            contract = ToContractResponse(loaded.Contract),
            valid,
            validationState
        });
    }

    private static List<object> ReadAuthorities(SqliteCommand command)
    {
        var authorities = new List<object>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            authorities.Add(ToAuthorityResponse(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.GetString(6)));
        }

        return authorities;
    }

    private static object ToAuthorityResponse(
        string authorityId,
        string displayName,
        string curveName,
        string publicKeyX,
        string publicKeyY,
        string? secretBlob,
        string createdAt)
    {
        return new
        {
            authorityId,
            displayName,
            curveName,
            publicKey = new { x = publicKeyX, y = publicKeyY },
            secretBlob,
            createdAt
        };
    }

    private static object ToCeremonyResponse(
        string ceremonyId,
        string authorityId,
        string requesterUsername,
        ContractVersionRow contract,
        string curveName,
        EcPoint basePoint,
        EcPoint signaturePoint,
        string receiptTag,
        string validationState)
    {
        return new
        {
            ceremonyId,
            authorityId,
            requesterUsername,
            contract = ToContractResponse(contract),
            curveName,
            basePoint = SigningCurves.ToPublicPoint(basePoint),
            signaturePoint = SigningCurves.ToPublicPoint(signaturePoint),
            receiptTag,
            validationState
        };
    }

    private static object ToContractResponse(ContractVersionRow contract)
    {
        return new
        {
            reference = contract.Reference,
            title = contract.Title,
            versionNumber = contract.VersionNumber,
            checksum = contract.Checksum
        };
    }

    private static bool TryReadBasePoint(
        EcCurve curve,
        EcPointRequest? request,
        out EcPoint point,
        out string error)
    {
        try
        {
            point = request is null
                ? curve.Generator
                : new EcPoint(EcCurve.ParseHex(request.X), EcCurve.ParseHex(request.Y));
        }
        catch (FormatException)
        {
            point = EcPoint.Infinity;
            error = "basePoint coordinates must be hex strings";
            return false;
        }

        if (!curve.IsInField(point))
        {
            error = "basePoint coordinates must be inside the selected field";
            return false;
        }

        error = "";
        return true;
    }

    private static ContractVersionRow? LoadLatestContractVersion(SqliteConnection connection, string reference)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                v.id,
                c.owner_user_id,
                c.public_reference,
                c.title,
                v.version_number,
                v.checksum
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

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        return new ContractVersionRow(
            reader.GetInt64(0),
            reader.GetInt64(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetInt32(4),
            reader.GetString(5));
    }

    private static SigningAuthorityRow? LoadAuthority(SqliteConnection connection, string authorityId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, public_id, owner_user_id, curve_name, private_scalar
            FROM signing_authorities
            WHERE public_id = $public_id
            LIMIT 1;
            """;
        Database.AddParameter(command, "$public_id", authorityId);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        return new SigningAuthorityRow(
            reader.GetInt64(0),
            reader.GetString(1),
            reader.GetInt64(2),
            reader.GetString(3),
            reader.GetString(4));
    }

    private static SignatureCeremonyRow? LoadCeremony(SqliteConnection connection, string ceremonyId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                sc.public_id,
                sa.public_id,
                sa.owner_user_id,
                sa.private_scalar,
                sc.requester_user_id,
                u.username,
                v.id,
                c.owner_user_id,
                c.public_reference,
                c.title,
                v.version_number,
                v.checksum,
                sc.curve_name,
                sc.base_point_x,
                sc.base_point_y,
                sc.signature_point_x,
                sc.signature_point_y,
                sc.signature_point_infinity,
                sc.receipt_tag,
                sc.validation_state
            FROM signature_ceremonies sc
            JOIN signing_authorities sa ON sa.id = sc.authority_id
            JOIN users u ON u.id = sc.requester_user_id
            JOIN contract_versions v ON v.id = sc.contract_version_id
            JOIN contracts c ON c.id = v.contract_id
            WHERE sc.public_id = $public_id
            LIMIT 1;
            """;
        Database.AddParameter(command, "$public_id", ceremonyId);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var signaturePoint = reader.GetInt32(17) == 1
            ? EcPoint.Infinity
            : new EcPoint(EcCurve.ParseHex(reader.GetString(15)), EcCurve.ParseHex(reader.GetString(16)));

        return new SignatureCeremonyRow(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetInt64(2),
            reader.GetString(3),
            reader.GetInt64(4),
            reader.GetString(5),
            new ContractVersionRow(
                reader.GetInt64(6),
                reader.GetInt64(7),
                reader.GetString(8),
                reader.GetString(9),
                reader.GetInt32(10),
                reader.GetString(11)),
            reader.GetString(12),
            new EcPoint(EcCurve.ParseHex(reader.GetString(13)), EcCurve.ParseHex(reader.GetString(14))),
            signaturePoint,
            reader.GetString(18),
            reader.GetString(19));
    }

    private static string CreateUniquePublicId(SqliteConnection connection, string prefix)
    {
        for (var attempt = 0; attempt < 16; attempt++)
        {
            var publicId = SigningSecretBox.CreatePublicId(prefix);
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT 1
                FROM signing_authorities
                WHERE public_id = $public_id
                UNION
                SELECT 1
                FROM signature_ceremonies
                WHERE public_id = $public_id
                LIMIT 1;
                """;
            Database.AddParameter(command, "$public_id", publicId);
            if (command.ExecuteScalar() is null)
            {
                return publicId;
            }
        }

        throw new InvalidOperationException("Could not create a unique signing id.");
    }

    private static string ComputeReceiptTag(
        string authorityId,
        string ceremonyId,
        ContractVersionRow contract,
        EcPoint basePoint,
        EcPoint signaturePoint)
    {
        var signatureText = signaturePoint.IsInfinity
            ? "infinity"
            : $"{EcCurve.ToHex(signaturePoint.X)}:{EcCurve.ToHex(signaturePoint.Y)}";
        var material = Encoding.UTF8.GetBytes(
            $"contract-signature:v1:{authorityId}:{ceremonyId}:{contract.Reference}:{contract.VersionNumber}:{contract.Checksum}:{EcCurve.ToHex(basePoint.X)}:{EcCurve.ToHex(basePoint.Y)}:{signatureText}");
        return Convert.ToHexString(SHA256.HashData(material)).ToLowerInvariant();
    }

    private static bool PointsEqual(EcPoint left, EcPoint right)
    {
        return left.IsInfinity == right.IsInfinity
            && (left.IsInfinity || (left.X == right.X && left.Y == right.Y));
    }

    private sealed record SigningAuthorityRow(
        long Id,
        string PublicId,
        long OwnerUserId,
        string CurveName,
        string PrivateScalar);

    private sealed record ContractVersionRow(
        long Id,
        long OwnerUserId,
        string Reference,
        string Title,
        int VersionNumber,
        string Checksum);

    private sealed record SignatureCeremonyRow(
        string CeremonyId,
        string AuthorityPublicId,
        long AuthorityOwnerUserId,
        string PrivateScalar,
        long RequesterUserId,
        string RequesterUsername,
        ContractVersionRow Contract,
        string CurveName,
        EcPoint BasePoint,
        EcPoint SignaturePoint,
        string ReceiptTag,
        string ValidationState);
}
