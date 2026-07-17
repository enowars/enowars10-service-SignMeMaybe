namespace SignMeMaybe.Models;

public sealed record RegisterRequest(string Username, string Password);

public sealed record LoginRequest(string Username, string Password);

public sealed record ContractCreateRequest(string Title, string Content, string? ArchivePacket = null);

public sealed record ContractUpdateRequest(string Title, string Content);

public sealed record SigningAuthorityCreateRequest(
    string DisplayName,
    string? CurveName = null,
    string? SigningSecret = null);

public sealed record EcPointRequest(string X, string Y);

public sealed record SignatureCeremonyCreateRequest(
    string ContractReference,
    string? CurveName = null,
    EcPointRequest? BasePoint = null);
