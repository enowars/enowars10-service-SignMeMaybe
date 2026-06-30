namespace SignMeMaybe.Models;

public sealed record RegisterRequest(string Username, string Password);

public sealed record LoginRequest(string Username, string Password);

public sealed record ContractCreateRequest(string Title, string Content, string? NotarySecret = null);
