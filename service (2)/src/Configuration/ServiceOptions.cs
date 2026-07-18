namespace SignMeMaybe.Configuration;

public sealed record ServiceOptions(
    string DbPath,
    string PdfRoot,
    string ExportRoot,
    string PacketRoot,
    long MaxUploadBytes,
    int CleanupRetentionSeconds)
{
    public static ServiceOptions LoadFromEnvironment()
    {
        var dbPath = Environment.GetEnvironmentVariable("SIGNMEMAYBE_DB_PATH")
            ?? "/data/signmemaybe.sqlite3";

        var pdfRoot = Environment.GetEnvironmentVariable("SIGNMEMAYBE_PDF_ROOT")
            ?? "/data/pdfs";

        var exportRoot = Environment.GetEnvironmentVariable("SIGNMEMAYBE_EXPORT_ROOT")
            ?? "/data/exports";

        var packetRoot = Environment.GetEnvironmentVariable("SIGNMEMAYBE_PACKET_ROOT")
            ?? "/data/packets";

        var maxUploadBytesRaw = Environment.GetEnvironmentVariable("SIGNMEMAYBE_MAX_UPLOAD_BYTES")
            ?? "10485760";

        var maxUploadBytes = long.TryParse(maxUploadBytesRaw, out var parsedMaxUploadBytes)
            ? parsedMaxUploadBytes
            : 10_485_760;

        var cleanupRetentionSeconds = LoadPositiveInt(
            "SIGNMEMAYBE_CLEANUP_RETENTION_SECONDS",
            720);

        return new ServiceOptions(dbPath, pdfRoot, exportRoot, packetRoot, maxUploadBytes, cleanupRetentionSeconds);
    }

    public void EnsureStorageExists()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(DbPath) ?? "/data");
        Directory.CreateDirectory(PdfRoot);
        Directory.CreateDirectory(ExportRoot);
        Directory.CreateDirectory(PacketRoot);
    }

    private static int LoadPositiveInt(string name, int fallback)
    {
        var raw = Environment.GetEnvironmentVariable(name);
        return int.TryParse(raw, out var parsed) && parsed > 0
            ? parsed
            : fallback;
    }
}
