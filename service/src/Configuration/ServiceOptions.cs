namespace SignMeMaybe.Configuration;

public sealed record ServiceOptions(
    string DbPath,
    string PdfRoot,
    string ExportRoot,
    long MaxUploadBytes)
{
    public static ServiceOptions LoadFromEnvironment()
    {
        var dbPath = Environment.GetEnvironmentVariable("SIGNMEMAYBE_DB_PATH")
            ?? "/data/signmemaybe.sqlite3";

        var pdfRoot = Environment.GetEnvironmentVariable("SIGNMEMAYBE_PDF_ROOT")
            ?? "/data/pdfs";

        var exportRoot = Environment.GetEnvironmentVariable("SIGNMEMAYBE_EXPORT_ROOT")
            ?? "/data/exports";

        var maxUploadBytesRaw = Environment.GetEnvironmentVariable("SIGNMEMAYBE_MAX_UPLOAD_BYTES")
            ?? "10485760";

        var maxUploadBytes = long.TryParse(maxUploadBytesRaw, out var parsedMaxUploadBytes)
            ? parsedMaxUploadBytes
            : 10_485_760;

        return new ServiceOptions(dbPath, pdfRoot, exportRoot, maxUploadBytes);
    }

    public void EnsureStorageExists()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(DbPath) ?? "/data");
        Directory.CreateDirectory(PdfRoot);
        Directory.CreateDirectory(ExportRoot);
    }
}
