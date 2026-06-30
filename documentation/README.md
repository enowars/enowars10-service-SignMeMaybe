# Service Documentation

SignMeMaybe is a contract signing and archive service with a file-backed notary vault. Contract records have visible title/content, private `CNTR-...` reference values, versions, checksums, and generated PDFs. Some contracts also have a public notary stamp proving that a private sealed record exists.

## Vulnerability 0: Metadata-Derived IDOR Flagstore

Checker vuln `0` stores flags in ordinary contract content. The latest JSON/PDF routes intentionally remain permissive: any authenticated user can request `GET /api/contracts/{reference}/versions/latest` or `/pdf` for any known `CNTR-...` reference.

Public holder metadata no longer exposes raw references. New contract references prefer:

```text
CNTR-<first 24 lowercase hex chars of sha256(username + ":" + title + ":" + checksum)>
```

The `username` is the canonical authenticated username, `title` is the trimmed contract title, and `checksum` is the lowercase content SHA-256. If the preferred reference already exists, creation falls back to a random `CNTR-...` reference. Checker flag content and titles are unique, so vuln `0` references should be metadata-derived.

## Vulnerability 1: Notary Flagstore

Checker vuln `1` flags are stored as private sealed records, not as normal contract text.

- `POST /api/contracts` accepts optional `notarySecret`.
- `notarySecret` is UTF-8 encoded, limited to 4096 bytes, written to a random file below `SIGNMEMAYBE_NOTARY_VAULT_ROOT`, and indexed in SQLite table `notary_secrets`.
- Public metadata exposes `notaryStamp` and latest-version metadata, but not sealed record bytes or raw contract references.
- Latest-version JSON returns normal contract content and does not include sealed record bytes.
- Ordinary victim PDFs do not automatically embed the sealed record.
- Owners can retrieve their own sealed record through `GET /api/contracts/{reference}/notary/sealed`.

Runtime storage environment:

- `SIGNMEMAYBE_DB_PATH`, default `/data/signmemaybe.sqlite3`
- `SIGNMEMAYBE_PDF_ROOT`, default `/data/pdfs`
- `SIGNMEMAYBE_EXPORT_ROOT`, default `/data/exports`
- `SIGNMEMAYBE_NOTARY_VAULT_ROOT`, default `/data/notary-vault`
- `SIGNMEMAYBE_CLEANUP_RETENTION_SECONDS`, default `720`

## Public Contract Metadata

`GET /api/users/{username}/contracts` returns public holder metadata:

```json
{
  "username": "arden_ledger_12345",
  "contracts": [
    {
      "title": "Certified Supplier Agreement",
      "createdAt": "2026-06-16 12:00:00",
      "latestVersion": {
        "versionNumber": 1,
        "approvalState": "draft",
        "checksum": "<sha256>",
        "createdAt": "2026-06-16 12:00:00"
      },
      "notaryStamp": "<public stamp>"
    }
  ]
}
```

The raw contract reference is intentionally absent from public metadata. For vuln `0`, the public username, contract title, and checksum are enough to derive likely candidate references. For vuln `1`, the stamp is not the sealed record and cannot be converted directly into the flag through public APIs.

## Vuln 0 Exploitation Path

1. The checker creates a victim contract with the flag in ordinary contract content.
2. The checker also creates three ordinary decoy contracts for the same victim user.
3. Public metadata exposes each victim contract title and checksum, but not raw contract references.
4. The attacker registers or logs in with their own account.
5. The attacker fetches `GET /api/users/{victimUsername}/contracts` and extracts the public username plus each contract title/checksum pair.
6. For each public contract, the attacker derives `CNTR-{sha256(username + ":" + title + ":" + checksum)[:24]}`.
7. The attacker reads `GET /api/contracts/{derivedReference}/versions/latest` or `/pdf` with their own valid session and searches the candidates for the flag.

## Certified PDF Annexes

Contract markup may declare external evidence attachments:

```html
<link rel="attachment" title="evidence.bin" href="https://example.com/evidence.bin">
```

During contract creation, the service parses up to two attachment directives, fetches each valid external evidence URL, and passes the fetched bytes to the existing custom `PdfDocumentGenerator`. Generated PDFs with fetched evidence contain an `/EmbeddedFiles` name tree and uncompressed embedded file streams.

The initial evidence URL validator accepts only `http` and `https` and rejects initial localhost/loopback targets such as `127.0.0.1`. The fetcher then uses automatic redirects and does not re-check the final redirected target.

## Internal Notary Interface

The render worker can access:

```http
GET /internal/notary/sealed/{publicStamp}
X-SignMeMaybe-Render-Worker: certified-pdf-v2
```

The route returns sealed record bytes only when the request comes from a loopback address and carries the render-worker header. External requests receive a non-success response. This route is not exposed in the browser UI.

## Compatibility Redirect

`GET /api/links/leave?to=<url>` is an unauthenticated compatibility redirect for external evidence links. It requires an absolute `http` or `https` target and returns a `302 Found` response without blocking localhost redirect targets.

## Vuln 1 Exploitation Path

The intended path is a Web2Doc-style certified annex chain:

1. The checker creates a victim contract with harmless public content and stores the flag in `notarySecret`.
2. Public metadata exposes the victim `notaryStamp`, but not the sealed record.
3. The attacker registers or logs in with their own account.
4. The attacker fetches `GET /api/users/{victimUsername}/contracts` and extracts `notaryStamp`.
5. The attacker builds an internal notary URL:

```text
http://127.0.0.1:1984/internal/notary/sealed/{notaryStamp}
```

6. The attacker URL-encodes that internal URL and wraps it with the compatibility redirect:

```text
http://TARGET:1984/api/links/leave?to=<encoded-internal-url>
```

7. The attacker creates their own contract containing:

```html
<link rel="attachment" title="sealed-record.txt" href="http://TARGET:1984/api/links/leave?to=<encoded-internal-url>">
```

8. During PDF generation, the annex fetcher validates only the initial `TARGET` URL, follows the redirect to `127.0.0.1`, and carries the render-worker header.
9. The internal notary route returns the victim sealed record to the render-worker request.
10. The existing custom PDF generator embeds those bytes as a PDF attachment in the attacker’s own generated PDF.
11. The attacker downloads their own latest PDF and extracts or raw-searches the uncompressed embedded file bytes.

## Checker Coverage

- **vuln `0` `putflag/getflag`**: Stores flags in ordinary contract content, creates three decoy contracts, verifies latest JSON/PDF, and checks that public metadata exposes title/checksum pairs but not references.
- **vuln `1` `putflag/getflag`**: Stores flags in `notarySecret`, records the public stamp, verifies owner-only sealed retrieval, and checks that latest JSON/PDF do not contain the sealed record.
- **`putnoise/getnoise`**: Stores ordinary title/content contracts and verifies standard account, listing, public title/checksum metadata, latest JSON, and PDF workflows.
- **`havoc`**: Runs stateless health and rejection checks.
- **vuln `0` `exploit`**: Uses public username/title/checksum metadata to derive candidate contract references and recover ordinary contract content through the IDOR.
- **vuln `1` `exploit`**: Uses public metadata, the compatibility redirect, certified annex fetching, and PDF embedded files to recover the sealed record.

## Runtime Cleanup

The cleanup container invokes:

```bash
dotnet /app/SignMeMaybe.dll --cleanup-once
```

Cleanup collects stale generated PDF paths, export paths, and `notary_secrets.secret_path` values before deleting old rows. It then removes old files under the configured PDF, export, and notary vault roots. Missing sealed-record files are ignored.

## Local Validation

Build and checker syntax:

```bash
dotnet build service/src/SignMeMaybe.csproj
python3 -m py_compile checker/src/checker.py
```

Start the service with temporary storage:

```bash
SIGNMEMAYBE_DB_PATH=/tmp/signmemaybe-smoke.sqlite3 SIGNMEMAYBE_PDF_ROOT=/tmp/signmemaybe-smoke-pdfs SIGNMEMAYBE_EXPORT_ROOT=/tmp/signmemaybe-smoke-exports SIGNMEMAYBE_NOTARY_VAULT_ROOT=/tmp/signmemaybe-smoke-notary-vault dotnet run --project service/src/SignMeMaybe.csproj --urls http://127.0.0.1:51989
```

Then verify ordinary contract creation, public metadata without raw references, metadata-derived latest retrieval, notary-backed contract creation, owner sealed-record retrieval, direct loopback annex rejection, redirect-based annex success, `/EmbeddedFiles` in attacker PDFs, and absence of the sealed record from the victim PDF.
