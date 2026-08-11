# Vulnerabilities

SignMeMaybe contains three intentional vulnerabilities. Each vulnerability maps to one checker vuln ID and one flagstore.

| Vuln ID | Name | Flag location | Public clue | Impact |
| --- | --- | --- | --- | --- |
| `0` | Metadata-derived IDOR | Contract `content` | Public title and checksum | Read another user's latest contract JSON/PDF |
| `1` | Archive annex SSRF | Private `archivePacket` file | Public `archiveTicket` | Embed another user's archive packet in an attacker PDF |
| `2` | Faulty curve signing | Signing authority `signingSecret` | Public `secretBlob` and authority ID | Recover signing scalar and decrypt the private note |

## Vuln 0: Metadata-Derived IDOR

Checker vuln `0` stores the flag directly in ordinary contract content:

```text
Escrow disclosure: ENO...
```

The service tries to keep raw contract references private. Owner listings include `reference`, but public holder metadata from `GET /api/users/{username}/contracts` omits it.

The problem is that normal contract references are deterministic:

```text
CNTR-<sha256(username + ":" + trimmedTitle + ":" + lowercaseChecksum)[:24]>
```

Public metadata contains all three inputs needed for that formula:

- canonical `username`
- contract `title`
- latest version `checksum`

After deriving the reference, any authenticated user can call:

```http
GET /api/contracts/{reference}/versions/latest
GET /api/contracts/{reference}/versions/latest/pdf
```

Those latest-version endpoints only require a valid session. They do not require the requester to own the referenced contract. This creates an IDOR that leaks the flag from contract JSON or the generated PDF.

Important implementation areas:

- Reference derivation: `CreateArchiveReference` in `ContractEndpoints.cs`
- Public metadata: `ListPublicContractsByUsername`
- Vulnerable reads: `GetLatestContractVersion` and `GetLatestContractPdf`

## Vuln 1: Archive Annex SSRF

Checker vuln `1` stores the flag as a private archive packet:

```json
{
  "title": "Certified Supplier Agreement ...",
  "content": "This contract package includes a private archive packet.",
  "archivePacket": "ENO..."
}
```

The public contract body and PDF do not contain the packet. The owner-only API protects the packet by contract ownership:

```http
GET /api/contracts/{reference}/archive/packet
```

Public metadata still exposes the packet's `archiveTicket`:

```json
{
  "title": "Certified Supplier Agreement ...",
  "latestVersion": {
    "checksum": "..."
  },
  "archiveTicket": "..."
}
```

The PDF generator supports certified annex attachments declared in contract content:

```html
<link rel="attachment" title="evidence.bin" href="https://example.com/evidence.bin">
```

When a contract is created or updated, the service parses up to two attachment links, fetches them, and embeds the fetched bytes into the generated PDF as `/EmbeddedFiles`.

The fetcher blocks ordinary loopback/private URLs for initial targets. However, it deliberately allows same-service `/api/links/leave?to=...` URLs and follows redirects. A redirect target matching this pattern is treated as an internal archive packet fetch:

```text
http://127.0.0.1:1984/internal/archive/packets/{archiveTicket}
```

For that internal target, the fetcher pins the request to loopback and adds:

```http
X-SignMeMaybe-Pdf-Worker: annex-worker-v2
```

The internal archive route only requires loopback plus that worker header. It does not know which user caused the PDF generation. Therefore an attacker can use a victim's public `archiveTicket` as an annex target, generate an attacker-owned PDF, and receive the victim's private archive packet as an embedded file.

Important implementation areas:

- Annex parsing: `AnnexDirectiveParser.cs`
- Remote fetching and redirect handling: `RemoteAnnexFetcher.cs`
- Internal packet route: `InternalArchiveEndpoints.cs`
- PDF embedded files: `PdfDocumentGenerator.cs`

## Vuln 2: Faulty Curve Signing

Checker vuln `2` stores the flag as a private signing note on a P-256 signing authority:

```json
{
  "displayName": "Civic Signing Authority ...",
  "curveName": "P-256",
  "signingSecret": "ENO..."
}
```

The owner can retrieve the plaintext note with:

```http
GET /api/signing/authorities/{authorityId}/secret
```

Public metadata exposes the authority ID, curve, public key, and encrypted note blob:

```json
{
  "authorityId": "SIG-...",
  "curveName": "P-256",
  "publicKey": {
    "x": "...",
    "y": "..."
  },
  "secretBlob": "v1:<nonceHex>:<ciphertextHex>"
}
```

Signing ceremonies let a requester provide a custom `basePoint`. The service checks that the submitted coordinates parse as hex and are inside the field:

```text
0 <= x < p
0 <= y < p
```

It does not check that the point lies on the selected elliptic curve.

The scalar multiplication formulas use the selected curve's field and `a` parameter. If the attacker submits a point on a related singular/off-curve group with known structure, the returned `signaturePoint = privateScalar * basePoint` leaks the authority's private scalar. For P-256 authorities the generated scalar is intentionally only 96 bits, so the checker exploit recovers it from one chosen point of order `2^96`.

Once the scalar is known, the attacker can reproduce the signing-note keystream and decrypt `secretBlob`.

Important implementation areas:

- Base point validation: `TryReadBasePoint` in `SigningEndpoints.cs`
- Scalar multiplication: `EllipticCurve.cs`
- Signing note encryption/decryption: `SigningSecretBox.cs`
