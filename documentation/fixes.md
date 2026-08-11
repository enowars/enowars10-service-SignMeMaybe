# Fixes

This page describes the fixes for a defended or post-competition version of SignMeMaybe. The `main` branch keeps the vulnerabilities for the A/D CTF service, while the `fixed` branch already contains these fixes implemented. Each fix should preserve legitimate owner workflows and break only the exploit path.

## Fix Vuln 0: Enforce Contract Ownership

Problem: `GET /api/contracts/{reference}/versions/latest` and `/pdf` return another user's contract to any authenticated requester who knows or derives the reference.

Fix:

- In `GetLatestContractVersion`, load `c.owner_user_id` and compare it with the authenticated user ID before returning content.
- In `GetLatestContractPdf`, apply the same owner check before returning the PDF file.
- Return `403 Forbidden` for an authenticated non-owner and keep `404 Not Found` for unknown references.
- Optionally stop deriving references from public metadata and always use random `CNTR-...` values. This is defense in depth; the required fix is the authorization check.

Regression checks:

- Owner can fetch latest JSON and PDF for their contract.
- Different authenticated user receives `403` for latest JSON and PDF.
- Unauthenticated user still receives `401`.
- Public metadata still omits `reference`.
- Checker `getflag(0)` owner retrieval still works.
- Checker `exploit(0)` can no longer recover flags.

## Fix Vuln 1: Block User-Controlled Internal Annex Fetches

Problem: user-controlled annex URLs can redirect through `/api/links/leave` to `/internal/archive/packets/{ticket}`. The annex fetcher then adds the PDF worker header and embeds private packet bytes in the attacker's PDF.

Fix:

- In `RemoteAnnexFetcher`, remove the special redirect allowance for `/internal/archive/packets/` when the URL originates from user contract content.
- Re-validate every redirect target with the same public-target rules as initial URLs.
- Keep loopback, private, link-local, multicast, and wildcard addresses blocked for user-supplied annexes, including after redirects.
- Do not add `X-SignMeMaybe-Pdf-Worker: annex-worker-v2` for any user-supplied external annex fetch.
- Keep `/internal/archive/packets/{ticket}` restricted to loopback plus worker header for trusted internal jobs only.

Optional hardening:

- Remove `archiveTicket` from public metadata if public packet discovery is not needed.
- Make archive packet embedding an owner-authenticated server action instead of a URL fetch side effect.
- Restrict `/api/links/leave` so it rejects loopback/private destinations.

Regression checks:

- Owner can still retrieve their packet through `GET /api/contracts/{reference}/archive/packet`.
- Different authenticated user still receives `403` for the owner packet endpoint.
- Public external annexes still embed when they use allowed public HTTP/HTTPS targets.
- Direct loopback annex URLs are rejected or ignored.
- `/api/links/leave` redirect to loopback/internal packet is rejected or ignored by PDF generation.
- Generated attacker PDFs no longer contain the victim archive packet.
- Checker `getflag(1)` still works, and checker `exploit(1)` fails.

## Fix Vuln 2: Validate Signing Base Points

Problem: signing ceremonies accept a custom base point that is inside the field but not on the selected curve. Multiplication by that attacker-controlled off-curve point leaks the private scalar.

Fix:

- In `TryReadBasePoint`, after parsing and field checks, call `curve.IsOnCurve(point)`.
- Return `400 Bad Request` for any custom point that is not on the selected curve.
- Keep the default generator path unchanged when `basePoint` is omitted.
- Consider rejecting all custom base points unless the feature is required.

Minimal intended validation:

```csharp
if (!curve.IsOnCurve(point))
{
    error = "basePoint must be on the selected curve";
    return false;
}
```

Optional hardening:

- Use full-width private scalars for P-256 instead of the 96-bit profile scalar.
- Replace the custom XOR stream for `secretBlob` with authenticated encryption.
- Add rate limiting for ceremony creation.

Regression checks:

- Default ceremony creation and validation still works.
- A valid custom generator point on the selected curve still works if custom points remain supported.
- Field-valid but off-curve points return `400`.
- Curve mismatch still returns `400`.
- Owner-only `GET /api/signing/authorities/{authorityId}/secret` still works.
- Public signing metadata can still be listed without exposing plaintext notes.
- Checker `getflag(2)` still works, and checker `exploit(2)` fails.

## Documentation And Operations Checks

When validating the `fixed` branch or reapplying the fixes elsewhere, run at least these checks:

```bash
dotnet build service/src/SignMeMaybe.csproj
python3 -m py_compile checker/src/checker.py
```

Then run the service and checker locally and verify:

- `havoc` checks pass.
- Owner `putflag/getflag` paths pass for all vuln IDs.
- Reference-derivation, annex-redirect, and off-curve exploit paths no longer return flags.
