# SignMeMaybe Documentation

This folder contains the long-form documentation for SignMeMaybe. It is written for people who did not work on the service originally and need to run, understand, exploit, or fix it in a later attack/defense CTF.

SignMeMaybe is a departmental contract registry built as an ASP.NET Core service. Users create contract records, receive private `CNTR-...` references, publish limited public metadata, generate certified PDFs, attach private archive packets, and create signing authorities for contract signature ceremonies.

## Read This First

- [`service-overview.md`](service-overview.md): how the service, checker, storage, API, and cleanup job work.
- [`vulnerabilities.md`](vulnerabilities.md): the three intentional flagstores and why each one is vulnerable.
- [`exploits.md`](exploits.md): step-by-step exploit recipes for all checker vuln IDs.
- [`fixes.md`](fixes.md): intended fixes and regression checks for a defended version.

## Flagstores

| Vuln ID | Flagstore | Public clue | Intended bug |
| --- | --- | --- | --- |
| `0` | Ordinary contract content | Public title and checksum | Metadata-derived contract references plus IDOR on latest-version endpoints |
| `1` | Private archive packet file | Public `archiveTicket` | Certified PDF annex fetching can reach the internal archive packet endpoint |
| `2` | Private signing authority note | Public signing authority and `secretBlob` | Signing ceremonies accept off-curve base points |

## Runtime At A Glance

- Service port: `1984`
- Checker port: `11984`
- Service framework: ASP.NET Core / .NET 10
- Service storage: SQLite plus managed file roots for PDFs, exports, and archive packets
- Checker framework: Python `enochecker3`
- Checker state: MongoDB
- Authentication: random session token in the `X-Session-Token` header

## Operational Disclaimer

During the permanent setup phase and the ENOWARS A/D CTF, SignMeMaybe did not perform reliably under heavy load. After some time under contest traffic, the service started to return frequent checker mumbles. The service includes cleanup, SQLite busy handling, and resource limits, but future operators should treat load behavior as a known risk and run their own stress/performance validation before reusing it in another A/D CTF.

## Documentation Conventions

Endpoint examples use `http://TARGET:1984` for the victim service. Replace `TARGET` with the service IP or hostname provided by the checker or CTF infrastructure.

The exploit pages describe the intended CTF vulnerabilities in enough detail to reproduce them in a lab or competition environment. They do not add runnable exploit files to the repository.
