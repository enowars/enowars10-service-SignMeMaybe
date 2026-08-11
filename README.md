# SignMeMaybe

SignMeMaybe is a small contract signing and archive service for attack/defense CTFs. Users can register, create contract records, generate PDFs, attach private archive packets, publish limited metadata, and run signing ceremonies through named signing authorities.

The detailed handoff documentation lives in [`documentation/`](documentation/README.md).

## Quick Start

Start the service:

```bash
cd service
docker compose up --build
```

The web interface and API are available at:

```text
http://localhost:1984
```

Stop the service:

```bash
cd service
docker compose down
```

## Checker

Start the checker:

```bash
cd checker
docker compose up --build
```

The local checker API documentation is available at:

```text
http://localhost:11984/docs/
```

Run a local checker test after both service and checker are running:

```bash
ENOCHECKER_SERVICE_ADDRESS="<host-ip-address>" ENOCHECKER_CHECKER_PORT=11984 ENOCHECKER_TEST_CHECKER_ADDRESS="localhost" enochecker_test
```

## Basic Workflow

1. Register or log in through the web interface.
2. Create a contract with a title and content.
3. Inspect your private archive cabinet to view contract references, latest versions, checksums, and PDFs.
4. Search another user's public ledger to see public contract metadata.
5. Create signing authorities and use them to sign your own contracts.

## Project Layout

- `service/`: ASP.NET Core service, Docker setup, persisted runtime data, and cleanup container.
- `checker/`: Python `enochecker3` checker and MongoDB-backed checker state.
- `documentation/`: Service overview, vulnerabilities, exploit recipes, and intended fixes.

Start with [`documentation/README.md`](documentation/README.md) for the full service handoff.
