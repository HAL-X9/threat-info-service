# Threat Info Service

A REST service in Go for storing and exchanging threat intelligence, with each threat identified by the MD5 hash of the malicious file.

The API is spec-first: the OpenAPI document is the single source of truth for the contract. Server stubs are generated from it, and requests are validated against the same schema they are documented with, so the specification and the implementation cannot drift apart.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the layering, the request lifecycle and the reasoning behind the design decisions, and [api/openapi.yaml](api/openapi.yaml) for the API contract.

## Status

The project is under active development. The OpenAPI specification, the configuration subsystem, the PostgreSQL connection pool, and the HTTP server with graceful shutdown are in place. The only endpoints served so far are `GET /healthz` (the process is alive) and `GET /readyz` (the database answers a ping); the threat endpoints defined in the specification are not implemented yet.

## Quick start

### Run with Docker

Requirements: Docker with the Compose plugin.

```bash
git clone https://github.com/HAL-X9/threat-info-service.git
cd threat-info-service
make up
```

The command builds the service image and starts two containers: the service on port `8080` and PostgreSQL 18 on port `5432`. The service starts only after the database reports itself healthy.

### Run from source

Requirements: Go 1.27 and a reachable PostgreSQL instance. The Compose database can serve this purpose:

```bash
docker compose up -d postgres
make run
```

`make run` connects to the database published by Compose on `localhost:5432`. To use another database, set the DSN explicitly:

```bash
THREAT_INFO_DATABASE_DSN='postgres://user:password@host:5432/dbname?sslmode=disable' make run
```

## Verify

Once the service is running, check that it is alive and that it can reach the database:

```bash
curl -i http://localhost:8080/healthz
curl -i http://localhost:8080/readyz
```

`/healthz` answers `200 OK` while the process is alive. `/readyz` answers `200 OK` when the database responds and `503 Service Unavailable` otherwise.
