# Threat Info Service

A REST service in Go for storing and exchanging threat intelligence, with each threat identified by the MD5 hash of the malicious file.

The API is spec-first: the OpenAPI document is the single source of truth for the contract. Server stubs are generated from it, and requests are validated against the same schema they are documented with, so the specification and the implementation cannot drift apart.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the layering, the request lifecycle and the reasoning behind the design decisions, [api/openapi.yaml](api/openapi.yaml) for the API contract, and [docs/database.md](docs/database.md) for the database schema and migrations.

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

The command creates `.env` from [`.env.example`](.env.example) on the first run, starts PostgreSQL 18 on port `5432`, applies the database migrations, then builds the image and starts the service on port `8080`. The example file holds ready-to-use test values for the local database and for the API token, so nothing has to be configured. The API documentation is served by Swagger UI at http://localhost:8082. Goose is not required: the Makefile runs a pinned version through Go. Run `make help` to see every command.

### Run from source

Requirements: Go 1.27 and Docker for the database.

```bash
make run
```

`make run` starts the Compose database if needed, applies the migrations and runs the service against `localhost:5432`. To use another database, set the DSN explicitly. The migration commands honour it too:

```bash
export THREAT_INFO_DATABASE_DSN='postgres://user:password@host:5432/dbname?sslmode=disable'
make migrate-up
go run ./cmd
```

## Verify

Once the service is running, check that it is alive and that it can reach the database:

```bash
curl -i http://localhost:8080/healthz
curl -i http://localhost:8080/readyz
```

`/healthz` answers `200 OK` while the process is alive. `/readyz` answers `200 OK` when the database responds and `503 Service Unavailable` otherwise.

Reads are open. `POST` and `PUT` require a bearer token from `THREAT_INFO_API_TOKEN` (`local-dev-token-1234` in the example file):

```bash
curl -i -X POST http://localhost:8080/info \
  -H 'Authorization: Bearer local-dev-token-1234' \
  -H 'Content-Type: application/json' \
  -d '{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic","severity":"high","category":"trojan"}'

curl -i http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e
```
