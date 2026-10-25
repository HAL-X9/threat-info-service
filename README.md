# Threat Info Service

A REST service in Go for storing and exchanging threat intelligence, with each threat identified by the MD5 hash of the malicious file.

The API is spec-first: the OpenAPI document is the single source of truth for the contract. Server stubs are generated from it, and requests are validated against the same schema they are documented with, so the specification and the implementation cannot drift apart.

## Quick start

### Run with Docker

Requirements: Docker with the Compose plugin.

```bash
git clone https://github.com/HAL-X9/threat-info-service.git
cd threat-info-service
make up
```

The command creates `.env` from [`.env.example`](.env.example) on the first run, starts PostgreSQL 18 on port `5432`, applies the database migrations, then builds the image and starts the service on port `8080`. The example file holds ready-to-use test values for the local database and for the API token, so nothing has to be configured. Swagger UI serves the API documentation at http://localhost:8082. Goose is not required: the Makefile runs a pinned version through Go. Run `make help` to see every command.

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

## API

| Method | Path | Purpose | Token |
|---|---|---|---|
| `POST` | `/info` | Create a threat | Required |
| `GET` | `/info/{md5}` | Read a threat | Not required |
| `PUT` | `/info/{md5}` | Replace the details of a threat | Required |

`POST` and `PUT` require the header `Authorization: Bearer <token>`; the token is `THREAT_INFO_API_TOKEN` (`local-dev-token-1234` in the example file).

```bash
curl -i -X POST http://localhost:8080/info \
  -H 'Authorization: Bearer local-dev-token-1234' \
  -H 'Content-Type: application/json' \
  -d '{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic","severity":"high","category":"trojan"}'

curl -i http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e
```

`GET /healthz` reports that the process is alive, and `GET /readyz` that the database responds. The full description, with the model, the errors and the limits, is in [docs/api.md](docs/api.md).

## Tests

| Command | Scope |
|---|---|
| `make test` | Unit tests with the race detector |
| `make test-integration` | The application on a PostgreSQL container, one test per endpoint (needs Docker) |
| `make test-e2e` | End-to-end flows against the running stack (run `make up` first) |

## Documentation

- [docs/api.md](docs/api.md): the HTTP API, with the model, the errors, the limits and examples
- [api/openapi.yaml](api/openapi.yaml): the API contract
- [ARCHITECTURE.md](ARCHITECTURE.md): the layering, the request lifecycle and the design decisions
- [docs/database.md](docs/database.md): the database schema and its constraints
- [docs/migrations.md](docs/migrations.md): the migration workflow
