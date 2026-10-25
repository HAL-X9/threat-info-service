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

### Demo

```bash
make demo
make check-api
```

`make demo` does everything in one command: it creates `.env` and a self-signed certificate in `certs/` when they are missing, starts the database, applies the migrations, then builds the image and starts the service over HTTPS on https://localhost:8080. `make check-api` then calls every endpoint of the API and prints the status of each case, with the expected one:

```
PASS  POST /info                 create a threat     201
PASS  POST /info                 duplicate hash      409
PASS  GET  /info/{md5}           unknown hash        404
PASS  PUT  /info/{md5}           replace the threat  200
```

The script detects whether the service answers over HTTPS or HTTP, so it works after `make up` as well. The demo key is readable by the container user and must not be reused. Run `make up` to return to plain HTTP.

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

## TLS

The service serves plain HTTP unless the configuration names a certificate. To try TLS from source, create a self-signed certificate and add it to [`configs/config.yaml`](configs/config.yaml):

```bash
make cert
```

```yaml
httpserver:
  tls:
    cert_file: certs/cert.pem
    key_file: certs/key.pem
```

```bash
make run
curl --cacert certs/cert.pem https://localhost:8080/readyz
```

The files can also be given by `THREAT_INFO_TLS_CERT_FILE` and `THREAT_INFO_TLS_KEY_FILE`, which override the file; `make demo` uses them to enable TLS in the container. The server accepts TLS 1.2 and later, negotiates HTTP/2, and refuses to start when the certificate cannot be loaded. `make up` serves plain HTTP.

## Tests

| Command | Scope |
|---|---|
| `make test` | Unit tests with the race detector |
| `make test-integration` | The application on a PostgreSQL container, one test per endpoint (needs Docker) |
| `make test-e2e` | End-to-end flows against the running stack over HTTP (run `make up` first) |
| `make check-api` | A readable pass or fail report of every endpoint, over HTTPS or HTTP |

## Documentation

- [docs/api.md](docs/api.md): the HTTP API, with the model, the errors, the limits and examples
- [api/openapi.yaml](api/openapi.yaml): the API contract
- [ARCHITECTURE.md](ARCHITECTURE.md): the layering, the request lifecycle and the design decisions
- [docs/database.md](docs/database.md): the database schema and its constraints
- [docs/migrations.md](docs/migrations.md): the migration workflow
