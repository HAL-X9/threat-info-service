# Migrations

The schema is managed with [goose](https://github.com/pressly/goose). Each migration is one SQL file in [`migrations/`](../migrations), applied in order of its version number.

## Files

```
migrations/00001_create_threats.sql
```

A file has two sections: the statements under `-- +goose Up` apply the change, and the ones under `-- +goose Down` revert it. Goose records the applied versions in the `goose_db_version` table and applies only what is missing, so running it twice is safe.

Goose is not installed on the machine. The Makefile runs a pinned version with `go run`, so the only requirement is Go.

## Commands

| Command | Action |
|---|---|
| `make up` | Starts everything: the database, the migrations, then the service |
| `make migrate-up` | Applies the pending migrations |
| `make migrate-down` | Reverts the last migration |
| `make migrate-status` | Lists the migrations and whether they are applied |
| `make migrate-create name=add_source` | Creates the next numbered migration file |
| `make run` | Starts the database, applies the migrations, then runs the service from source |

`make up` is the single command that leaves everything ready. The migration commands use `THREAT_INFO_DATABASE_DSN`, which defaults to the Compose database on `localhost:5432`, so they work with any database when it is set:

```bash
THREAT_INFO_DATABASE_DSN='postgres://user:password@host:5432/dbname?sslmode=disable' make migrate-up
```

## Startup order

```mermaid
%%{init: {'theme':'base'}}%%
flowchart LR
    DB["Start postgres, wait until healthy"] --> MIG["Apply migrations with goose"]
    MIG --> APP["Start the service"]

    classDef default fill:#e5f3ff,stroke:none,color:#22559b;
```

The migrations run between the two steps, so the service never starts against a missing or half-built schema. If a migration fails, `make up` stops before the service is started.

## Adding a migration

1. Run `make migrate-create name=add_source`. It creates `migrations/00002_add_source.sql` with both sections.
2. Write the change under `Up` and the statements that restore the previous state under `Down`. Keep one change per migration.
3. Run `make migrate-up`, `make migrate-down` and `make migrate-up` again to check that both directions work.

A migration that was applied to a shared database is never edited: a new migration corrects it.
