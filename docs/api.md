# HTTP API

The service stores threats, each identified by the MD5 hash of the malicious file. The contract is the OpenAPI document [`api/openapi.yaml`](../api/openapi.yaml), also rendered by Swagger UI at http://localhost:8082 when the stack is running. This document describes the behavior of the implementation and gives examples.

All requests and responses use `application/json`. The examples assume the local stack and the token from `.env.example`:

```bash
BASE=http://localhost:8080
TOKEN=local-dev-token-1234
```

## Endpoints

| Method | Path | Purpose | Token |
|---|---|---|---|
| `POST` | `/info` | Create a threat | Required |
| `GET` | `/info/{md5}` | Read a threat | Not required |
| `PUT` | `/info/{md5}` | Replace the details of a threat | Required |

`{md5}` is 32 hexadecimal characters in any case. The service stores and returns it in lowercase, so `D41D…` and `d41d…` identify the same threat.

## The threat

| Field | Type | Create | Replace | Constraints |
|---|---|---|---|---|
| `md5` | string | required | not accepted | 32 hexadecimal characters; never changes |
| `name` | string | required | required | 1 to 255 characters; surrounding whitespace is trimmed |
| `severity` | string | required | required | `low`, `medium`, `high` or `critical` |
| `category` | string | required | required | `trojan`, `ransomware`, `worm`, `spyware`, `adware` or `other` |
| `description` | string | optional | optional | at most 2000 characters; omitted from the response when empty |
| `tags` | array of strings | optional | optional | at most 20 unique entries of 1 to 50 characters; lowercased, trimmed and deduplicated by the service |
| `created_at` | string | assigned by the server | unchanged | RFC 3339, UTC |
| `updated_at` | string | assigned by the server | assigned by the server | RFC 3339, UTC |

The request bodies accept only the fields above: an unknown field is rejected with `400`. Lengths are counted in characters, not bytes.

## Create a threat

`POST /info` stores a new threat. The hash must not exist yet.

```bash
curl -i -X POST $BASE/info \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic","severity":"high","category":"trojan","description":"Drops and runs additional modules","tags":["dropper","persistence"]}'
```

```
HTTP/1.1 201 Created
Content-Type: application/json
X-Request-Id: 01a174bd-4f5f-7d70-bd94-9ea85d704f27

{"category":"trojan","created_at":"2026-10-25T20:25:26.112704Z","description":"Drops and runs additional modules","md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic","severity":"high","tags":["dropper","persistence"],"updated_at":"2026-10-25T20:25:26.112704Z"}
```

| Status | Meaning |
|---|---|
| `201` | The threat was created |
| `400` | The body does not satisfy the schema |
| `401` | The token is missing or wrong |
| `409` | A threat with this hash already exists; the stored one is not changed |

## Read a threat

`GET /info/{md5}` returns the threat.

```bash
curl -i $BASE/info/d41d8cd98f00b204e9800998ecf8427e
```

The response has the shape shown above, with status `200`.

| Status | Meaning |
|---|---|
| `200` | The threat |
| `400` | The hash is malformed |
| `404` | No threat has this hash |

## Replace a threat

`PUT /info/{md5}` replaces the details of an existing threat. The request carries the complete new state: an optional field that is omitted is cleared. The hash and `created_at` do not change, and `updated_at` is set to the time of the request. The operation is atomic and never creates a threat.

```bash
curl -i -X PUT $BASE/info/d41d8cd98f00b204e9800998ecf8427e \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Trojan.Win32.Generic","severity":"critical","category":"trojan","tags":["dropper"]}'
```

```
HTTP/1.1 200 OK
Content-Type: application/json
X-Request-Id: 01a174bd-537f-7669-a1b2-cdcd0bc7c44e

{"category":"trojan","created_at":"2026-10-25T20:25:26.112704Z","md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic","severity":"critical","tags":["dropper"],"updated_at":"2026-10-25T20:25:27.167725Z"}
```

| Status | Meaning |
|---|---|
| `200` | The updated threat |
| `400` | The hash or the body does not satisfy the schema |
| `401` | The token is missing or wrong |
| `404` | No threat has this hash |

## Errors

Every error, including those produced before a request reaches a handler, has the same body:

```json
{"message": "Invalid request", "details": "parameter \"md5\" in path has an error: string doesn't match the regular expression \"^[a-fA-F0-9]{32}$\""}
```

`message` is a short, stable description. `details` appears for `400` only and gives a one-line reason. The cause of an unexpected failure is never returned: it is written to the log together with the request identifier.

| Status | Cause |
|---|---|
| `400` | Invalid path parameter, malformed JSON, unknown or missing field, value outside its constraints |
| `401` | Missing or wrong token; the response carries `WWW-Authenticate: Bearer` |
| `404` | Unknown threat or unknown route |
| `405` | Method not defined for the route |
| `409` | The hash already exists |
| `413` | The request body exceeds the limit |
| `415` | A `POST` or `PUT` whose `Content-Type` is not `application/json` |
| `429` | The client exceeded the rate limit; the response carries `Retry-After` in seconds |
| `500` | Unexpected failure |

A request is checked in this order: rate limit, body size, `Content-Type`, token, schema. An unauthorized client therefore always receives `401`, even for a malformed body.

## Protection and limits

| Mechanism | Behavior | Configuration |
|---|---|---|
| Bearer token | Required for `POST` and `PUT`; reads are open | `THREAT_INFO_API_TOKEN` |
| Rate limit | A token bucket per client address: 10 requests per second with a burst of 20 | `httpserver.rate_limit` |
| Body size | At most 65536 bytes | `httpserver.max_body_bytes` |
| Request identifier | A well-formed `X-Request-Id` of the client is returned unchanged; otherwise a UUIDv7 is generated. It appears in every response and in the log line of the request | none |

## Probes

The probes are served outside the API chain: they need no token and are not rate limited.

| Path | Meaning |
|---|---|
| `GET /healthz` | `200` while the process is alive |
| `GET /readyz` | `200` when the database responds, `503` otherwise |
