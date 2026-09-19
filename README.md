# semgate-example — Injection Range

An intentionally vulnerable-looking web service, built as a test target ("range")
for validating the [semgate](https://github.com/m-mizutani) HTTP guard
middleware. It runs standalone: with no guard in front, attack payloads "land"
and the service reports the exploit; once the guard is inserted as middleware,
those same requests should be blocked before reaching the handlers.

> **This service performs no real side effects.** There is no database, no shell
> execution, no filesystem access, and no outbound network requests. Each
> endpoint parses/evaluates the input inside a model of the vulnerable sink to
> decide whether an attack *would* fire, and, when it fires, returns synthetic
> (fabricated) data. All shown data is fake — no real credentials, secrets,
> hosts, or files. Do not deploy on a public network; for authorized security
> testing only.

## Endpoints

All API routes are grouped under `/api` (one subrouter — the seam where a guard
middleware is later inserted). Each returns the same JSON envelope; `exploited`
is the ground-truth verdict.

| Method / path | Input (≤ 1KB) | Vulnerability |
|---|---|---|
| `POST /api/login` | body `{username, password}` | SQL injection |
| `GET /api/ping` | query `host` | OS command injection |
| `GET /api/files` | query `path` | Path traversal |
| `GET /api/greet` | query `name` | Template injection (SSTI) |
| `GET /api/fetch` | query `url` | SSRF |
| `GET /api/track` | header `X-Log-Tag` | Log4Shell (JNDI lookup) |

Response envelope:

```json
{
  "endpoint": "ping",
  "exploited": true,
  "category": "command_injection",
  "rule_id": "cmd_extra_command",
  "detail": "parsed into 2 commands",
  "message": "OS command injection succeeded — an extra command ran on the host",
  "result": { "output": "..." }
}
```

Requests are always answered with `200` (the verdict is the `exploited` flag), so
that a later guard's `403` is a clear before/after difference. Oversized input
returns `413`; malformed input or a missing parameter returns `400`.

### Rate limit

Each client IP may send at most 15 `/api` requests per minute (configurable with
`--rate-limit`). Requests beyond that return `429` with a `Retry-After` header
(seconds until the current minute ends) and never reach the handler.

- Counting uses fixed one-minute windows aligned to the clock; every count
  resets when the next minute starts.
- The client IP is the TCP peer address. `X-Forwarded-For` is ignored, so behind
  a reverse proxy all clients share the proxy's IP.
- Counts are held in process memory: they reset on restart, and multiple
  instances each enforce their own limit.
- SPA static files are not counted.

### How the verdict is decided

Detection is not substring matching — each input is evaluated inside a model of
the sink:

- **SQLi**: the input is concatenated into a query and run against a hardened,
  read-only in-memory SQLite (pure Go, `modernc.org/sqlite`); it fires when the
  concatenated query returns rows a safe parameterized query would not, or breaks
  the SQL grammar. The database is read-only with `ATTACH` disabled, so running
  attacker SQL only ever reads the fake table.
- **Command injection**: the command line is parsed with a real shell parser
  (`mvdan.cc/sh`); it fires when more than the single intended command appears.
  Nothing is executed.
- **Path traversal**: the path is URL-decoded and resolved against a virtual web
  root; it fires when the result escapes the root. No real file is read.
- **SSTI**: the template expression is evaluated by a safe arithmetic evaluator;
  it fires when the expression is computed (e.g. `{{7*7}}` → `49`).
- **SSRF**: the URL is parsed and classified; it fires for forbidden schemes or
  internal/loopback/link-local/private targets. No request is sent.
- **Log4Shell**: the `${...}` lookup grammar is expanded (including obfuscation);
  it fires when it resolves to a `jndi:` lookup. No lookup is performed.

## Running

```sh
go run . serve --addr :8080
```

Flags (with matching environment variables):

| Flag | Default | Env |
|---|---|---|
| `--addr` | `:8080` | `SEMGATE_EXAMPLE_ADDR` |
| `--log-format` | `json` | `SEMGATE_EXAMPLE_LOG_FORMAT` (`json` \| `console`) |
| `--log-level` | `info` | `SEMGATE_EXAMPLE_LOG_LEVEL` (`debug`\|`info`\|`warn`\|`error`) |
| `--rate-limit` | `15` | `SEMGATE_EXAMPLE_RATE_LIMIT` (`/api` requests per client IP per minute; `0` disables) |

The frontend is embedded in the binary, so the single process serves both the API
and the SPA.

## Structured logging

Every request emits a structured `detection` log record (JSON by default) so you
can inspect which attack arrived: `endpoint`, `exploited`, `category`, `rule_id`,
`detail`, `payload_location`, the raw `input.*` values (bounded to 1KB),
`request_id`, `remote_addr`, and `user_agent`. Fired requests log at `WARN`,
benign ones at `INFO`. A separate `access` record carries method/path/status/
latency, correlated by `request_id`.

## Development

```sh
# backend
go test ./...

# frontend (in ./frontend)
pnpm install
pnpm build      # outputs to frontend/dist, embedded by the Go binary
pnpm test       # vitest unit/render tests
pnpm lint

# end-to-end (builds frontend + binary, starts server, runs Playwright)
./frontend/scripts/e2e.sh
```

## Inserting the guard

The `/api` subrouter in `pkg/controller/http/server.go` is the single seam: a
guard middleware is added there with `api.Use(...)`. The input-size bound (1KB)
is applied at this boundary, since a guard cannot inspect a large body
effectively. Building the guard itself is out of scope for this repository.
