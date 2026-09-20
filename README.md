# semgate-example — Injection Range

An intentionally vulnerable-looking web service, built as a test target ("range")
for validating the [semgate](https://github.com/m-mizutani/semgate) HTTP guard
middleware. It runs both ways from the same binary: without a TypeSafe (Jev) API
key, attack payloads "land" and the service reports the exploit; with a key, the
semgate guard evaluates each `/api` request and answers `403` before the payload
reaches its handler.

> **This service performs no real side effects.** There is no database, no shell
> execution, and no filesystem access. Each endpoint parses/evaluates the input
> inside a model of the vulnerable sink to decide whether an attack *would*
> fire, and, when it fires, returns synthetic (fabricated) data. All shown data
> is fake — no real credentials, secrets, hosts, or files. For security testing
> only.
>
> The handlers make no outbound requests. The **guard** does: when it is
> enabled, each `/api` request's method, path, query, headers (minus the
> credential ones), and body up to 1KB are sent to the TypeSafe API for
> evaluation. See *The semgate guard* below.

## Endpoints

All API routes are grouped under `/api` (one subrouter — the seam where the
guard middleware is inserted). Each returns the same JSON envelope; `exploited`
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

A request that reaches its handler is always answered with `200` (the verdict is
the `exploited` flag), so the guard's `403` is a clear before/after difference.
Oversized input returns `413`; malformed input or a missing parameter returns
`400`; a request the guard stopped returns `403`.

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
- The number of IP entries kept for the current minute is not capped, so memory
  grows with the number of distinct client IPs seen within that minute. A client
  that can send from many source addresses (for example many addresses in one
  IPv6 /64) can grow that map without being rate limited. This is accepted for a
  range that is not meant to be deployed on a public network.

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

## The semgate guard

`pkg/controller/http/guard.go` builds the [semgate](https://github.com/m-mizutani/semgate)
middleware installed on the `/api` subrouter, before every handler. The whole
guard is one function, `NewGuard`, written out in one piece so that its body
reads as a worked example of using semgate: the provider options, the question,
and the decision made from the answer.

It asks [TypeSafe](https://docs.typesafe.ai/) Jev a single Noul (yes/no)
question per request — *does this request carry an attack payload?* — and
compares the returned probability with `--guard-threshold`. At or above the
threshold the request is answered `403` and the handler never runs.

The question text is the interesting part. It names the techniques to look for
(quote breakouts and `UNION SELECT`, shell separators and `$(...)`, `../`
sequences, `{{7*7}}`-style template expressions, loopback and metadata
addresses, `${jndi:...}` lookups, `<script>` and `javascript:`, CR/LF in a
header value) and then tells the model to judge the *decoded* meaning, because
payloads arrive percent-encoded, double-encoded, as HTML entities or Unicode
escapes, base64-ed, case-mangled (`SeLeCt`, `JnDi`), split by inline comments
(`UNION/**/SELECT`), or truncated with a null byte. It also says what is *not*
an attack, so an apostrophe in `O'Brien` does not block a login.

```json
{
  "blocked": true,
  "probability": 0.97,
  "message": "semgate blocked this request before it reached the vulnerable handler"
}
```

The guard runs only when a TypeSafe API key is configured; with no key the range
behaves exactly as it did before, and every payload lands. Two log records make
the decision auditable: `guard_blocked` (WARN) and `guard_allowed` (INFO), both
carrying the probability and the path.

The `Authorization`, `Proxy-Authorization`, and `Cookie` headers are excluded
from what is sent to the TypeSafe API (`semgate.WithHeaderDenylist`). Everything
else — the path, the query, the remaining headers, and the body up to 1KB — is
sent, because that is where the range's payloads travel and a guard that cannot
see them cannot be tested.

A body above 1KB is refused by the guard itself with `413`, and is never
evaluated: `http.MaxBytesReader` stops a body mid-read rather than refusing the
request up front, so bounding the body *before* the guard would have sent the
first kilobyte of a refused request to the TypeSafe API. Query values and the
`X-Log-Tag` header are still bounded before the guard (`boundInputs`), where
cutting them short is not a concern.

**Failures close the gate.** If the API call fails or returns an answer that
cannot be decoded, the request is answered `503` with
`{"error": "..."}` and is *not* forwarded: an unevaluated request must not reach
a handler the guard is supposed to protect. The failure is logged as
`guard_evaluation_failed` (ERROR).

## Running

```sh
go run . serve --addr :8080                       # unguarded
TYPESAFE_API_KEY=... go run . serve --addr :8080  # guarded
```

Flags (with matching environment variables):

| Flag | Default | Env |
|---|---|---|
| `--addr` | `:8080` | `SEMGATE_EXAMPLE_ADDR` |
| `--log-format` | `json` | `SEMGATE_EXAMPLE_LOG_FORMAT` (`json` \| `console`) |
| `--log-level` | `info` | `SEMGATE_EXAMPLE_LOG_LEVEL` (`debug`\|`info`\|`warn`\|`error`) |
| `--rate-limit` | `15` | `SEMGATE_EXAMPLE_RATE_LIMIT` (`/api` requests per client IP per minute; `0` disables) |
| `--typesafe-api-key` | — | `TYPESAFE_API_KEY` (the guard runs only when this is set; the name follows the semgate examples rather than the `SEMGATE_EXAMPLE_` prefix) |
| `--guard-threshold` | `0.8` | `SEMGATE_EXAMPLE_GUARD_THRESHOLD` (attack probability at which a request is blocked; `0 < t <= 1`) |

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

## Container image

`Dockerfile` builds the frontend, embeds it into a static Go binary, and runs it
on a distroless base image listening on `:8080`.

```sh
docker build -t semgate-example .
docker run --rm -p 8080:8080 semgate-example
```

## Deploying to Cloud Run

Two Cloud Run services are defined in `terraform/`, running the same image with
the same resources and both open to `allUsers`:

| Service | Identity | `TYPESAFE_API_KEY` | Behavior |
|---|---|---|---|
| `${service}` | `${service}@…` | from Secret Manager | guarded once the key is wired in |
| `${service}-noguard` | `${service}-noguard@…` | never set | every payload lands |

The no-guard service is not merely configured without the key: it runs as its
own service account, which is not granted `roles/secretmanager.secretAccessor`
on the secret, so it cannot read the key at all. The pair is the before/after
comparison the guard is measured against.

They are deployed with [Task](https://taskfile.dev) and
[zenv](https://github.com/m-mizutani/zenv):

```sh
task deploy
```

`task deploy` runs, in order:

1. enable the Run, Cloud Build, Artifact Registry, and Secret Manager APIs
2. create the Terraform state bucket and the Artifact Registry repository if
   they do not exist yet (Terraform cannot create the bucket holding its own
   state, so this step is not part of the Terraform configuration)
3. `terraform init` against the GCS backend
4. `gcloud builds submit --tag`, which builds `Dockerfile` and pushes the image
   tagged with the current commit and a timestamp
5. `terraform apply` with that image, printing the plan for confirmation

`task plan` shows the plan for the image currently recorded in the state, and
`task destroy` removes both services. The public URLs are the `service_url` and
`noguard_service_url` outputs.

### Storing the TypeSafe API key

Terraform creates the Secret Manager secret but never a secret version, so the
API key never enters the Terraform state (which lives in a GCS bucket). Enabling
the guard therefore takes two deployments:

```sh
# 1. First deploy. SEMGATE_EXAMPLE_KEY_VERSION is unset, so the guarded service
#    is deployed without TYPESAFE_API_KEY and runs unguarded. This also creates
#    the secret and the IAM binding.
task deploy

# 2. Store the key in the secret Terraform created.
printf '%s' "$YOUR_TYPESAFE_API_KEY" | \
  gcloud secrets versions add "$(terraform -chdir=terraform output -raw typesafe_api_key_secret)" \
    --project "$SEMGATE_EXAMPLE_PROJECT" --data-file=-

# 3. Set SEMGATE_EXAMPLE_KEY_VERSION=latest in .env.yaml and deploy again. The
#    service now receives TYPESAFE_API_KEY and the guard runs.
task deploy
```

The `guard_enabled` output reports whether the deployed configuration wires the
key in. Rotating the key means adding a new secret version and redeploying (or
restarting the service): `latest` is resolved when an instance starts, not on
every request.

### Environment variables

zenv reads `.env.yaml` (or `.env`) from the repository root; both are
gitignored. The names share the `SEMGATE_EXAMPLE_` prefix the server itself
uses, and `Taskfile.yml` passes them to Terraform as input variables.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `SEMGATE_EXAMPLE_PROJECT` | yes | — | Google Cloud project ID to deploy into |
| `SEMGATE_EXAMPLE_STATE_BUCKET` | yes | — | GCS bucket holding the Terraform state |
| `SEMGATE_EXAMPLE_REGION` | no | `asia-northeast1` | Cloud Run region |
| `SEMGATE_EXAMPLE_SERVICE` | no | `semgate-example` | Cloud Run service name (the unguarded one appends `-noguard`) |
| `SEMGATE_EXAMPLE_KEY_VERSION` | no | unset | Secret Manager version of the TypeSafe API key the guarded service reads (`latest` or a number). While unset, the guarded service is deployed without the key |

The API key itself is never one of these: it goes into Secret Manager directly
(see *Storing the TypeSafe API key* above).

```yaml
# .env.yaml
SEMGATE_EXAMPLE_PROJECT: my-project
SEMGATE_EXAMPLE_STATE_BUCKET: my-project-tfstate
SEMGATE_EXAMPLE_KEY_VERSION: latest
```

The state bucket is created with uniform bucket-level access, public access
prevention, and object versioning, so a broken state can be rolled back to an
earlier generation. Sharing the deployment across machines needs nothing but
`gcloud auth application-default login` on each of them.

### What the Terraform configuration sets

For each of the two services:

- scale to zero with at most one instance for the whole service (the
  service-level `scaling` block; the `scaling` block inside `template` would
  cap each revision, letting a rollout run two at once)
- the smallest resources Cloud Run accepts: `cpu = "0.08"`, `memory = "128Mi"`.
  A CPU below 1 requires `max_instance_request_concurrency = 1`, per-request
  CPU allocation (`cpu_idle = true`), and `EXECUTION_ENVIRONMENT_GEN1`, which
  is also required for memory below 512Mi
- public access: `allUsers` is granted `roles/run.invoker`, so anyone on the
  internet can reach the `run.app` URL without authentication
- a dedicated service account, so neither range runs as the Compute Engine
  default account

and, for the guarded service only:

- a Secret Manager secret holding the TypeSafe API key, with
  `roles/secretmanager.secretAccessor` granted on it to that service's account
- `TYPESAFE_API_KEY` sourced from that secret, present only while
  `typesafe_api_key_version` is set

### One-time project setup

```sh
PROJECT=my-project
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"

# Cloud Build runs as the Compute Engine default service account.
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role roles/artifactregistry.writer
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role roles/logging.logWriter
```

The account running `task deploy` needs, on the project: `roles/run.admin`
(creating the service and granting `allUsers` the invoker role requires
`run.services.setIamPolicy`), `roles/cloudbuild.builds.editor`,
`roles/artifactregistry.admin`, `roles/storage.admin` for the state bucket,
`roles/serviceusage.serviceUsageAdmin` to enable the APIs,
`roles/iam.serviceAccountAdmin` to create the two range service accounts,
`roles/secretmanager.admin` to create the secret, grant access on it, and add
key versions, and `roles/iam.serviceAccountUser` on the Cloud Run service
identities and the build service account. An organization policy that forbids
`allUsers` bindings makes `terraform apply` fail at
`google_cloud_run_v2_service_iam_member`.
