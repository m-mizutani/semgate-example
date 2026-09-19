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
> hosts, or files. For security testing only.

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

The Cloud Run service is defined in `terraform/` and deployed with
[Task](https://taskfile.dev) and [zenv](https://github.com/m-mizutani/zenv):

```sh
task deploy
```

`task deploy` runs, in order:

1. enable the Run, Cloud Build, and Artifact Registry APIs
2. create the Terraform state bucket and the Artifact Registry repository if
   they do not exist yet (Terraform cannot create the bucket holding its own
   state, so this step is not part of the Terraform configuration)
3. `terraform init` against the GCS backend
4. `gcloud builds submit --tag`, which builds `Dockerfile` and pushes the image
   tagged with the current commit and a timestamp
5. `terraform apply` with that image, printing the plan for confirmation

`task plan` shows the plan for the image currently recorded in the state, and
`task destroy` removes the service. The public URL is the `service_url` output.

### Environment variables

zenv reads `.env.yaml` (or `.env`) from the repository root; both are
gitignored. `TF_VAR_`-prefixed names are read by Terraform as input variables.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `TF_VAR_project` | yes | — | Google Cloud project ID to deploy into |
| `TF_STATE_BUCKET` | yes | — | GCS bucket holding the Terraform state |
| `TF_VAR_region` | no | `asia-northeast1` | Cloud Run region |
| `TF_VAR_service_name` | no | `semgate-example` | Cloud Run service name |

```yaml
# .env.yaml
TF_VAR_project: my-project
TF_STATE_BUCKET: my-project-tfstate
```

The state bucket is created with uniform bucket-level access, public access
prevention, and object versioning, so a broken state can be rolled back to an
earlier generation. Sharing the deployment across machines needs nothing but
`gcloud auth application-default login` on each of them.

### What the Terraform configuration sets

- scale to zero with at most one instance for the whole service (the
  service-level `scaling` block; the `scaling` block inside `template` would
  cap each revision, letting a rollout run two at once)
- the smallest resources Cloud Run accepts: `cpu = "0.08"`, `memory = "128Mi"`.
  A CPU below 1 requires `max_instance_request_concurrency = 1`, per-request
  CPU allocation (`cpu_idle = true`), and `EXECUTION_ENVIRONMENT_GEN1`, which
  is also required for memory below 512Mi
- public access: `allUsers` is granted `roles/run.invoker`, so anyone on the
  internet can reach the `run.app` URL without authentication

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
`roles/serviceusage.serviceUsageAdmin` to enable the APIs, and
`roles/iam.serviceAccountUser` on the Cloud Run service identity and the build
service account. An organization policy that forbids `allUsers` bindings makes
`terraform apply` fail at `google_cloud_run_v2_service_iam_member`.

## Inserting the guard

The `/api` subrouter in `pkg/controller/http/server.go` is the single seam: a
guard middleware is added there with `api.Use(...)`. The input-size bound (1KB)
is applied at this boundary, since a guard cannot inspect a large body
effectively. Building the guard itself is out of scope for this repository.
