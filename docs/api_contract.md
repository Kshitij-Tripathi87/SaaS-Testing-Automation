# API Contract — `v1`

This is the **frozen** contract for the Workflo REST API. Anything in
`packages/core-schema/src/tenant_shield_schema/api.py` is the source of
truth; this document is the human-readable companion.

## Versioning

- **Backwards-compatible additions** (new optional fields): no version bump.
- **Anything else** (rename, removal, type change, new required field):
  bump the version and add a migration entry.

Current version: **`v1`** (matches `/v1/` URL prefix).

---

## Authentication

Every request must include an API key header:

```http
POST /v1/runs HTTP/1.1
X-API-Key: wfl_<32-hex-chars>
Content-Type: application/json
```

Missing or invalid → `401 Unauthorized`. The key is hashed (SHA-256) on
the server; the plaintext key is **never** stored or logged.

For the demo, a seeded key can be issued by `POST /v1/auth/demo-token`.
Real OAuth is on the roadmap but not in this version.

---

## Endpoints

### `POST /v1/runs`

Queue a new run. Returns the initial `RunStatus` (status: `queued`);
the actual execution happens in a background task.

**Request body** (`RunRequest`):

```json
{
  "repo_url": "https://github.com/example/my-saas-app.git",
  "probe_groups": ["test", "security"],
  "commit_sha": "a1b2c3d4e5f6",
  "config": {
    "timeout_seconds": 300,
    "memory_mb": 2048
  }
}
```

**With `web`** — `start_command` and `port` are **required** when
`"web"` is in `probe_groups`:

```json
{
  "repo_url": "https://github.com/example/my-saas-app.git",
  "probe_groups": ["web", "security"],
  "start_command": "python app.py",
  "port": 5000
}
```

**Validation failures** return `400 Bad Request` with a structured body:

```json
{
  "detail": "probe_groups includes 'web' but missing required fields: start_command, port. Either provide them on the request, or add them to a workflo.yaml in the target repo's root. Failing fast before container creation."
}
```

**Successful response** (`200 OK`, body is a `RunStatus`):

```json
{
  "run_id": "7f3a2b8c-1234-5678-9abc-def012345678",
  "status": "queued",
  "created_at": "2026-08-21T16:42:11.123456Z",
  "receipt": null,
  "error": null
}
```

### `GET /v1/runs/{run_id}`

Poll for the latest status of a run. Returns a `RunStatus`.

**When status == "completed"**:

```json
{
  "run_id": "7f3a2b8c-1234-5678-9abc-def012345678",
  "status": "completed",
  "created_at": "2026-08-21T16:42:11.123456Z",
  "receipt": {},
  "error": null
}
```

**When status == "failed"** (infrastructure crash, not test failure):

```json
{
  "run_id": "7f3a2b8c-1234-5678-9abc-def012345678",
  "status": "failed",
  "created_at": "2026-08-21T16:42:11.123456Z",
  "receipt": null,
  "error": "Ollama did not respond within 30s; receipt not produced."
}
```

### `POST /v1/auth/demo-token`

Demo-only. Returns a fixed, seeded API key for the demo account.

```json
{ "api_key": "wfl_abc123def456" }
```

---

## Field reference

### `RunRequest`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `repo_url` | string | yes | git URL (https, git@, ssh, file:// for dev) |
| `probe_groups` | list of strings | yes | at least one functional tier |
| `commit_sha` | string | no | pinned commit, ≤ 64 chars |
| `start_command` | string | when `web` in `probe_groups` | shell-free command for app under test |
| `port` | int | when `web` in `probe_groups` | 1..65535 |
| `config` | object | no | optional overrides (see below) |

**`probe_groups` vocabulary** (case-sensitive):

- `test` — surface tier: the repo's native pytest + smoke
- `deep-test` — deep tier: + LLM-generated probes (requires the `-deep` worker image)
- `aggressive-test` — deep + future chaos/fuzz layer
- `web` — Playwright-driven browser probes (requires the `-web` worker image)
- `security` — composable with any functional tier; adds tenant-isolation probes

**`config` recognized keys** (unknown keys are ignored, not rejected):

| Key | Type | Range | Default |
|-----|------|-------|---------|
| `timeout_seconds` | int | 10..3600 | 600 |
| `memory_mb` | int | 256..16384 | 2048 |
| `cpu_cores` | float | 0.5..8.0 | 2.0 |

### `RunStatus`

See endpoint examples above.

---

## CLI parity

`workflo run --via-api <base_url> ...` round-trips through this exact
contract. The CLI constructs a `RunRequest`, POSTs to `/v1/runs`, then
polls `GET /v1/runs/{run_id}`. Receipts produced via the API are
byte-identical (modulo timestamps/run IDs) to those produced by a local
CLI run against the same repo/commit.

---

## Known limitations (deferred)

- In-memory run store (`_runs` dict). Survives process restarts? No.
  TODO: swap to Postgres before production.
- No Redis-backed queue. Single-process execution only. Horizontal worker
  scaling requires a queue.
- No real OAuth. `POST /v1/auth/demo-token` returns a fixed seeded key.
- No pagination on `GET /v1/runs` (it's currently per-id only).
