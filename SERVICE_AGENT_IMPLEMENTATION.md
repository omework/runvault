# runvault Service/Agent Implementation Plan

## Goal

Upgrade `runvault` from a CLI-only encrypted launcher into a long-running service that can:

- manage encrypted secrets and file-backed values through an API
- launch and supervise profiles on demand
- expose process state, health state, and execution history
- support local operator usage first, with a clean path to stronger multi-user controls later

This document defines the full target implementation, the recommended architecture, phased delivery, and the non-goals for the first version.

## Why This Exists

The current `runvault` is good at one-shot execution:

- load encrypted values
- decrypt only in memory
- materialize file-backed values at runtime
- run a process
- clean up runtime files

What it does not provide yet:

- long-running daemon mode
- stable programmatic API
- process supervision
- concurrent profile management
- execution history
- audit trail
- remote or local operator access control

The service/agent upgrade should preserve the current security model while making the tool operationally usable.

## Product Shape

`runvault` should become two things built from the same core:

1. `runvault` CLI
   - keeps the existing commands
   - can talk directly to the local store for simple offline work
   - can also talk to the local daemon when appropriate

2. `runvaultd` service
   - long-running background process
   - owns profile execution and supervision
   - exposes API for secret management and runtime control

The daemon should remain the source of truth for runtime state. The CLI becomes a client where that makes sense.

## Design Principles

- decrypted content must remain in memory except for explicit runtime file materialization
- runtime files must be ephemeral and cleaned deterministically
- existing encrypted payloads must remain readable
- agent behavior must be explicit, not magical
- local-first operation comes before multi-node complexity
- launch state and secret state must be separated

## Functional Scope

### Secrets

The service must support:

- set plain text value
- set file-backed value from file content with declared runtime path
- delete value
- list keys without exposing plaintext
- inspect metadata for a key
  - type
  - runtime file path when relevant
  - size
  - updated time

The service should not return plaintext secret values by default.

Optional future behavior:

- one-time reveal for local operator use
- import/export workflows
- secret version history

### Profiles

The service must support:

- register profile file path
- inspect resolved profile metadata
- run profile once
- start profile as managed process
- stop managed process
- restart managed process
- ping profile without launching
- view last launch result

### Runtime Supervision

The agent must support:

- track running/stopped/failed state
- restart policy
  - never
  - on-failure
  - always
- health wait using existing ping targets
- startup timeout
- graceful stop timeout
- kill fallback when graceful stop exceeds timeout

### Observability

The service must expose:

- current process state
- last exit code
- last failure reason
- last start time
- last stop time
- recent logs
- recent operations

### Access

Initial model:

- local service only
- authenticated local operator token or local socket permissions

Later model:

- optional HTTP bind
- auth tokens with roles
- audit trail

## Recommended Architecture

## 1. Core Library

Extract the business logic into reusable modules:

- `vault`
  - load/save encrypted store
  - legacy env compatibility
  - file-backed secret representation
- `profile`
  - parse and validate profile
- `runtime`
  - materialize files
  - spawn process
  - cleanup logic
- `supervisor`
  - managed lifecycle
  - state machine
- `api_types`
  - request/response structs

The current code already partially supports this split. The service layer should reuse the same primitives as the CLI.

## 2. Daemon

Introduce a new binary:

- `src/bin/runvaultd.rs`

Responsibilities:

- load daemon config
- own in-memory runtime state
- own process supervisors
- expose API server
- persist non-secret metadata where needed

The daemon should not rewrite secrets except through explicit API calls.

## 3. IPC/API Transport

Phase 1 recommendation:

- HTTP on `127.0.0.1`

Why:

- easiest to inspect and script
- easiest to test
- no platform-specific IPC complexity

Alternative:

- Unix domain socket on Unix systems

That is stronger by default but slower to build and slightly harder to use from tooling. It can come later.

## 4. Persistent State

Keep two classes of state:

### Secret state

Already exists:

- encrypted vault payload per profile

Keep it as file-backed encrypted state.

### Runtime/control state

Introduce a daemon state file or lightweight local database for:

- registered profiles
- desired state
- restart policy
- execution history
- audit log

Recommended first implementation:

- JSON or YAML file for daemon metadata

Recommended durable version:

- SQLite

SQLite becomes preferable once you add:

- audit trail
- log indexing
- process history
- token auth
- concurrent requests

## Data Model

### Managed Profile

Fields:

- `id`
- `profile_path`
- `display_name`
- `workdir`
- `desired_state`
  - `stopped`
  - `running`
- `actual_state`
  - `stopped`
  - `starting`
  - `running`
  - `stopping`
  - `failed`
- `restart_policy`
- `last_start_at`
- `last_stop_at`
- `last_exit_code`
- `last_error`

### Secret Metadata

Fields:

- `key`
- `kind`
  - `plain_text`
  - `file_content`
- `runtime_path`
- `size_bytes`
- `updated_at`

### Access Token

If auth is introduced:

- `id`
- `name`
- `token_hash`
- `role`
- `created_at`
- `expires_at`
- `disabled_at`

### Audit Event

- `id`
- `actor`
- `action`
- `target_type`
- `target_id`
- `created_at`
- `metadata_json`

## API Surface

Suggested first API:

### Health

- `GET /api/health`

### Profiles

- `GET /api/profiles`
- `POST /api/profiles/register`
- `GET /api/profiles/{id}`
- `POST /api/profiles/{id}/run-once`
- `POST /api/profiles/{id}/start`
- `POST /api/profiles/{id}/stop`
- `POST /api/profiles/{id}/restart`
- `POST /api/profiles/{id}/ping`

### Secrets

- `GET /api/profiles/{id}/secrets`
- `POST /api/profiles/{id}/secrets/set`
- `POST /api/profiles/{id}/secrets/delete`

Suggested set request body:

```json
{
  "key": "GOOGLE_APPLICATION_CREDENTIALS",
  "kind": "file_content",
  "value": {
    "source_file_path": "/tmp/gcp.json",
    "runtime_file_path": ".runvault/gcp.json"
  }
}
```

or:

```json
{
  "key": "DATABASE_URL",
  "kind": "plain_text",
  "value": "postgres://..."
}
```

### Runtime State

- `GET /api/processes`
- `GET /api/processes/{id}`
- `GET /api/processes/{id}/logs`

### Audit

- `GET /api/audit`

## Runtime File Materialization Rules

This part is security-sensitive and should stay strict.

Rules:

- file-backed values are written only during active process execution
- paths are relative to profile `workdir` unless explicitly absolute
- default mode on Unix should be `0600`
- existing files should not be overwritten silently
- cleanup must run on:
  - normal process exit
  - startup failure
  - stop request
  - daemon shutdown best-effort

Future option:

- allow an overwrite policy only when explicitly declared

For now, fail fast if the target runtime path already exists.

## Process Lifecycle Model

State machine:

- `stopped`
- `starting`
- `running`
- `stopping`
- `failed`

Transitions:

- `run-once`
  - `stopped -> starting -> running -> stopped|failed`
- `start`
  - `stopped -> starting -> running|failed`
- `stop`
  - `running -> stopping -> stopped`
- `restart`
  - `running -> stopping -> starting -> running|failed`

Health behavior:

- if `pings` exist, `starting` stays active until ping success or timeout
- if process exits before ping success, mark as `failed`
- restart policy is evaluated only after a definitive failure or exit

## Authentication and Authorization

Minimum local service:

- bind only to `127.0.0.1`
- no auth or optional single local admin token

Recommended secure local version:

- bootstrap admin token in config file
- CLI reads token from local config

Future multi-user version:

- admin login
- hashed access tokens
- roles:
  - `admin`
  - `operator`
  - `read_only`

Suggested role behavior:

- `admin`
  - full secret management
  - token management
  - profile registration
  - runtime control
- `operator`
  - runtime control
  - log inspection
  - secret metadata read
- `read_only`
  - health
  - profile state
  - logs

## Logging

Need two outputs:

1. daemon logs
   - service internal behavior
2. managed process logs
   - stdout/stderr of child processes

Initial recommendation:

- daemon logs to stdout
- per-process ring buffer in memory
- optional file sink later

Later:

- persisted process logs in SQLite or rotating files

## CLI Evolution

Existing commands should remain:

- `encrypt`
- `set`
- `delete`
- `run`
- `ping`

Add service-aware commands later:

- `daemon`
- `profile register`
- `profile list`
- `start`
- `stop`
- `restart`
- `logs`
- `status`

Important:

- keep direct file mode available for local/dev simplicity
- do not force daemon mode for every use case

## Backward Compatibility

Must preserve:

- existing profile format
- existing encrypted env payloads
- current one-shot `run` flow

Compatibility rules:

- old encrypted dotenv payloads load as plain-text-only vaults
- once rewritten by service-aware tooling, payloads may migrate to structured vault format
- migration should remain transparent to the user

## Suggested Delivery Plan

### Phase 1: Daemon Skeleton

Target: 1 day

- add `runvaultd`
- add health endpoint
- add daemon config
- add in-memory profile registry
- add API server shell

### Phase 2: Secret API

Target: 1 day

- add set/delete/list secret endpoints
- reuse current vault model
- support plain text and file-backed values
- add API tests

### Phase 3: Managed Runs

Target: 1 to 2 days

- start/stop/restart/run-once
- process state machine
- ping-based startup state
- cleanup guarantees
- execution history

### Phase 4: Logs and Observability

Target: 1 day

- in-memory process logs
- status endpoints
- recent event history

### Phase 5: Auth and Persistence Hardening

Target: 1 to 2 days

- admin token
- optional roles
- audit events
- move runtime metadata to SQLite if needed

## Testing Plan

### Unit Tests

- vault parse/save
- legacy payload compatibility
- file-backed materialization
- cleanup behavior
- state transitions
- restart policy decisions

### Integration Tests

- API set/delete
- API start/stop/restart
- run-once behavior
- ping timeout behavior
- file-backed runtime value visibility
- cleanup on failure

### Fault Injection

- wrong password
- invalid profile
- existing runtime file path
- child exits early
- ping never succeeds
- daemon restart with stale metadata

## Non-Goals for First Version

Do not include initially:

- cluster/distributed coordination
- remote internet-exposed service
- multi-node locking
- UI
- secret replication
- KMS integration
- hot secret reload inside child processes

Those can come later if the service proves useful.

## Open Questions

- should daemon-managed secrets remain profile-local files, or move to a daemon-wide store later?
- should runtime file paths be allowed outside the workdir?
- should overwrite of existing runtime files ever be allowed?
- do we need scheduled runs, or only on-demand and supervised long-running runs?
- is local HTTP enough, or should Unix socket be the default from the start?
- should logs be memory-only in v1, or persisted immediately?

## Recommendation

Build this in two layers:

1. a clean daemon with local HTTP API and in-memory supervisors
2. keep current CLI workflows intact and let them gradually adopt daemon-backed operations

Do not overbuild the first version. The service becomes useful as soon as it can:

- manage encrypted values
- launch and supervise profiles
- report state reliably
- clean up runtime files correctly

That is the minimum viable service/agent boundary worth shipping.
