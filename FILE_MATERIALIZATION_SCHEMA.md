# Runvault File Materialization Schema

This note defines the next profile and vault shape for file-backed runtime materials such as:

- TLS certificates
- TLS private keys
- JSON credentials
- SSH keys
- mounted config fragments

The current `runvault set --from-file ... --value-path ...` flow works for one-off files, but it is too low-level for deployment profiles that need stable file identities, explicit permissions, and deterministic dump paths.

## Goal

Keep plaintext env values simple, but make runtime files first-class.

That means:

- files are declared in the profile
- file content stays encrypted in the vault
- the profile controls where files are dumped
- the profile controls file mode
- optional env vars can point to the materialized path

## Proposed profile schema

```yaml
name: ovh-services
env_file: .env.enc

run:
  cmd: ["docker", "compose", "up", "-d"]
  clear_env: true

files:
  - id: root_ca
    target_path: .runvault/pki/root.chain.pem
    mode: "0644"
    required: true
    cleanup: keep
    env:
      - PKI_ROOT_CA_FILE

  - id: glt_market_cert
    target_path: .runvault/pki/glt.market.crt.pem
    mode: "0644"
    required: true
    cleanup: keep
    env:
      - GLT_MARKET_CERT_FILE

  - id: glt_market_key
    target_path: .runvault/pki/glt.market.key.pem
    mode: "0600"
    required: true
    cleanup: keep
    env:
      - GLT_MARKET_KEY_FILE
```

## Fields

### `id`

Stable vault identity for the file payload.

This is the lookup key in the encrypted vault.

It should not depend on a runtime env var name.

### `target_path`

Relative or absolute runtime dump location.

Rules:

- relative paths resolve from the profile workdir
- parent directories are created if needed
- path collisions are rejected unless explicitly overwritten by a future force flag

### `mode`

Unix file mode applied after materialization.

Examples:

- `0644` for public certs
- `0600` for private keys

If omitted, default should be:

- `0600` for file materials

That default is safer than `0644`.

### `required`

Whether missing vault content for this file should fail the run.

Defaults:

- `true`

### `cleanup`

Controls whether the dumped file is removed after the child process exits.

Values:

- `on_exit`
- `keep`

Recommended defaults:

- app runtime secrets: `on_exit`
- deployment materials mounted by Docker Compose: `keep`

For deployment use, `keep` is usually necessary because Compose starts containers and returns immediately, while the files still need to exist on disk after `runvault` exits.

### `env`

Optional env vars that should receive the materialized path string.

Example:

```yaml
env:
  - GLT_MARKET_KEY_FILE
```

That would export:

```bash
GLT_MARKET_KEY_FILE=.runvault/pki/glt.market.key.pem
```

## Vault model

Today, file-backed values are attached to env keys.

That should change.

Proposed encrypted vault entry model:

```json
{
  "env": {
    "POSTGRES_DSN": {
      "kind": "text",
      "value": "host=..."
    }
  },
  "files": {
    "root_ca": {
      "kind": "file",
      "content_b64": "..."
    },
    "glt_market_key": {
      "kind": "file",
      "content_b64": "..."
    }
  }
}
```

This separates:

- text env entries
- file materials

That separation is important because files have different runtime rules.

## CLI changes

## Set file content

Current:

```bash
runvault set profile.yaml GOOGLE_APPLICATION_CREDENTIALS \
  --from-file ./service-account.json \
  --value-path .runvault/service-account.json
```

Proposed first-class file command:

```bash
runvault file set profile.yaml root_ca --from-file ./root.chain.pem
runvault file set profile.yaml glt_market_key --from-file ./glt.market.key.pem
runvault file delete profile.yaml glt_market_key
```

This keeps file storage aligned with profile `files[].id`.

## Optional compatibility path

For migration, `runvault set --from-file ... --value-path ...` can remain supported for old profiles, but new file materialization should prefer:

- `files:` in profile
- `runvault file set`

## Runtime behavior

At `runvault run profile.yaml`:

1. load and decrypt vault
2. resolve env text values
3. resolve declared `files`
4. materialize each file to `target_path`
5. apply file mode
6. export any configured `env` path variables
7. start child process
8. on exit:
   - remove files marked `on_exit`
   - keep files marked `keep`

## Docker deployment implications

This schema works well with Compose mounts.

Example:

```yaml
volumes:
  - ./.runvault/pki/root.chain.pem:/tls/root.chain.pem:ro
  - ./.runvault/pki/glt.market.crt.pem:/tls/glt.market.crt.pem:ro
  - ./.runvault/pki/glt.market.key.pem:/tls/glt.market.key.pem:ro
```

Important consequence:

For Compose-driven deployments, the certificate files usually need `cleanup: keep`, otherwise they disappear as soon as `runvault` exits.

## Validation rules

Profile validation should enforce:

- unique `files[].id`
- unique `files[].target_path`
- valid octal `mode`
- valid `cleanup` enum
- `env` names must be unique within one file entry

Runtime validation should enforce:

- all `required` file ids exist in the vault
- target parent directories are writable
- file mode application succeeds

## Migration plan

1. add `files` support to profile parsing
2. add `files` section to encrypted vault model
3. add `runvault file set/delete`
4. keep old file-backed env entries supported temporarily
5. migrate deployment profiles to the new schema
6. later deprecate env-key-coupled file storage

## Recommended first deployment use

Use this first for:

- root CA
- service certificate
- service private key

That is the cleanest validation case because the file semantics are clear and the runtime paths are deterministic.
