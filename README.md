# runvault

`runvault` is a Rust launcher for encrypted environment payloads.

It keeps the profile metadata in plaintext, keeps the env payload encrypted on disk, decrypts only in memory, and launches a target command with the resolved environment.

The default folder model is:

```text
<profile-folder>/
  runvault.yaml
  env.sec
```

`runvault` commands can target the folder directly.

## Commands

```bash
runvault encrypt .env
runvault set deployments/ovh/services DATABASE_URL --value postgres://...
runvault import deployments/ovh/services .env.example --prefix PROD_
runvault set deployments/ovh/services TLS_KEY \
  --value \"secret-key\" \
  --to-file .runvault/tls/key.pem \
  --mode 0600 \
  --keep
runvault set deployments/ovh/services GOOGLE_APPLICATION_CREDENTIALS \
  --from-file ./gcp-service-account.json \
  --to-file .runvault/gcp-service-account.json \
  --mode 0600
runvault delete deployments/ovh/services GOOGLE_APPLICATION_CREDENTIALS
runvault reveal deployments/ovh/services DATABASE_URL
runvault reveal deployments/ovh/services GOOGLE_APPLICATION_CREDENTIALS --raw
runvault run deployments/ovh/services
runvault ping deployments/ovh/services
```

## Profile format

```yaml
name: glt-market-local
run:
  cmd: ["cargo", "run"]
  clear_env: true
  pass_env:
    - CARGO_HOME
    - RUSTUP_HOME
pings:
  - name: api
    url: http://127.0.0.1:8080/health
    timeout_seconds: 30
    interval_millis: 500
```

If `env_file` is omitted, it defaults to `env.sec` next to `runvault.yaml`.

If a command input path is a directory, `runvault` resolves:

- `runvault.yaml` as the profile file
- `env.sec` as the default encrypted payload path

Explicit profile file paths still work.

## Value modes

`runvault` supports two stored value types inside the encrypted payload:

- plain text values
- file-backed values

Plain text values are injected directly as environment variables.

File-backed values store the file bytes encrypted in the vault and, at runtime, materialize them to the configured `--to-file` path before the target command starts. The environment variable value is that configured file path.

Example:

```bash
runvault set deployments/ovh/services GOOGLE_APPLICATION_CREDENTIALS \
  --from-file ./gcp-service-account.json \
  --to-file .runvault/gcp-service-account.json \
  --mode 0600
```

At runtime, `runvault` will:
- write the encrypted file content to `<workdir>/.runvault/gcp-service-account.json`
- set `GOOGLE_APPLICATION_CREDENTIALS=.runvault/gcp-service-account.json`
- remove the file again after the child process exits

## Set semantics

`set` now separates:

- input source
  - `--value`
  - `--from-file`
- runtime materialization
  - plain env value
  - file via `--to-file`

Examples:

```bash
# value -> env
runvault set deployments/ovh/services API_KEY --value abc

# file -> env (source file must be valid UTF-8)
runvault set deployments/ovh/services TLS_CERT_PEM --from-file ./cert.pem

# value -> file
runvault set deployments/ovh/services TLS_KEY \
  --value \"secret-key\" \
  --to-file .runvault/tls/key.pem \
  --mode 0600 \
  --keep

# file -> file
runvault set deployments/ovh/services GOOGLE_APPLICATION_CREDENTIALS \
  --from-file ./gcp-service-account.json \
  --to-file .runvault/gcp-service-account.json \
  --mode 0600
```

Options for file materialization:

- `--to-file PATH`
- `--mode 0600`
- `--keep`

Defaults:

- mode defaults to `0600`
- cleanup defaults to `on_exit`
- `--keep` changes cleanup to `keep`

## Importing an existing env file

You can bulk-load an existing dotenv-style file into the encrypted vault:

```bash
runvault import deployments/ovh/services .env.example
```

You can also add a prefix to every imported key before it is stored:

```bash
runvault import deployments/ovh/services .env.example --prefix PROD_
```

Behavior:

- dotenv content is parsed with the same parser used for legacy env payloads
- imported keys overwrite existing plain-text values with the same final key
- file-backed values are not created by `import`; it is plain env text import only
- the prefix is applied before key validation

## Revealing a stored value

You can inspect a stored key with:

```bash
runvault reveal deployments/ovh/services DATABASE_URL
```

Behavior:

- plain-text values print directly to stdout
- file-backed values show metadata by default:
  - key
  - target path
  - size
  - mode
  - cleanup policy

To print file-backed content directly:

```bash
runvault reveal deployments/ovh/services GOOGLE_APPLICATION_CREDENTIALS --raw
```

To write any revealed value to a file:

```bash
runvault reveal deployments/ovh/services GOOGLE_APPLICATION_CREDENTIALS --output /tmp/gcp.json
```

## Notes

- the profile stays plaintext
- the env payload is expected to be age passphrase-encrypted
- the default encrypted payload file name is `env.sec`
- plaintext env files are only used as `encrypt` input
- `runvault` never writes decrypted plain text values back to disk
- file-backed values are written only for the child runtime, then cleaned up
- when `clear_env` is true, `runvault` keeps a small default passthrough set like `PATH`, `HOME`, `USER`, `SHELL`, and `TMPDIR`
