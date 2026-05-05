# runvault

`runvault` is a Rust launcher for encrypted environment payloads.

It keeps the profile metadata in plaintext, keeps the env payload encrypted on disk, decrypts only in memory, and launches a target command with the resolved environment.

## Commands

```bash
runvault encrypt .env .env.enc
runvault set profiles/glt.market.local.yaml DATABASE_URL --value postgres://...
runvault set profiles/glt.market.local.yaml GOOGLE_APPLICATION_CREDENTIALS \
  --from-file ./gcp-service-account.json \
  --value-path .runvault/gcp-service-account.json
runvault delete profiles/glt.market.local.yaml GOOGLE_APPLICATION_CREDENTIALS
runvault run profiles/glt.market.local.yaml
runvault ping profiles/glt.market.local.yaml
```

## Profile format

```yaml
name: glt-market-local
env_file: ../secrets/glt.market.env.enc
workdir: /Users/jabarkarim/sources/glt.market
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

## Value modes

`runvault` supports two stored value types inside the encrypted payload:

- plain text values
- file-backed values

Plain text values are injected directly as environment variables.

File-backed values store the file bytes encrypted in the vault and, at runtime, materialize them to the configured `--value-path` before the target command starts. The environment variable value is that configured file path.

Example:

```bash
runvault set profiles/glt.market.local.yaml GOOGLE_APPLICATION_CREDENTIALS \
  --from-file ./gcp-service-account.json \
  --value-path .runvault/gcp-service-account.json
```

At runtime, `runvault` will:
- write the encrypted file content to `<workdir>/.runvault/gcp-service-account.json`
- set `GOOGLE_APPLICATION_CREDENTIALS=.runvault/gcp-service-account.json`
- remove the file again after the child process exits

## Notes

- the profile stays plaintext
- the env payload is expected to be age passphrase-encrypted
- plaintext env files are only used as `encrypt` input
- `runvault` never writes decrypted plain text values back to disk
- file-backed values are written only for the child runtime, then cleaned up
- when `clear_env` is true, `runvault` keeps a small default passthrough set like `PATH`, `HOME`, `USER`, `SHELL`, and `TMPDIR`
