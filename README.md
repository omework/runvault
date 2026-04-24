# runvault

`runvault` is a Rust launcher for encrypted environment payloads.

It keeps the profile metadata in plaintext, keeps the env payload encrypted on disk, decrypts only in memory, and launches a target command with the resolved environment.

## Commands

```bash
runvault encrypt --input .env --output .env.enc
runvault run --profile profiles/glt.market.local.yaml
runvault ping --profile profiles/glt.market.local.yaml
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

## Notes

- the profile stays plaintext
- the env payload is expected to be age passphrase-encrypted
- plaintext env files are only used as `encrypt` input
- `runvault` never writes decrypted env content back to disk
- when `clear_env` is true, `runvault` keeps a small default passthrough set like `PATH`, `HOME`, `USER`, `SHELL`, and `TMPDIR`
