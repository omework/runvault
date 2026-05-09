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

If you omit the profile path, `runvault` now defaults to:

```text
./.vault
```

You can also target a profile explicitly with the global `--profile` / `-p` flag:

```bash
runvault --profile deployments/ovh/services run
runvault -p deployments/ovh/services import env .env.local
runvault -p deployments/ovh/services cmd set -- docker compose up -d
```

The flag takes precedence over legacy positional profile arguments.

## Commands

```bash
runvault create-profile
runvault create-profile deployments/ovh/services
runvault --profile deployments/ovh/services run
runvault bundle services.bundle.yaml --version v1.0.0 --description "OVH services profile"
runvault run services.bundle.yaml
runvault encrypt .env
runvault jwt JWT_SIGNING_SECRET --issuer runvault --audience tempo --subject worker --ttl 15m
runvault set DATABASE_URL --value postgres://...
runvault set deployments/ovh/services DATABASE_URL --value postgres://...
runvault --profile deployments/ovh/services set DATABASE_URL --value postgres://...
runvault import env .env.example .env.local --prefix PROD_
runvault import env deployments/ovh/services .env.example .env.local --prefix PROD_
runvault --profile deployments/ovh/services import env .env.example .env.local --prefix PROD_
runvault import-files files-spec.yaml tls-files.yaml
runvault import-files deployments/ovh/services files-spec.yaml tls-files.yaml
runvault cmd set -- docker compose up -d
runvault --profile deployments/ovh/services cmd set -- docker compose up -d
runvault ping add api http://127.0.0.1:8080/health
runvault --profile deployments/ovh/services pki init
runvault --profile deployments/ovh/services pki issue glt.market --dns glt.market --server
runvault --profile deployments/ovh/services pki issue mazie-client --client
runvault set deployments/ovh/services TLS_KEY \
  --value \"secret-key\" \
  --to-file .runvault/tls/key.pem \
  --mode 0600
runvault set deployments/ovh/services GOOGLE_APPLICATION_CREDENTIALS \
  --from-file ./gcp-service-account.json \
  --to-file .runvault/gcp-service-account.json \
  --mode 0600
runvault delete GOOGLE_APPLICATION_CREDENTIALS
runvault reveal DATABASE_URL
runvault reveal GOOGLE_APPLICATION_CREDENTIALS --raw
runvault run
runvault ping
runvault cache clear deployments/ovh/services
```

`create-profile` bootstraps the profile folder by creating:

- `runvault.yaml`

It does not create `env.sec`; that file is created lazily by the first `set` or `import`.

`pki` keeps certificate material next to the profile under:

```text
<profile-folder>/pki/
  ca/root/root.key.pem
  ca/root/root.crt.pem
  ca/root/root.chain.pem
  issued/<name>/<name>.key.pem
  issued/<name>/<name>.crt.pem
  issued/<name>/<name>.chain.pem
```

`runvault pki init` creates the profile root CA. `runvault pki issue` signs a leaf with that root. If you do not pass `--client` or `--server`, the issued cert gets both usages. If you issue a server cert without any `--dns` or `--ip` SANs, `runvault` uses the certificate name as the default DNS SAN.

## Secure password reuse

`runvault` does not keep a local fallback password cache on disk.

Current behavior:

- on macOS:
  - `runvault` reuses the password from Keychain when a matching entry exists
  - if no Keychain entry exists, it prompts
  - once you enter a valid password, it stores it in Keychain for that profile
- on platforms without supported system secure storage:
  - `runvault` prompts every command

So the rule is:

- system secure store available -> reuse through that store
- no secure store -> prompt

You can clear a stored profile password with:

```bash
runvault cache clear deployments/ovh/services
```

On macOS this removes the matching Keychain-backed runvault entry for that profile.

## Profile format

```yaml
name: glt-market-local
env_file: env.sec
run:
  cmd: ["cargo", "run"]
  clear_env: true
  pass_env:
    - CARGO_HOME
    - RUSTUP_HOME
files:
  GOOGLE_APPLICATION_CREDENTIALS:
    target_path: .runvault/gcp-service-account.json
    mode: "0600"
    cleanup: keep
resources:
  BUNDLED_DOCKER_COMPOSE_FILE:
    source_path: ./docker-compose.yml
    target_path: ./docker-compose.yml
    mode: "0644"
    cleanup: keep
pings:
  - name: api
    url: http://127.0.0.1:8080/health
    timeout_seconds: 30
    interval_millis: 500
```

If `env_file` is omitted, it defaults to `env.sec` next to `runvault.yaml`.

Inside `runvault.yaml`, `resources:` uses profile field names:

- `source_path`
- `target_path`

## Creating a profile folder

Bootstrap a new profile folder with:

```bash
runvault create-profile
runvault create-profile deployments/ovh/services
```

You can override the generated profile name and encrypted env filename:

```bash
runvault create-profile deployments/ovh/services \
  --name ovh-services \
  --env-file env.sec
```

The generated `runvault.yaml` uses a safe placeholder command:

```yaml
run:
  cmd: ["echo", "configure run.cmd in runvault.yaml"]
```

Edit that before you rely on `runvault run`.

You can also set the run command from the CLI:

```bash
runvault cmd set -- docker compose up -d
runvault cmd set vault -- docker compose up -d
runvault cmd set . -- /usr/local/bin/my-service --port 8080
```

Why `--`:

- everything before `--` is parsed as `runvault` arguments
- everything after `--` is stored verbatim as `run.cmd`

If a command input path is a directory, `runvault` resolves:

- `runvault.yaml` as the profile file
- `env.sec` as the default encrypted payload path

Explicit profile file paths still work.

If no profile path is provided for profile-based commands, `runvault` uses `./.vault`.

If `./.vault` does not exist yet, `runvault` bootstraps it automatically the first time you use an implicit default-profile command.

## Bundling a profile

You can package a profile into a single file that contains:

- bundle metadata
- the profile YAML
- the encrypted `env.sec` payload
- bundled profile resources

Export a bundle with:

```bash
runvault bundle services.bundle.yaml
runvault bundle deployments/ovh/services/vault services.bundle.yaml \
  --version v1.0.0 \
  --description "OVH services deployment"
runvault bundle deployments/ovh/services/vault services.bundle.yaml --force
```

Run it later with:

```bash
runvault run services.bundle.yaml
```

Behavior:

- `bundle` defaults to `./.vault` if no profile is specified
- existing bundle targets are rejected by default; use `--force` to overwrite them
- `run <bundle-file>` unpacks into a temporary profile directory and runs from there
- password reuse for bundle execution is keyed off the bundle file path, not the temporary extraction path
- profile `resources:` are copied into the bundle and restored before execution
- bundle schema version `1` uses structured YAML under top-level `env`, `files`, and `resources`

## Managing ping targets

You can register or update a ping target directly from the CLI:

```bash
runvault ping add api http://127.0.0.1:8080/health
runvault ping add deployments/ovh/services api https://api.example.com/health \
  --timeout-seconds 10 \
  --interval-millis 250
```

Behavior:

- ping targets are stored in `runvault.yaml`
- `ping add` upserts by target name
- if the target name already exists, its URL and timing settings are updated
- if no profile path is provided, the target is added to `./.vault/runvault.yaml`

## Value modes

`runvault` supports two stored value types inside the encrypted payload:

- plain text values
- file-backed values

Plain text values are injected directly as environment variables.

File-backed values now split across the two profile artifacts:

- `runvault.yaml`
  - declares the visible file spec:
    - key
    - target path
    - mode
    - cleanup
- `env.sec`
  - stores the encrypted file content

At runtime, `runvault` reads the file spec from `runvault.yaml`, decrypts the matching file content from `env.sec`, writes it to the configured target path, and sets the environment variable value to that configured file path.

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
- keep the file in place by default

If you want an ephemeral runtime file instead, use `--on-exit`. That writes `cleanup: on_exit` into `runvault.yaml` and removes the materialized file after the child exits.

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
runvault set API_KEY --value abc

# explicit profile
runvault set deployments/ovh/services API_KEY --value abc

# file -> env (source file must be valid UTF-8)
runvault set deployments/ovh/services TLS_CERT_PEM --from-file ./cert.pem

# value -> file
runvault set deployments/ovh/services TLS_KEY \
  --value \"secret-key\" \
  --to-file .runvault/tls/key.pem \
  --mode 0600

# file -> file
runvault set deployments/ovh/services GOOGLE_APPLICATION_CREDENTIALS \
  --from-file ./gcp-service-account.json \
  --to-file .runvault/gcp-service-account.json \
  --mode 0600

# file -> file, cleaned up after the child exits
runvault set deployments/ovh/services TEMP_COMPOSE_FILE \
  --from-file ./docker-compose.override.yml \
  --to-file .runvault/docker-compose.override.yml \
  --on-exit
```

Options for file materialization:

- `--to-file PATH`
- `--mode 0600`
- `--keep`
- `--on-exit`

Defaults:

- mode defaults to `0600`
- cleanup defaults to `keep` when `--to-file` is used
- `--on-exit` changes cleanup to `on_exit`

`set ... --to-file ...` also updates `runvault.yaml` so the file spec is visible without decrypting the vault.

## Generating a JWT

You can mint an HS256 JWT and store it as a plain-text value in the vault:

```bash
runvault jwt CADDY_TEMPO_INGEST_TOKEN \
  --issuer runvault \
  --audience tempo \
  --subject workers-otel \
  --ttl 15m
```

Explicit profile also works:

```bash
runvault jwt deployments/ovh/services/vault CADDY_TEMPO_INGEST_TOKEN --audience tempo
```

Behavior:

- the generated JWT is always stored back into the vault key you pass positionally
- by default `runvault` generates a fresh signing secret internally for the token
- if you want deterministic signing, pass `--signing-key <KEY>` and that key must already exist in the vault as a plain-text value
- `iat` and `exp` are always added automatically
- `--ttl` accepts:
  - seconds, for example `900`
  - `s`, `m`, `h`, `d` suffixes, for example `30s`, `15m`, `1h`, `1d`
- you can add custom string claims with repeated `--claim KEY=VALUE`
- custom claims cannot override reserved claims:
  - `iat`
  - `exp`
  - `iss`
  - `aud`
  - `sub`
- by default the token is also printed to stdout
- `--file <path>` writes the generated token to a file instead
- `--output <path>` remains accepted as an alias of `--file`

## Importing an existing env file

You can bulk-load an existing dotenv-style file into the encrypted vault:

```bash
runvault import env deployments/ovh/services .env.example
```

You can also import multiple dotenv files in one call. Shell wildcards work naturally because the shell expands them before `runvault` sees the arguments:

```bash
runvault import env deployments/ovh/services .env .env.local
runvault import env deployments/ovh/services .env.*
```

You can also add a prefix to every imported key before it is stored:

```bash
runvault import env deployments/ovh/services .env.example .env.local --prefix PROD_
```

Behavior:

- dotenv content is parsed with the same parser used for legacy env payloads
- multiple input files are imported from left to right
- later files overwrite earlier keys when they define the same final key
- imported keys overwrite existing plain-text values with the same final key
- `import env` also understands inline file-spec references in env values
- the prefix is applied before key validation

Inline reference format:

```dotenv
PROD_GLT_MARKET_OPENAI_API_KEY=@.env-files.yaml
PROD_GLT_MARKET_GOOGLE_APPLICATION_CREDENTIALS=@".env-files.yaml"
```

Recommended notation:

- `@.env-files.yaml`
- use `@"path with spaces.yaml"` only when quoting is needed

When `import env` sees one of these values, it:

- loads the referenced YAML file
- looks up the same env key inside its `files:` map
- imports that entry using the same semantics as `runvault import-files`

## Importing resources from a YAML spec

You can bulk-load profile resources from a YAML file:

```bash
runvault import resources deployments/ovh/services resources.yaml
```

Spec format:

```yaml
resources:
  BUNDLED_DOCKER_COMPOSE_FILE:
    src: ./docker-compose.yml
    to-file: ./docker-compose.yml
    mode: "0644"
    cleanup: keep
```

This import spec format is intentionally different from `runvault.yaml`:

- import spec fields are `src` and `to-file`
- stored profile fields are `source_path` and `target_path`

Behavior:

- resources are written into `runvault.yaml`, not into `env.sec`
- multiple spec files are imported from left to right
- later spec files overwrite earlier resource entries with the same key
- relative `src` paths are resolved relative to the YAML spec file location
- `~` in `src` paths is expanded against `$HOME`
- imported `to-file` values become profile `target_path` entries
- profile `target_path` is resolved from the profile workdir at runtime
- when exporting a bundle, relative resource `source_path` values are looked up from the same effective workdir used by `run`, after resolving any relative workdir from the current process directory
- when `workdir` is omitted, bundle export treats the current process directory as the lookup base for relative resource `source_path`

## Importing file-backed values from a YAML spec

You can bulk-load file-backed values from a YAML file:

```bash
runvault import-files deployments/ovh/services files-spec.yaml
```

You can also import multiple spec files:

```bash
runvault import-files deployments/ovh/services files-spec.yaml certs/*.yaml
```

Spec format:

```yaml
files:
  SERVICE_CA_CRT:
    src: ../pki/ca/root/root.crt.pem
    to-file: /home/debian/mata35/pki/root.crt.pem
    mode: "0644"
    cleanup: keep
  SERVICE_KEY:
    src: ../pki/issued/glt.market/glt.market.key.pem
    to-file: /home/debian/mata35/pki/glt.market.key.pem
    mode: "0600"
    cleanup: keep
  FIREBASE_JSON:
    src: ../firebase/service-account.json
```

Behavior:

- `src` is read from disk when you run the command
- multiple spec files are imported from left to right
- later spec files overwrite earlier keys when they define the same env var
- with `to-file`, encrypted file content is stored in `env.sec` and the visible file spec is mirrored into `runvault.yaml`
- without `to-file`, the source file content is imported as a plain env value
- when importing as a plain env value, the source file must be valid UTF-8
- `runvault import` can reference this same spec file inline from a dotenv value using `@path`
- relative `src` paths are resolved relative to the YAML spec file location
- imported file-backed keys overwrite existing values with the same key
- `mode` and `cleanup` are only valid when `to-file` is present
- when `to-file` is present and `cleanup` is omitted, it defaults to `keep`
- `~` in `src` paths is expanded against `$HOME`

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
- file-backed values persist by default when `--to-file` is used
- use `--on-exit` or `cleanup: on_exit` for ephemeral runtime files
- when `clear_env` is true, `runvault` keeps a small default passthrough set like `PATH`, `HOME`, `USER`, `SHELL`, and `TMPDIR`
