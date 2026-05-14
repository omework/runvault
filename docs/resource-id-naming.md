# Resource ID Naming

Runvault resources are global on the machine that builds bundles. Resource IDs should therefore be stable, descriptive, and independent from the current directory, local username, host name, or profile path.

A good resource ID answers three questions:

- Where is this value used?
- Which service or component owns it?
- What material does it contain?

## Recommended Shape

Use dot-separated, lowercase IDs:

```text
<scope>.<domain>.<component>.<material>
shared.<domain>.<component>.<material>
<generic-asset>
```

The exact segment names can vary by project, but they should stay consistent across all environments.

For deployment repositories, a practical shape is:

```text
<environment>.<server-type>.<service>.<material>
```

Examples:

```text
production.services.proxy.client-ca
production.services.database.password
production.workload.database.dsn
staging.services.proxy.ingest-token
staging.workload.worker.queue-dsn
shared.payments.gateway.api-key
docker.config
services.compose
workload.run.assets
```

## Segment Guidance

`<environment>` identifies the environment, location, tenant, or deployment target. Examples: `production`, `staging`, `home`, `edge-eu`, `customer-a`.

`<server-type>` identifies the reusable server template or role. Examples: `services`, `workload`, `ingress`, `observability`, `storage`.

`<service>` or `<component>` identifies the owner or consumer. Prefer the compose service name, Kubernetes workload name, or application component name. Examples: `proxy`, `database`, `grafana`, `api`, `worker`.

`<material>` identifies the file or secret type. Use precise names such as `password`, `dsn`, `admin-password`, `jwt-secret`, `client-ca`, `server-cert`, `server-key`, `ingest-token`, or `api-key`.

## Shared Resources

Use `shared.<domain>.<component>.<material>` only when the same external value is deliberately reused by multiple environments or server types.

Examples:

```text
shared.identity.oauth.client-secret
shared.email.smtp.password
shared.payments.gateway.api-key
```

If changing a value for one environment should not affect another environment, keep it environment-scoped instead:

```text
production.services.database.password
staging.services.database.password
```

When in doubt, prefer an environment-scoped ID. Sharing can be made explicit later.

## Generic Assets

Short top-level IDs are acceptable for generic deployment assets that are intentionally environment-neutral.

Examples:

```text
docker.config
services.compose
services.run.assets
workload.compose
workload.run.assets
```

Avoid this shape for secrets or credentials. A secret usually needs an owner and a scope.

## Naming Rules

Use lowercase ASCII letters, digits, dots, and hyphens.

Use dots to separate hierarchy and hyphens inside one segment:

```text
production.services.proxy.ingest-token
```

Do not include local filesystem paths, usernames, machine names, or temporary folder names.

Do not include obsolete implementation names in new IDs. Use the current service or server-type name.

Do not encode file extensions unless the extension is part of the meaning. Prefer `service-account-key` over `service-account-key-json`.

Do not use generic IDs for environment-specific material. Prefer `production.services.proxy.ingest-token` over `proxy-token`.

## Checklist

Before adding a resource, confirm:

- The ID is meaningful outside the current folder.
- The ID is stable if the source file moves.
- The scope is explicit unless the asset is intentionally generic.
- The component segment names the owner or consumer.
- The final segment names the material, not just the local filename.
- The same naming pattern can be reused for another environment without inventing a new convention.
