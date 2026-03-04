# Secret Engine

`secret-engine` is a Rust-based secret management scaffold with a Vault-style KV API, a CLI, PostgreSQL persistence, Docker-based local development, raw Kubernetes manifests, and a small React control UI.

## Layout

- `crates/core`: shared models and the pluggable encryption abstraction.
- `crates/server`: `axum` API server backed by PostgreSQL and SQL migrations.
- `crates/cli`: `secretsctl` command-line client.
- `web`: React/Vite web UI.
- `migrations`: database schema bootstrap.
- `deploy/docker`: container build assets.
- `deploy/k8s`: raw Kubernetes manifests.

## Local development

1. Start the local stack:

   ```bash
   docker compose up --build
   ```

2. Open the UI at `http://localhost:3000`.
3. Use the API at `http://localhost:8080`.
4. Use the default bootstrap token `dev-root-token`.

The API only accepts browser requests from configured origins. For local development, the default allowlist is `http://localhost:3000` and `http://127.0.0.1:3000`.

## Rust builds on mounted drives

This repository is configured to place Cargo build artifacts in `/tmp/secret-engine-target` via [`.cargo/config.toml`](/mnt/g/My%20Drive/Projects/secret-engine/.cargo/config.toml). That avoids `Text file busy (os error 26)` failures that can happen when build scripts are executed directly from synced or mounted filesystems.

## CLI examples

```bash
export SECRET_ENGINE_ADDR=http://127.0.0.1:8080
export SECRET_ENGINE_TOKEN=dev-root-token

secretsctl status
secretsctl kv put apps/demo/password super-secret
secretsctl kv get apps/demo/password
secretsctl kv get --version 1 apps/demo/password
secretsctl kv metadata apps/demo/password
secretsctl kv undelete --version 2 apps/demo/password
secretsctl kv destroy --version 1 apps/demo/password
secretsctl kv list --prefix apps/
secretsctl kv delete apps/demo/password
```

## Token management

On startup, the configured `SECRET_ENGINE__ADMIN_TOKEN` is seeded into the database as the bootstrap admin token.

You can mint a scoped service token with:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/tokens \
  -H 'Authorization: Bearer dev-root-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "label": "demo-reader",
    "admin": false,
    "scopes": [
      { "mount": "kv", "path_prefix": "apps/demo" }
    ]
  }'
```

Use the returned token as the bearer credential for subsequent API calls.

## Current scope

- Single bootstrap admin token.
- Vault-like KV pathing (`/api/v1/kv/<mount>/<path>/<key>`).
- Versioned KV storage with metadata, soft delete, undelete, and destroy flows.
- AES-256-GCM encryption with an Argon2id-derived master key for new writes.
- Encryption is isolated behind a trait so it can be replaced later with a stronger key-management model.

## Kubernetes note

The checked-in Kubernetes workload manifests reference pre-created secrets instead of embedding credentials directly. Use [secrets.example.yaml](/mnt/g/My%20Drive/Projects/secret-engine/deploy/k8s/secrets.example.yaml) as a template and replace every `REPLACE_WITH_...` value before applying it to a cluster.
