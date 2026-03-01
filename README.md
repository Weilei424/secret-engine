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

## Rust builds on mounted drives

This repository is configured to place Cargo build artifacts in `/tmp/secret-engine-target` via [`.cargo/config.toml`](/mnt/g/My%20Drive/Projects/secret-engine/.cargo/config.toml). That avoids `Text file busy (os error 26)` failures that can happen when build scripts are executed directly from synced or mounted filesystems.

## CLI examples

```bash
export SECRET_ENGINE_ADDR=http://127.0.0.1:8080
export SECRET_ENGINE_TOKEN=dev-root-token

secretsctl status
secretsctl kv put apps/demo/password super-secret
secretsctl kv get apps/demo/password
secretsctl kv list --prefix apps/
secretsctl kv delete apps/demo/password
```

## Current scope

- Single bootstrap admin token.
- Vault-like KV pathing (`/api/v1/kv/<mount>/<path>/<key>`).
- AES-256-GCM encryption with a passphrase-derived master key.
- Encryption is isolated behind a trait so it can be replaced later with a stronger key-management model.
