# Development

## Prerequisites

- Rust toolchain
- Docker and Docker Compose
- Node.js and npm

Optional but useful:

- `psql`
- `kubectl`

## Repository layout

- `Cargo.toml`: workspace root and shared dependency definitions
- `crates/core`: shared models and encryption module
- `crates/server`: API server
- `crates/cli`: CLI client
- `migrations`: SQL migrations
- `web`: React UI
- `deploy/docker`: Dockerfiles and nginx config
- `deploy/k8s`: raw Kubernetes manifests
- `docs`: project documentation

## Cargo target directory

This repository stores Cargo build artifacts in `/tmp/secret-engine-target` via [`.cargo/config.toml`](/mnt/g/My%20Drive/Projects/secret-engine/.cargo/config.toml#L1).

That avoids `Text file busy (os error 26)` failures when the repository is located on a mounted or synced filesystem.

## Environment configuration

Use [`.env.example`](/mnt/g/My%20Drive/Projects/secret-engine/.env.example#L1) as the reference configuration.

Important server settings:

- `SECRET_ENGINE__HOST`
- `SECRET_ENGINE__PORT`
- `SECRET_ENGINE__DATABASE_URL`
- `SECRET_ENGINE__ALLOWED_ORIGINS`
- `SECRET_ENGINE__MASTER_KEY`

Important frontend setting:

- `VITE_API_BASE_URL`

For the web app, the preferred runtime configuration path is `web/public/config.js`, which is overridden in Kubernetes via a ConfigMap.

## Common commands

### Format and compile

```bash
cargo fmt --all
cargo check --workspace
```

### Run the local stack

```bash
docker compose up --build
```

This brings up:

- PostgreSQL on `localhost:5432`
- API server on `localhost:8080`
- web UI on `localhost:3000`

### Run only the Rust server locally

If PostgreSQL is already available:

```bash
export SECRET_ENGINE__DATABASE_URL=postgres://secret:secret@127.0.0.1:5432/secret_engine
export SECRET_ENGINE__ALLOWED_ORIGINS='["http://localhost:3000","http://127.0.0.1:3000"]'
export SECRET_ENGINE__MASTER_KEY=dev-master-key-change-me

cargo run -p secret-engine-server
```

### Run the CLI locally

```bash
export SECRET_ENGINE_ADDR=http://127.0.0.1:8080

cargo run -p secret-engine-cli -- sys init
export SECRET_ENGINE_TOKEN=REPLACE_WITH_ROOT_TOKEN

cargo run -p secret-engine-cli -- status
cargo run -p secret-engine-cli -- sys status
cargo run -p secret-engine-cli -- sys root rotate
cargo run -p secret-engine-cli -- sys root revoke
cargo run -p secret-engine-cli -- sys root recover --recovery-key REPLACE_WITH_RECOVERY_KEY
cargo run -p secret-engine-cli -- kv put apps/demo/password super-secret
cargo run -p secret-engine-cli -- kv get apps/demo/password
cargo run -p secret-engine-cli -- kv list --prefix apps/
cargo run -p secret-engine-cli -- kv delete apps/demo/password
```

### Run the web UI directly

```bash
cd web
npm install
npm run dev
```

## Local verification workflow

After a code change, the default verification order should be:

1. `cargo fmt --all`
2. `cargo check --workspace`
3. `docker compose up --build`
4. Validate `/health`
5. Validate one full CLI KV write/read/delete flow
6. Validate the same flow through the UI

This order catches:

- syntax and typing issues first
- integration issues next
- UI/API mismatch last

## Database notes

- The API server runs SQL migrations automatically at startup.
- The current schema creates a single `secrets` table.
- `pgcrypto` is enabled so `gen_random_uuid()` is available.

If you need to inspect the local database:

```bash
docker compose exec postgres psql -U secret -d secret_engine
```

Useful query:

```sql
SELECT mount, path, secret_key, version, updated_at
FROM secrets
ORDER BY path, secret_key;
```

## Docker workflow

### Rebuild after backend changes

```bash
docker compose up --build server
```

### Rebuild after web changes

```bash
docker compose up --build web
```

### Stop and remove containers

```bash
docker compose down
```

### Remove volumes too

```bash
docker compose down -v
```

Use `-v` only if you want to discard the local PostgreSQL data.

## Kubernetes workflow

The manifests are raw and intentionally simple.

Before applying the workloads, create real Kubernetes secrets from [secrets.example.yaml](/mnt/g/My%20Drive/Projects/secret-engine/deploy/k8s/secrets.example.yaml) and replace every `REPLACE_WITH_...` value. Treat that file as a template, not a production manifest.

Apply in this order:

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/secrets.example.yaml
kubectl apply -f deploy/k8s/postgres.yaml
kubectl apply -f deploy/k8s/server.yaml
kubectl apply -f deploy/k8s/web.yaml
```

These manifests currently assume:

- images will be built and pushed separately
- image names will be replaced from the placeholder `ghcr.io/example/...`
- secret values are created separately from the workload manifests
- cluster networking is plain HTTP for now

The web manifest now proxies `/api/*` and `/health` to the in-cluster server service, so the browser can use same-origin requests instead of calling `localhost` from inside the cluster.

## Coding expectations

When extending the project:

- keep shared models in `crates/core`
- keep server-only concerns in `crates/server`
- keep the encryption implementation behind the `SecretCipher` trait even if the server currently uses a concrete type
- prefer additive schema changes with migrations
- preserve the Vault-like path shape unless intentionally redesigning the API

## Recommended next development tasks

1. Add integration tests for the current KV API.
2. Add an explicit bootstrap/init workflow.
3. Add persistent tokens and path-based policies.
4. Add versioned secret history instead of only the latest value.
5. Add CI for formatting and workspace compile checks.
