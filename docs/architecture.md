# Architecture

## Purpose

`secret-engine` is a Rust-based secret management system modeled after the basic shape of HashiCorp Vault. The current implementation is an MVP focused on a single KV secret engine, explicit one-time initialization with a root token, PostgreSQL-backed persistence, and local/container deployment.

The design goal is to keep the initial system simple while leaving room for stronger authentication, policy controls, encryption changes, and Kubernetes hardening.

## Current components

### Rust workspace

- `crates/core`
  - Shared domain models for secret reads/writes/lists.
  - Encryption abstraction (`SecretCipher`) and the current AES-256-GCM implementation.
- `crates/server`
  - `axum` HTTP API.
  - Configuration loading from environment variables.
  - SQL migrations on startup.
  - Secret CRUD handlers backed by PostgreSQL.
- `crates/cli`
  - `secretsctl` command-line client.
  - Calls the server API over HTTP using a Vault-like CLI shape.

### Web UI

- `web`
  - React + Vite frontend.
  - Minimal operator console for health check, token entry, and KV read/write/list.
  - Runtime API endpoint configuration via `public/config.js`.

### Deployment assets

- `docker-compose.yml`
  - Local developer stack for PostgreSQL, API server, and web UI.
- `deploy/docker`
  - Container builds for server and web.
- `deploy/k8s`
  - Raw manifests for namespace, PostgreSQL, API server, and web UI.

## Data flow

### Write secret

1. A client sends `POST /api/v1/kv/<mount>/<path>/<key>` with a bearer token and plaintext secret value.
2. The server validates the bearer token against stored service tokens (after initialization).
3. The server encrypts the plaintext using the configured cipher implementation.
4. The server stores the encrypted payload, algorithm identifier, and version metadata in PostgreSQL.
5. The server returns mount/path/key/version metadata.

### Read secret

1. A client sends `GET /api/v1/kv/<mount>/<path>/<key>`.
2. The server validates the bearer token.
3. The server loads the encrypted record from PostgreSQL.
4. The server decrypts the record using the configured cipher.
5. The server returns plaintext and metadata.

### List secrets

1. A client sends `GET /api/v1/kv/<mount>?prefix=<prefix>`.
2. The server validates the bearer token.
3. The server performs a prefix-style query on the stored path field.
4. The server returns metadata only, not plaintext secret values.

## API shape

### Health

- `GET /health`
  - Returns a simple health payload.

### Auth

- `GET /api/v1/auth/validate`
  - Confirms that the supplied bearer token is accepted.

### KV engine

- `GET /api/v1/kv/:mount`
  - Lists secrets for a mount, optionally filtered by `prefix`.
- `GET /api/v1/kv/:mount/metadata/*path`
  - Returns per-version metadata for a single secret.
- `POST /api/v1/kv/:mount/undelete/*path`
  - Clears soft-delete markers for the requested versions.
- `POST /api/v1/kv/:mount/destroy/*path`
  - Permanently removes the requested versions.
- `GET /api/v1/kv/:mount/*path`
  - Reads the current secret version by default, or a specific version when `?version=<n>` is supplied.
- `POST /api/v1/kv/:mount/*path`
  - Writes a new current version for a single secret.
- `DELETE /api/v1/kv/:mount/*path`
  - Soft-deletes the current secret version.

The current path convention treats the final path segment as the key and the preceding segments as the logical path. Example:

- Request path: `/api/v1/kv/kv/apps/demo/password`
- Logical mount: `kv`
- Logical path: `apps/demo`
- Key: `password`

## Persistence model

The current PostgreSQL schema stores versioned secret rows with:

- `mount`
- `path`
- `secret_key`
- `encrypted_value`
- `cipher_algorithm`
- `version`
- `deleted_at` for soft-deleted current versions
- timestamps

The combination of `mount + path + secret_key + version` is unique.

Destroyed versions are removed permanently. The current schema does not keep a separate tombstone record after destroy.

This schema is intentionally narrow. It supports the current KV use case and keeps future upgrades straightforward:

- token tables
- policy tables
- versioned secret history
- audit/event logs
- mounts beyond KV

## Encryption model

The current implementation uses:

- AES-256-GCM
- a master key derived from a configured passphrase using Argon2id for new writes
- legacy SHA-256-derived ciphertext remains readable during migration
- a random nonce per secret write
- a serialized envelope containing a versioned algorithm identifier and base64 payload

This is acceptable for an MVP, but it is not the long-term target for a production-grade secret engine.

The upgrade path is preserved by the `SecretCipher` trait in `crates/core`, which allows replacing the implementation with:

- a keyring-backed master key
- envelope encryption
- HSM/KMS integration
- key rotation support

## Security model

### Current

- Explicit init flow that mints a root token once.
- No user identities.
- No policy enforcement.
- No audit trail.
- Service token issuance is available, with optional expiry.

### Intended future direction

- Explicit init/unseal or bootstrap workflow.
- Managed service tokens with TTLs.
- Fine-grained path policies.
- Audit logging for secret access and mutation.
- Secret version history and optional soft delete.

## Deployment model

### Local development

- Docker Compose runs PostgreSQL, the API server, and the web UI.
- PostgreSQL is the only persistent local dependency.
- The server runs migrations at startup.

### Kubernetes

- Raw manifests are provided first to keep the deployment shape obvious.
- The current manifests are suitable as a starting point, not as production-ready infrastructure.

Production hardening will require:

- real image publishing
- non-default secrets
- ingress
- TLS
- storage class choices
- resource limits/requests
- network policies
- backup and restore strategy

## Known limitations

- Single-node architecture.
- No HA or leader election.
- No secret leases or dynamic secret backends.
- No auth backends beyond a static token.
- No transit engine, PKI engine, or database credentials engine.
- No tests yet beyond compile validation.

## Immediate architectural priorities

1. Expand integration tests against PostgreSQL for current KV/auth flows.
2. Add audit logging and request correlation.
3. Harden policy expressiveness beyond path-prefix checks.
4. Add key-rotation lifecycle support.
5. Harden deployment manifests for realistic Kubernetes usage.
