use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result as AnyResult};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use config::{Config, Environment};
use secret_engine_core::{
    crypto::{AesGcmCipher, CiphertextEnvelope, SecretCipher},
    model::{
        SecretListResponse, SecretMetadata, SecretMetadataResponse, SecretReadResponse,
        SecretVersionActionRequest, SecretVersionMetadata, SecretWriteRequest, SecretWriteResponse,
        SystemInitResponse, SystemInitStatusResponse, SystemRootRecoverRequest,
        SystemRootRecoverResponse, SystemRootRotateResponse, TokenCreateRequest,
        TokenCreateResponse, TokenListResponse, TokenMetadata, TokenScope,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, postgres::PgPoolOptions};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
struct Settings {
    host: String,
    port: u16,
    database_url: String,
    allowed_origins: Vec<String>,
    master_key: String,
}

impl Settings {
    fn load() -> AnyResult<Self> {
        let config = Config::builder()
            .set_default("host", "0.0.0.0")?
            .set_default("port", 8080)?
            .set_default(
                "allowed_origins",
                vec!["http://localhost:3000", "http://127.0.0.1:3000"],
            )?
            .add_source(Environment::with_prefix("SECRET_ENGINE").separator("__"))
            .build()?;

        config.try_deserialize().context("invalid configuration")
    }
}

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    cipher: Arc<AesGcmCipher>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReadQuery {
    version: Option<i32>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Clone, FromRow)]
struct SecretRow {
    id: Uuid,
    mount: String,
    path: String,
    secret_key: String,
    encrypted_value: String,
    cipher_algorithm: String,
    version: i32,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, FromRow)]
struct ServiceTokenRow {
    id: Uuid,
    label: String,
    is_admin: bool,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, FromRow)]
struct TokenPolicyRow {
    mount: String,
    path_prefix: String,
}

#[derive(Debug, Clone, FromRow)]
struct SystemStateRow {
    initialized_at: Option<chrono::DateTime<chrono::Utc>>,
    recovery_key_hash: Option<String>,
}

#[derive(Debug, Clone)]
struct AuthContext {
    token_id: Uuid,
    is_admin: bool,
}

impl From<SecretRow> for SecretMetadata {
    fn from(value: SecretRow) -> Self {
        let _ = value.id;
        let _ = value.created_at;
        let _ = value.deleted_at;
        Self {
            mount: value.mount,
            path: value.path,
            key: value.secret_key,
            version: value.version,
            current_version: value.version,
            updated_at: value.updated_at,
        }
    }
}

#[tokio::main]
async fn main() -> AnyResult<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "secret_engine_server=info,tower_http=info".to_string()),
        )
        .init();

    let settings = Settings::load()?;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&settings.database_url)
        .await
        .context("database connection failed")?;

    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .context("failed to run migrations")?;

    let state = AppState {
        pool,
        cipher: Arc::new(
            AesGcmCipher::from_passphrase(&settings.master_key)
                .context("failed to derive master key")?,
        ),
    };
    let cors = build_cors_layer(&settings).context("invalid CORS configuration")?;

    let app = Router::new()
        .route("/health", get(health))
        .route(
            "/api/v1/sys/init",
            get(read_system_init_status).post(init_system),
        )
        .route("/api/v1/sys/root/rotate", axum::routing::post(rotate_root))
        .route("/api/v1/sys/root/revoke", axum::routing::post(revoke_root))
        .route(
            "/api/v1/sys/root/recover",
            axum::routing::post(recover_root),
        )
        .route("/api/v1/auth/validate", get(validate_token))
        .route("/api/v1/tokens", get(list_tokens).post(create_token))
        .route(
            "/api/v1/tokens/:token_id",
            axum::routing::delete(delete_token),
        )
        .route("/api/v1/kv/:mount", get(list_secrets))
        .route(
            "/api/v1/kv/:mount/metadata/*path",
            get(read_secret_metadata),
        )
        .route(
            "/api/v1/kv/:mount/undelete/*path",
            axum::routing::post(undelete_secret),
        )
        .route(
            "/api/v1/kv/:mount/destroy/*path",
            axum::routing::post(destroy_secret),
        )
        .route(
            "/api/v1/kv/:mount/*path",
            get(read_secret).post(write_secret).delete(delete_secret),
        )
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = format!("{}:{}", settings.host, settings.port).parse()?;
    info!("listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

fn build_cors_layer(settings: &Settings) -> AnyResult<CorsLayer> {
    let allowed_origins = settings
        .allowed_origins
        .iter()
        .map(|origin| {
            origin
                .parse::<HeaderValue>()
                .with_context(|| format!("invalid allowed origin: {origin}"))
        })
        .collect::<AnyResult<Vec<_>>>()?;

    Ok(CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]))
}

async fn validate_token(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> std::result::Result<StatusCode, ApiError> {
    authenticate(&headers, &state).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn read_system_init_status(
    State(state): State<AppState>,
) -> std::result::Result<Json<SystemInitStatusResponse>, ApiError> {
    let initialized_at = load_initialized_at(&state.pool).await?;
    Ok(Json(SystemInitStatusResponse {
        initialized: initialized_at.is_some(),
        initialized_at,
    }))
}

async fn init_system(
    State(state): State<AppState>,
) -> std::result::Result<Json<SystemInitResponse>, ApiError> {
    let mut tx = state.pool.begin().await?;

    let already_initialized = sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
        r#"
        SELECT initialized_at
        FROM system_state
        WHERE id = 1
        FOR UPDATE
        "#,
    )
    .fetch_optional(&mut *tx)
    .await?
    .flatten();

    if already_initialized.is_some() {
        return Err(ApiError::conflict("system is already initialized"));
    }

    let root_token = new_root_token();
    let recovery_key = new_recovery_key();
    let root_token_hash = hash_token(&root_token);
    let recovery_key_hash = hash_token(&recovery_key);
    let root_token_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO service_tokens (id, label, token_hash, is_admin, bootstrap_slot)
        VALUES ($1, 'root', $2, TRUE, 1)
        "#,
    )
    .bind(root_token_id)
    .bind(root_token_hash)
    .execute(&mut *tx)
    .await?;

    let initialized_at = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
        r#"
        UPDATE system_state
        SET initialized_at = NOW(), recovery_key_hash = $1, updated_at = NOW()
        WHERE id = 1
        RETURNING initialized_at
        "#,
    )
    .bind(recovery_key_hash)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(SystemInitResponse {
        root_token,
        recovery_key,
        initialized_at,
    }))
}

async fn rotate_root(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> std::result::Result<Json<SystemRootRotateResponse>, ApiError> {
    authorize_root(&headers, &state).await?;
    let mut tx = state.pool.begin().await?;

    let root_token = new_root_token();
    let recovery_key = new_recovery_key();
    let root_token_hash = hash_token(&root_token);
    let recovery_key_hash = hash_token(&recovery_key);

    let rotated_at = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
        r#"
        UPDATE service_tokens
        SET token_hash = $1, is_admin = TRUE, expires_at = NULL, updated_at = NOW()
        WHERE bootstrap_slot = 1
        RETURNING updated_at
        "#,
    )
    .bind(root_token_hash)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("root token not found"))?;

    sqlx::query(
        r#"
        UPDATE system_state
        SET recovery_key_hash = $1, updated_at = NOW()
        WHERE id = 1
        "#,
    )
    .bind(recovery_key_hash)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(SystemRootRotateResponse {
        root_token,
        recovery_key,
        rotated_at,
    }))
}

async fn revoke_root(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> std::result::Result<StatusCode, ApiError> {
    authorize_root(&headers, &state).await?;

    let result = sqlx::query(
        r#"
        DELETE FROM service_tokens
        WHERE bootstrap_slot = 1
        "#,
    )
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("root token not found"));
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn recover_root(
    State(state): State<AppState>,
    Json(payload): Json<SystemRootRecoverRequest>,
) -> std::result::Result<Json<SystemRootRecoverResponse>, ApiError> {
    if payload.recovery_key.trim().is_empty() {
        return Err(ApiError::bad_request("recovery key cannot be empty"));
    }

    let mut tx = state.pool.begin().await?;
    let system_row = sqlx::query_as::<_, SystemStateRow>(
        r#"
        SELECT initialized_at, recovery_key_hash
        FROM system_state
        WHERE id = 1
        FOR UPDATE
        "#,
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::service_unavailable("system state row is missing"))?;

    if system_row.initialized_at.is_none() {
        return Err(ApiError::service_unavailable(
            "server is not initialized; call POST /api/v1/sys/init",
        ));
    }

    let recovery_hash = system_row
        .recovery_key_hash
        .ok_or_else(|| ApiError::conflict("recovery key is not configured; rotate root first"))?;

    if recovery_hash != hash_token(payload.recovery_key.trim()) {
        return Err(ApiError::unauthorized("recovery key rejected"));
    }

    let root_token = new_root_token();
    let new_recovery_key = new_recovery_key();
    let root_token_hash = hash_token(&root_token);
    let new_recovery_key_hash = hash_token(&new_recovery_key);
    let root_id = Uuid::new_v4();

    let recovered_at = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
        r#"
        INSERT INTO service_tokens (id, label, token_hash, is_admin, bootstrap_slot)
        VALUES ($1, 'root', $2, TRUE, 1)
        ON CONFLICT (bootstrap_slot)
        DO UPDATE SET
            token_hash = EXCLUDED.token_hash,
            is_admin = TRUE,
            expires_at = NULL,
            updated_at = NOW()
        RETURNING updated_at
        "#,
    )
    .bind(root_id)
    .bind(root_token_hash)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        UPDATE system_state
        SET recovery_key_hash = $1, updated_at = NOW()
        WHERE id = 1
        "#,
    )
    .bind(new_recovery_key_hash)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(SystemRootRecoverResponse {
        root_token,
        recovery_key: new_recovery_key,
        recovered_at,
    }))
}

async fn list_tokens(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> std::result::Result<Json<TokenListResponse>, ApiError> {
    authorize_admin(&headers, &state).await?;

    let rows = sqlx::query_as::<_, ServiceTokenRow>(
        r#"
        SELECT id, label, is_admin, expires_at, created_at, updated_at
        FROM service_tokens
        ORDER BY created_at ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let metadata = load_token_metadata(&state.pool, row).await?;
        items.push(metadata);
    }

    Ok(Json(TokenListResponse { items }))
}

async fn create_token(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<TokenCreateRequest>,
) -> std::result::Result<Json<TokenCreateResponse>, ApiError> {
    authorize_admin(&headers, &state).await?;

    let TokenCreateRequest {
        label,
        admin,
        expires_at,
        scopes: requested_scopes,
    } = payload;

    if label.trim().is_empty() {
        return Err(ApiError::bad_request("token label cannot be empty"));
    }

    if !admin && requested_scopes.is_empty() {
        return Err(ApiError::bad_request(
            "non-admin tokens require at least one scope",
        ));
    }

    let mut scopes = Vec::with_capacity(requested_scopes.len());
    for scope in requested_scopes {
        let mount = scope.mount.trim().to_string();
        if mount.is_empty() {
            return Err(ApiError::bad_request("token scope mount cannot be empty"));
        }

        scopes.push(TokenScope {
            mount,
            path_prefix: normalize_path_prefix(&scope.path_prefix),
        });
    }

    let plain_token = format!("se_{}", Uuid::new_v4().simple());
    let token_hash = hash_token(&plain_token);
    let token_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO service_tokens (id, label, token_hash, is_admin, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(token_id)
    .bind(label.trim())
    .bind(token_hash)
    .bind(admin)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

    for scope in &scopes {
        sqlx::query(
            r#"
            INSERT INTO service_token_policies (token_id, mount, path_prefix)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(token_id)
        .bind(&scope.mount)
        .bind(&scope.path_prefix)
        .execute(&state.pool)
        .await?;
    }

    let row = sqlx::query_as::<_, ServiceTokenRow>(
        r#"
        SELECT id, label, is_admin, expires_at, created_at, updated_at
        FROM service_tokens
        WHERE id = $1
        "#,
    )
    .bind(token_id)
    .fetch_one(&state.pool)
    .await?;

    let metadata = load_token_metadata(&state.pool, row).await?;

    Ok(Json(TokenCreateResponse {
        token: plain_token,
        metadata,
    }))
}

async fn list_secrets(
    headers: HeaderMap,
    Path(mount): Path<String>,
    Query(query): Query<ListQuery>,
    State(state): State<AppState>,
) -> std::result::Result<Json<SecretListResponse>, ApiError> {
    let prefix = normalize_path_prefix(query.prefix.as_deref().unwrap_or_default());
    authorize_path(&headers, &state, &mount, &prefix).await?;

    let like_value = if prefix.is_empty() {
        "%".to_string()
    } else {
        format!("{prefix}%")
    };

    let rows = sqlx::query_as::<_, SecretRow>(
        r#"
        SELECT id, mount, path, secret_key, encrypted_value, cipher_algorithm, version, created_at, updated_at, deleted_at
        FROM (
            SELECT DISTINCT ON (mount, path, secret_key)
                id, mount, path, secret_key, encrypted_value, cipher_algorithm, version, created_at, updated_at, deleted_at
            FROM secrets
            WHERE mount = $1 AND path LIKE $2
            ORDER BY mount, path, secret_key, version DESC
        ) AS current_secrets
        WHERE deleted_at IS NULL
        ORDER BY path ASC, secret_key ASC
        "#,
    )
    .bind(&mount)
    .bind(&like_value)
    .fetch_all(&state.pool)
    .await?;

    let items = rows.into_iter().map(SecretMetadata::from).collect();
    Ok(Json(SecretListResponse { items }))
}

async fn read_secret(
    headers: HeaderMap,
    Path((mount, path)): Path<(String, String)>,
    Query(query): Query<ReadQuery>,
    State(state): State<AppState>,
) -> std::result::Result<Json<SecretReadResponse>, ApiError> {
    let (secret_path, key) = split_secret_path(&path)?;
    authorize_path(&headers, &state, &mount, &secret_path).await?;
    let latest = load_latest_secret_row(&state.pool, &mount, &secret_path, &key)
        .await?
        .ok_or_else(|| ApiError::not_found("secret not found"))?;

    let row = match query.version {
        Some(version) => {
            if version <= 0 {
                return Err(ApiError::bad_request("version must be greater than zero"));
            }

            let row = load_secret_version_row(&state.pool, &mount, &secret_path, &key, version)
                .await?
                .ok_or_else(|| ApiError::not_found("secret version not found"))?;

            if row.deleted_at.is_some() {
                return Err(ApiError::not_found("secret version is deleted"));
            }

            row
        }
        None => {
            if latest.deleted_at.is_some() {
                return Err(ApiError::not_found("secret not found"));
            }

            latest.clone()
        }
    };

    let value = decrypt_secret_row(&state, &row).await?;

    Ok(Json(SecretReadResponse {
        mount: row.mount,
        path: row.path,
        key: row.secret_key,
        value,
        version: row.version,
        current_version: latest.version,
        updated_at: row.updated_at,
    }))
}

async fn read_secret_metadata(
    headers: HeaderMap,
    Path((mount, path)): Path<(String, String)>,
    State(state): State<AppState>,
) -> std::result::Result<Json<SecretMetadataResponse>, ApiError> {
    let (secret_path, key) = split_secret_path(&path)?;
    authorize_path(&headers, &state, &mount, &secret_path).await?;

    let rows = load_all_secret_versions(&state.pool, &mount, &secret_path, &key).await?;
    if rows.is_empty() {
        return Err(ApiError::not_found("secret not found"));
    }

    let latest_version = rows[0].version;
    let current_version = if rows[0].deleted_at.is_none() {
        Some(rows[0].version)
    } else {
        None
    };
    let versions = rows
        .into_iter()
        .map(|row| SecretVersionMetadata {
            version: row.version,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deleted_at: row.deleted_at,
        })
        .collect();

    Ok(Json(SecretMetadataResponse {
        mount,
        path: secret_path,
        key,
        latest_version,
        current_version,
        versions,
    }))
}

async fn write_secret(
    headers: HeaderMap,
    Path((mount, path)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(payload): Json<SecretWriteRequest>,
) -> std::result::Result<Json<SecretWriteResponse>, ApiError> {
    let (secret_path, key) = split_secret_path(&path)?;
    authorize_path(&headers, &state, &mount, &secret_path).await?;

    let encrypted = state
        .cipher
        .encrypt(&payload.value)
        .await
        .map_err(|err| ApiError::internal(format!("encrypt failed: {err}")))?;

    let mut tx = state.pool.begin().await?;
    // Serialize version allocation per logical secret to avoid duplicate version races.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1 || '|' || $2 || '|' || $3))")
        .bind(&mount)
        .bind(&secret_path)
        .bind(&key)
        .execute(&mut *tx)
        .await?;

    let row = sqlx::query_as::<_, SecretRow>(
        r#"
        INSERT INTO secrets (mount, path, secret_key, encrypted_value, cipher_algorithm, version)
        SELECT
            $1,
            $2,
            $3,
            $4,
            $5,
            COALESCE(MAX(version), 0) + 1
        FROM secrets
        WHERE mount = $1 AND path = $2 AND secret_key = $3
        RETURNING id, mount, path, secret_key, encrypted_value, cipher_algorithm, version, created_at, updated_at, deleted_at
        "#,
    )
    .bind(&mount)
    .bind(&secret_path)
    .bind(&key)
    .bind(&encrypted.payload)
    .bind(&encrypted.algorithm)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(SecretWriteResponse {
        mount: row.mount,
        path: row.path,
        key: row.secret_key,
        version: row.version,
    }))
}

async fn delete_secret(
    headers: HeaderMap,
    Path((mount, path)): Path<(String, String)>,
    State(state): State<AppState>,
) -> std::result::Result<StatusCode, ApiError> {
    let (secret_path, key) = split_secret_path(&path)?;
    authorize_path(&headers, &state, &mount, &secret_path).await?;

    let result = sqlx::query(
        r#"
        WITH latest AS (
            SELECT id
            FROM secrets
            WHERE mount = $1 AND path = $2 AND secret_key = $3
            ORDER BY version DESC
            LIMIT 1
        )
        UPDATE secrets
        SET deleted_at = NOW(), updated_at = NOW()
        WHERE id IN (SELECT id FROM latest)
          AND deleted_at IS NULL
        "#,
    )
    .bind(&mount)
    .bind(&secret_path)
    .bind(&key)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("secret not found"));
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn undelete_secret(
    headers: HeaderMap,
    Path((mount, path)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(payload): Json<SecretVersionActionRequest>,
) -> std::result::Result<StatusCode, ApiError> {
    let (secret_path, key) = split_secret_path(&path)?;
    authorize_path(&headers, &state, &mount, &secret_path).await?;
    let versions = normalize_requested_versions(payload.versions)?;

    ensure_secret_versions_exist(&state.pool, &mount, &secret_path, &key, &versions).await?;

    sqlx::query(
        r#"
        UPDATE secrets
        SET deleted_at = NULL, updated_at = NOW()
        WHERE mount = $1
          AND path = $2
          AND secret_key = $3
          AND version = ANY($4)
          AND deleted_at IS NOT NULL
        "#,
    )
    .bind(&mount)
    .bind(&secret_path)
    .bind(&key)
    .bind(&versions)
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn destroy_secret(
    headers: HeaderMap,
    Path((mount, path)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(payload): Json<SecretVersionActionRequest>,
) -> std::result::Result<StatusCode, ApiError> {
    let (secret_path, key) = split_secret_path(&path)?;
    authorize_path(&headers, &state, &mount, &secret_path).await?;
    let versions = normalize_requested_versions(payload.versions)?;

    ensure_secret_versions_exist(&state.pool, &mount, &secret_path, &key, &versions).await?;

    sqlx::query(
        r#"
        DELETE FROM secrets
        WHERE mount = $1
          AND path = $2
          AND secret_key = $3
          AND version = ANY($4)
        "#,
    )
    .bind(&mount)
    .bind(&secret_path)
    .bind(&key)
    .bind(&versions)
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn delete_token(
    headers: HeaderMap,
    Path(token_id): Path<Uuid>,
    State(state): State<AppState>,
) -> std::result::Result<StatusCode, ApiError> {
    let auth = authorize_admin(&headers, &state).await?;
    if auth.token_id == token_id {
        return Err(ApiError::bad_request(
            "cannot delete the token used for this request",
        ));
    }

    let result = sqlx::query(
        r#"
        DELETE FROM service_tokens
        WHERE id = $1
        "#,
    )
    .bind(token_id)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("token not found"));
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn load_latest_secret_row(
    pool: &PgPool,
    mount: &str,
    path: &str,
    key: &str,
) -> std::result::Result<Option<SecretRow>, ApiError> {
    sqlx::query_as::<_, SecretRow>(
        r#"
        SELECT id, mount, path, secret_key, encrypted_value, cipher_algorithm, version, created_at, updated_at, deleted_at
        FROM secrets
        WHERE mount = $1 AND path = $2 AND secret_key = $3
        ORDER BY version DESC
        LIMIT 1
        "#,
    )
    .bind(mount)
    .bind(path)
    .bind(key)
    .fetch_optional(pool)
    .await
    .map_err(ApiError::from)
}

async fn load_secret_version_row(
    pool: &PgPool,
    mount: &str,
    path: &str,
    key: &str,
    version: i32,
) -> std::result::Result<Option<SecretRow>, ApiError> {
    sqlx::query_as::<_, SecretRow>(
        r#"
        SELECT id, mount, path, secret_key, encrypted_value, cipher_algorithm, version, created_at, updated_at, deleted_at
        FROM secrets
        WHERE mount = $1 AND path = $2 AND secret_key = $3 AND version = $4
        "#,
    )
    .bind(mount)
    .bind(path)
    .bind(key)
    .bind(version)
    .fetch_optional(pool)
    .await
    .map_err(ApiError::from)
}

async fn load_all_secret_versions(
    pool: &PgPool,
    mount: &str,
    path: &str,
    key: &str,
) -> std::result::Result<Vec<SecretRow>, ApiError> {
    sqlx::query_as::<_, SecretRow>(
        r#"
        SELECT id, mount, path, secret_key, encrypted_value, cipher_algorithm, version, created_at, updated_at, deleted_at
        FROM secrets
        WHERE mount = $1 AND path = $2 AND secret_key = $3
        ORDER BY version DESC
        "#,
    )
    .bind(mount)
    .bind(path)
    .bind(key)
    .fetch_all(pool)
    .await
    .map_err(ApiError::from)
}

async fn decrypt_secret_row(
    state: &AppState,
    row: &SecretRow,
) -> std::result::Result<String, ApiError> {
    state
        .cipher
        .decrypt(&CiphertextEnvelope {
            algorithm: row.cipher_algorithm.clone(),
            payload: row.encrypted_value.clone(),
        })
        .await
        .map_err(|err| ApiError::internal(format!("decrypt failed: {err}")))
}

async fn ensure_secret_versions_exist(
    pool: &PgPool,
    mount: &str,
    path: &str,
    key: &str,
    versions: &[i32],
) -> std::result::Result<(), ApiError> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM secrets
        WHERE mount = $1
          AND path = $2
          AND secret_key = $3
          AND version = ANY($4)
        "#,
    )
    .bind(mount)
    .bind(path)
    .bind(key)
    .bind(versions.to_vec())
    .fetch_one(pool)
    .await?;

    if count != versions.len() as i64 {
        return Err(ApiError::not_found("secret version not found"));
    }

    Ok(())
}

async fn load_token_metadata(
    pool: &PgPool,
    row: ServiceTokenRow,
) -> std::result::Result<TokenMetadata, ApiError> {
    let scopes = sqlx::query_as::<_, TokenPolicyRow>(
        r#"
        SELECT mount, path_prefix
        FROM service_token_policies
        WHERE token_id = $1
        ORDER BY mount ASC, path_prefix ASC
        "#,
    )
    .bind(row.id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|scope| TokenScope {
        mount: scope.mount,
        path_prefix: scope.path_prefix,
    })
    .collect();

    Ok(TokenMetadata {
        id: row.id,
        label: row.label,
        admin: row.is_admin,
        expires_at: row.expires_at,
        scopes,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

async fn load_initialized_at(
    pool: &PgPool,
) -> std::result::Result<Option<chrono::DateTime<chrono::Utc>>, ApiError> {
    sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
        r#"
        SELECT initialized_at
        FROM system_state
        WHERE id = 1
        "#,
    )
    .fetch_optional(pool)
    .await
    .map(|row| row.flatten())
    .map_err(ApiError::from)
}

async fn is_initialized(pool: &PgPool) -> std::result::Result<bool, ApiError> {
    Ok(load_initialized_at(pool).await?.is_some())
}

async fn load_root_token_id(pool: &PgPool) -> std::result::Result<Option<Uuid>, ApiError> {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT id
        FROM service_tokens
        WHERE bootstrap_slot = 1
        "#,
    )
    .fetch_optional(pool)
    .await
    .map_err(ApiError::from)
}

async fn authorize_admin(
    headers: &HeaderMap,
    state: &AppState,
) -> std::result::Result<AuthContext, ApiError> {
    let auth = authenticate(headers, state).await?;
    if !auth.is_admin {
        return Err(ApiError::forbidden("admin token required"));
    }
    Ok(auth)
}

async fn authorize_root(
    headers: &HeaderMap,
    state: &AppState,
) -> std::result::Result<AuthContext, ApiError> {
    let auth = authenticate(headers, state).await?;
    let root_id = load_root_token_id(&state.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("root token not found"))?;

    if auth.token_id != root_id {
        return Err(ApiError::forbidden("root token required"));
    }

    Ok(auth)
}

async fn authorize_path(
    headers: &HeaderMap,
    state: &AppState,
    mount: &str,
    path: &str,
) -> std::result::Result<AuthContext, ApiError> {
    let auth = authenticate(headers, state).await?;
    if auth.is_admin {
        return Ok(auth);
    }

    let allowed = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM service_token_policies
            WHERE token_id = $1
              AND mount = $2
              AND (
                path_prefix = ''
                OR $3 = path_prefix
                OR $3 LIKE path_prefix || '/%'
              )
        )
        "#,
    )
    .bind(auth.token_id)
    .bind(mount)
    .bind(normalize_path_prefix(path))
    .fetch_one(&state.pool)
    .await?;

    if !allowed {
        return Err(ApiError::forbidden("token is not allowed for this path"));
    }

    Ok(auth)
}

async fn authenticate(
    headers: &HeaderMap,
    state: &AppState,
) -> std::result::Result<AuthContext, ApiError> {
    if !is_initialized(&state.pool).await? {
        return Err(ApiError::service_unavailable(
            "server is not initialized; call POST /api/v1/sys/init",
        ));
    }

    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing authorization header"))?;

    let Some(token) = auth.strip_prefix("Bearer ") else {
        return Err(ApiError::unauthorized("expected Bearer token"));
    };

    let row = sqlx::query_as::<_, ServiceTokenRow>(
        r#"
        SELECT id, label, is_admin, expires_at, created_at, updated_at
        FROM service_tokens
        WHERE token_hash = $1
          AND (expires_at IS NULL OR expires_at > NOW())
        "#,
    )
    .bind(hash_token(token.trim()))
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::unauthorized("token rejected"))?;

    let ServiceTokenRow { id, is_admin, .. } = row;

    Ok(AuthContext {
        token_id: id,
        is_admin,
    })
}

fn split_secret_path(raw: &str) -> std::result::Result<(String, String), ApiError> {
    let normalized = raw.trim_matches('/');
    if normalized.is_empty() {
        return Err(ApiError::bad_request("secret path cannot be empty"));
    }

    let mut parts = normalized.rsplitn(2, '/');
    let key = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or("").to_string();

    if key.is_empty() {
        return Err(ApiError::bad_request("secret key cannot be empty"));
    }

    Ok((path, key))
}

fn normalize_path_prefix(value: &str) -> String {
    value.trim_matches('/').to_string()
}

fn normalize_requested_versions(values: Vec<i32>) -> std::result::Result<Vec<i32>, ApiError> {
    if values.is_empty() {
        return Err(ApiError::bad_request("at least one version is required"));
    }

    let mut versions = values;
    if versions.iter().any(|version| *version <= 0) {
        return Err(ApiError::bad_request("version must be greater than zero"));
    }

    versions.sort_unstable();
    versions.dedup();
    Ok(versions)
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    format!("{digest:x}")
}

fn new_root_token() -> String {
    format!("se_root_{}", Uuid::new_v4().simple())
}

fn new_recovery_key() -> String {
    format!(
        "se_recovery_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(value: sqlx::Error) -> Self {
        Self::internal(format!("database error: {value}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = Json(ErrorResponse {
            error: self.message,
        });
        (self.status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AppState, ListQuery, ReadQuery, SecretVersionActionRequest, SecretWriteRequest,
        authorize_path, delete_secret, destroy_secret, hash_token, init_system, list_secrets,
        normalize_path_prefix, normalize_requested_versions, read_secret, read_secret_metadata,
        read_system_init_status, recover_root, revoke_root, rotate_root, split_secret_path,
        undelete_secret, validate_token, write_secret,
    };
    use axum::{
        Json,
        extract::{Path, Query, State},
        http::{HeaderMap, HeaderValue, StatusCode, header},
    };
    use secret_engine_core::crypto::AesGcmCipher;
    use secret_engine_core::model::SystemRootRecoverRequest;
    use sqlx::PgPool;
    use std::sync::Arc;
    use uuid::Uuid;

    #[test]
    fn split_secret_path_supports_nested_paths() {
        let (path, key) = split_secret_path("apps/demo/password").expect("path should parse");
        assert_eq!(path, "apps/demo");
        assert_eq!(key, "password");
    }

    #[test]
    fn split_secret_path_allows_root_key() {
        let (path, key) = split_secret_path("token").expect("root key should parse");
        assert_eq!(path, "");
        assert_eq!(key, "token");
    }

    #[test]
    fn split_secret_path_rejects_empty_input() {
        let error = split_secret_path("/").expect_err("empty path should fail");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.message, "secret path cannot be empty");
    }

    #[test]
    fn normalize_path_prefix_trims_slashes() {
        assert_eq!(normalize_path_prefix("/apps/demo/"), "apps/demo");
        assert_eq!(normalize_path_prefix("///"), "");
    }

    #[test]
    fn normalize_requested_versions_sorts_and_deduplicates() {
        let versions = normalize_requested_versions(vec![3, 1, 3, 2]).expect("versions valid");
        assert_eq!(versions, vec![1, 2, 3]);
    }

    #[test]
    fn normalize_requested_versions_rejects_invalid_values() {
        let empty = normalize_requested_versions(vec![]).expect_err("empty should fail");
        assert_eq!(empty.status, StatusCode::BAD_REQUEST);

        let non_positive = normalize_requested_versions(vec![1, 0]).expect_err("0 should fail");
        assert_eq!(non_positive.status, StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn kv_version_lifecycle(pool: PgPool) {
        let state = test_state(pool);
        let headers = admin_headers(&state.pool).await;
        let mount = "kv".to_string();
        let secret = "apps/demo/password".to_string();

        let first = write_secret(
            headers.clone(),
            Path((mount.clone(), secret.clone())),
            State(state.clone()),
            Json(SecretWriteRequest {
                value: "value-v1".to_string(),
            }),
        )
        .await
        .expect("first write");
        assert_eq!(first.0.version, 1);

        let second = write_secret(
            headers.clone(),
            Path((mount.clone(), secret.clone())),
            State(state.clone()),
            Json(SecretWriteRequest {
                value: "value-v2".to_string(),
            }),
        )
        .await
        .expect("second write");
        assert_eq!(second.0.version, 2);

        let latest = read_secret(
            headers.clone(),
            Path((mount.clone(), secret.clone())),
            Query(ReadQuery { version: None }),
            State(state.clone()),
        )
        .await
        .expect("read latest");
        assert_eq!(latest.0.value, "value-v2");
        assert_eq!(latest.0.version, 2);
        assert_eq!(latest.0.current_version, 2);

        let historical = read_secret(
            headers.clone(),
            Path((mount.clone(), secret.clone())),
            Query(ReadQuery { version: Some(1) }),
            State(state.clone()),
        )
        .await
        .expect("read historical");
        assert_eq!(historical.0.value, "value-v1");
        assert_eq!(historical.0.version, 1);
        assert_eq!(historical.0.current_version, 2);

        let listed = list_secrets(
            headers.clone(),
            Path(mount.clone()),
            Query(ListQuery {
                prefix: Some("apps/".to_string()),
            }),
            State(state.clone()),
        )
        .await
        .expect("list secrets");
        assert_eq!(listed.0.items.len(), 1);
        assert_eq!(listed.0.items[0].version, 2);

        delete_secret(
            headers.clone(),
            Path((mount.clone(), secret.clone())),
            State(state.clone()),
        )
        .await
        .expect("delete latest");

        let deleted_read = read_secret(
            headers.clone(),
            Path((mount.clone(), secret.clone())),
            Query(ReadQuery { version: None }),
            State(state.clone()),
        )
        .await
        .expect_err("deleted secret should not read");
        assert_eq!(deleted_read.status, StatusCode::NOT_FOUND);

        let metadata = read_secret_metadata(
            headers.clone(),
            Path((mount.clone(), secret.clone())),
            State(state.clone()),
        )
        .await
        .expect("read metadata");
        assert_eq!(metadata.0.latest_version, 2);
        assert_eq!(metadata.0.current_version, None);

        undelete_secret(
            headers.clone(),
            Path((mount.clone(), secret.clone())),
            State(state.clone()),
            Json(SecretVersionActionRequest { versions: vec![2] }),
        )
        .await
        .expect("undelete version");

        let restored = read_secret(
            headers.clone(),
            Path((mount.clone(), secret.clone())),
            Query(ReadQuery { version: None }),
            State(state.clone()),
        )
        .await
        .expect("restored read");
        assert_eq!(restored.0.value, "value-v2");

        destroy_secret(
            headers,
            Path((mount.clone(), secret.clone())),
            State(state.clone()),
            Json(SecretVersionActionRequest { versions: vec![1] }),
        )
        .await
        .expect("destroy historical");

        let metadata_after_destroy = read_secret_metadata(
            admin_headers(&state.pool).await,
            Path((mount.clone(), secret.clone())),
            State(state.clone()),
        )
        .await
        .expect("metadata after destroy");
        assert!(
            metadata_after_destroy
                .0
                .versions
                .iter()
                .all(|v| v.version != 1)
        );

        let destroyed_read = read_secret(
            admin_headers(&state.pool).await,
            Path((mount, secret)),
            Query(ReadQuery { version: Some(1) }),
            State(state),
        )
        .await
        .expect_err("destroyed version should not read");
        assert_eq!(destroyed_read.status, StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn authorize_path_enforces_token_scope(pool: PgPool) {
        let state = test_state(pool.clone());
        mark_initialized(&pool).await;

        let token_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO service_tokens (id, label, token_hash, is_admin)
            VALUES ($1, $2, $3, FALSE)
            "#,
        )
        .bind(token_id)
        .bind("scoped-token")
        .bind(hash_token("scoped"))
        .execute(&pool)
        .await
        .expect("insert scoped token");

        sqlx::query(
            r#"
            INSERT INTO service_token_policies (token_id, mount, path_prefix)
            VALUES ($1, 'kv', 'apps/demo')
            "#,
        )
        .bind(token_id)
        .execute(&pool)
        .await
        .expect("insert policy");

        let headers = bearer_headers("scoped");
        authorize_path(&headers, &state, "kv", "apps/demo/feature")
            .await
            .expect("path should be allowed");

        let denied = authorize_path(&headers, &state, "kv", "apps/prod")
            .await
            .expect_err("path should be denied");
        assert_eq!(denied.status, StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn init_flow_is_idempotent_and_gates_auth(pool: PgPool) {
        let state = test_state(pool.clone());

        let status_before = read_system_init_status(State(state.clone()))
            .await
            .expect("status before init");
        assert!(!status_before.0.initialized);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer not-yet-valid"),
        );
        let blocked = validate_token(headers, State(state.clone()))
            .await
            .expect_err("validate should fail before init");
        assert_eq!(blocked.status, StatusCode::SERVICE_UNAVAILABLE);

        let init_response = init_system(State(state.clone())).await.expect("initialize");
        assert!(init_response.0.root_token.starts_with("se_root_"));
        assert!(init_response.0.recovery_key.starts_with("se_recovery_"));

        let second_init = init_system(State(state.clone()))
            .await
            .expect_err("second init should fail");
        assert_eq!(second_init.status, StatusCode::CONFLICT);

        let status_after = read_system_init_status(State(state.clone()))
            .await
            .expect("status after init");
        assert!(status_after.0.initialized);

        let headers = bearer_headers(&init_response.0.root_token);
        let valid = validate_token(headers, State(state))
            .await
            .expect("root token should validate");
        assert_eq!(valid, StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn root_rotate_recover_revoke_lifecycle(pool: PgPool) {
        let state = test_state(pool.clone());
        let init_response = init_system(State(state.clone())).await.expect("initialize");

        let root_headers = bearer_headers(&init_response.0.root_token);
        let rotated = rotate_root(root_headers.clone(), State(state.clone()))
            .await
            .expect("rotate root");
        assert!(rotated.0.root_token.starts_with("se_root_"));
        assert!(rotated.0.recovery_key.starts_with("se_recovery_"));

        let old_root_validate = validate_token(root_headers, State(state.clone()))
            .await
            .expect_err("old root token should fail");
        assert_eq!(old_root_validate.status, StatusCode::UNAUTHORIZED);

        let rotated_headers = bearer_headers(&rotated.0.root_token);
        let valid_rotated = validate_token(rotated_headers.clone(), State(state.clone()))
            .await
            .expect("rotated root should validate");
        assert_eq!(valid_rotated, StatusCode::NO_CONTENT);

        revoke_root(rotated_headers.clone(), State(state.clone()))
            .await
            .expect("revoke root");
        let revoked_validate = validate_token(rotated_headers, State(state.clone()))
            .await
            .expect_err("revoked root should fail");
        assert_eq!(revoked_validate.status, StatusCode::UNAUTHORIZED);

        let recovered = recover_root(
            State(state.clone()),
            Json(SystemRootRecoverRequest {
                recovery_key: rotated.0.recovery_key,
            }),
        )
        .await
        .expect("recover root");
        let recovered_headers = bearer_headers(&recovered.0.root_token);
        let recovered_valid = validate_token(recovered_headers, State(state))
            .await
            .expect("recovered root should validate");
        assert_eq!(recovered_valid, StatusCode::NO_CONTENT);
    }

    fn test_state(pool: PgPool) -> AppState {
        AppState {
            pool,
            cipher: Arc::new(AesGcmCipher::from_passphrase("test-master-key").expect("cipher")),
        }
    }

    async fn admin_headers(pool: &PgPool) -> HeaderMap {
        mark_initialized(pool).await;
        let token = format!("admin-{}", Uuid::new_v4().simple());

        sqlx::query(
            r#"
            INSERT INTO service_tokens (id, label, token_hash, is_admin)
            VALUES ($1, $2, $3, TRUE)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind("admin-token")
        .bind(hash_token(&token))
        .execute(pool)
        .await
        .expect("insert admin token");

        bearer_headers(&token)
    }

    async fn mark_initialized(pool: &PgPool) {
        sqlx::query(
            r#"
            UPDATE system_state
            SET initialized_at = NOW(), updated_at = NOW()
            WHERE id = 1
            "#,
        )
        .execute(pool)
        .await
        .expect("mark initialized");
    }

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let value = HeaderValue::from_str(&format!("Bearer {token}")).expect("header");
        headers.insert(header::AUTHORIZATION, value);
        headers
    }
}
