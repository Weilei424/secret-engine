use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result as AnyResult};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use config::{Config, Environment};
use secret_engine_core::{
    crypto::{AesGcmCipher, CiphertextEnvelope},
    model::{
        SecretListResponse, SecretMetadata, SecretReadResponse, SecretWriteRequest,
        SecretWriteResponse,
    },
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, postgres::PgPoolOptions};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
struct Settings {
    host: String,
    port: u16,
    database_url: String,
    admin_token: String,
    master_key: String,
}

impl Settings {
    fn load() -> AnyResult<Self> {
        let config = Config::builder()
            .set_default("host", "0.0.0.0")?
            .set_default("port", 8080)?
            .add_source(Environment::with_prefix("SECRET_ENGINE").separator("__"))
            .build()?;

        config.try_deserialize().context("invalid configuration")
    }
}

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    admin_token: Arc<String>,
    cipher: Arc<AesGcmCipher>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    prefix: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, FromRow)]
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
}

impl From<SecretRow> for SecretMetadata {
    fn from(value: SecretRow) -> Self {
        let _ = value.id;
        let _ = value.created_at;
        Self {
            mount: value.mount,
            path: value.path,
            key: value.secret_key,
            version: value.version,
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
        admin_token: Arc::new(settings.admin_token),
        cipher: Arc::new(AesGcmCipher::from_passphrase(&settings.master_key)),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/auth/validate", get(validate_token))
        .route("/api/v1/kv/:mount", get(list_secrets))
        .route(
            "/api/v1/kv/:mount/*path",
            get(read_secret).post(write_secret).delete(delete_secret),
        )
        .with_state(state)
        .layer(CorsLayer::permissive())
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

async fn validate_token(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> std::result::Result<StatusCode, ApiError> {
    authorize(&headers, &state)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_secrets(
    headers: HeaderMap,
    Path(mount): Path<String>,
    Query(query): Query<ListQuery>,
    State(state): State<AppState>,
) -> std::result::Result<Json<SecretListResponse>, ApiError> {
    authorize(&headers, &state)?;

    let prefix = query.prefix.unwrap_or_default();
    let like_value = if prefix.is_empty() {
        "%".to_string()
    } else {
        format!("{prefix}%")
    };

    let rows = sqlx::query_as::<_, SecretRow>(
        r#"
        SELECT id, mount, path, secret_key, encrypted_value, cipher_algorithm, version, created_at, updated_at
        FROM secrets
        WHERE mount = $1 AND path LIKE $2
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
    State(state): State<AppState>,
) -> std::result::Result<Json<SecretReadResponse>, ApiError> {
    authorize(&headers, &state)?;

    let (secret_path, key) = split_secret_path(&path)?;
    let row = sqlx::query_as::<_, SecretRow>(
        r#"
        SELECT id, mount, path, secret_key, encrypted_value, cipher_algorithm, version, created_at, updated_at
        FROM secrets
        WHERE mount = $1 AND path = $2 AND secret_key = $3
        "#,
    )
    .bind(&mount)
    .bind(&secret_path)
    .bind(&key)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("secret not found"))?;

    let value = state
        .cipher
        .decrypt(&CiphertextEnvelope {
            algorithm: row.cipher_algorithm.clone(),
            payload: row.encrypted_value.clone(),
        })
        .await
        .map_err(|err| ApiError::internal(format!("decrypt failed: {err}")))?;

    Ok(Json(SecretReadResponse {
        mount: row.mount,
        path: row.path,
        key: row.secret_key,
        value,
        version: row.version,
        updated_at: row.updated_at,
    }))
}

async fn write_secret(
    headers: HeaderMap,
    Path((mount, path)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(payload): Json<SecretWriteRequest>,
) -> std::result::Result<Json<SecretWriteResponse>, ApiError> {
    authorize(&headers, &state)?;

    let (secret_path, key) = split_secret_path(&path)?;
    let encrypted = state
        .cipher
        .encrypt(&payload.value)
        .await
        .map_err(|err| ApiError::internal(format!("encrypt failed: {err}")))?;

    let row = sqlx::query_as::<_, SecretRow>(
        r#"
        INSERT INTO secrets (mount, path, secret_key, encrypted_value, cipher_algorithm)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (mount, path, secret_key)
        DO UPDATE SET
            encrypted_value = EXCLUDED.encrypted_value,
            cipher_algorithm = EXCLUDED.cipher_algorithm,
            version = secrets.version + 1,
            updated_at = NOW()
        RETURNING id, mount, path, secret_key, encrypted_value, cipher_algorithm, version, created_at, updated_at
        "#,
    )
    .bind(&mount)
    .bind(&secret_path)
    .bind(&key)
    .bind(&encrypted.payload)
    .bind(&encrypted.algorithm)
    .fetch_one(&state.pool)
    .await?;

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
    authorize(&headers, &state)?;

    let (secret_path, key) = split_secret_path(&path)?;
    let result = sqlx::query(
        r#"
        DELETE FROM secrets
        WHERE mount = $1 AND path = $2 AND secret_key = $3
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

fn authorize(headers: &HeaderMap, state: &AppState) -> std::result::Result<(), ApiError> {
    let expected = state.admin_token.as_str();
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing authorization header"))?;

    let Some(token) = auth.strip_prefix("Bearer ") else {
        return Err(ApiError::unauthorized("expected Bearer token"));
    };

    if token != expected {
        return Err(ApiError::unauthorized("token rejected"));
    }

    Ok(())
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

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
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
