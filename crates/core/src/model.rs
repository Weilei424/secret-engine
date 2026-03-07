use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub id: Uuid,
    pub mount: String,
    pub path: String,
    pub key: String,
    pub encrypted_value: String,
    pub cipher_algorithm: String,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub mount: String,
    pub path: String,
    pub key: String,
    pub version: i32,
    pub current_version: i32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersionMetadata {
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadataResponse {
    pub mount: String,
    pub path: String,
    pub key: String,
    pub latest_version: i32,
    pub current_version: Option<i32>,
    pub versions: Vec<SecretVersionMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretWriteRequest {
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretWriteResponse {
    pub mount: String,
    pub path: String,
    pub key: String,
    pub version: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretReadResponse {
    pub mount: String,
    pub path: String,
    pub key: String,
    pub value: String,
    pub version: i32,
    pub current_version: i32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretListResponse {
    pub items: Vec<SecretMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersionActionRequest {
    pub versions: Vec<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenScope {
    pub mount: String,
    pub path_prefix: String,
    #[serde(default = "default_policy_capabilities")]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCreateRequest {
    pub label: String,
    pub admin: bool,
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub scopes: Vec<TokenScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    pub id: Uuid,
    pub label: String,
    pub admin: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<TokenScope>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCreateResponse {
    pub token: String,
    pub metadata: TokenMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenListResponse {
    pub items: Vec<TokenMetadata>,
}

fn default_policy_capabilities() -> Vec<String> {
    vec![
        "read".to_string(),
        "list".to_string(),
        "write".to_string(),
        "delete".to_string(),
        "undelete".to_string(),
        "destroy".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInitStatusResponse {
    pub initialized: bool,
    pub initialized_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInitResponse {
    pub root_token: String,
    pub recovery_key: String,
    pub initialized_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemRootRotateResponse {
    pub root_token: String,
    pub recovery_key: String,
    pub rotated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemRootRecoverRequest {
    pub recovery_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemRootRecoverResponse {
    pub root_token: String,
    pub recovery_key: String,
    pub recovered_at: DateTime<Utc>,
}
