use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failure")]
    Encrypt,
    #[error("decryption failure")]
    Decrypt,
    #[error("invalid payload format")]
    InvalidPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextEnvelope {
    pub algorithm: String,
    pub payload: String,
}

#[async_trait]
pub trait SecretCipher: Send + Sync {
    async fn encrypt(&self, plaintext: &str) -> Result<CiphertextEnvelope, CryptoError>;
    async fn decrypt(&self, envelope: &CiphertextEnvelope) -> Result<String, CryptoError>;
}

#[derive(Debug, Clone)]
pub struct AesGcmCipher {
    key: [u8; 32],
}

impl AesGcmCipher {
    pub fn from_passphrase(passphrase: &str) -> Self {
        let digest = Sha256::digest(passphrase.as_bytes());
        let mut key = [0_u8; 32];
        key.copy_from_slice(&digest);
        Self { key }
    }

    fn engine(&self) -> Aes256Gcm {
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&self.key);
        Aes256Gcm::new(key)
    }
}

#[async_trait]
impl SecretCipher for AesGcmCipher {
    async fn encrypt(&self, plaintext: &str) -> Result<CiphertextEnvelope, CryptoError> {
        let mut nonce_bytes = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = self.engine();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| CryptoError::Encrypt)?;

        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&encrypted);

        Ok(CiphertextEnvelope {
            algorithm: "aes-256-gcm".to_string(),
            payload: BASE64.encode(combined),
        })
    }

    async fn decrypt(&self, envelope: &CiphertextEnvelope) -> Result<String, CryptoError> {
        if envelope.algorithm != "aes-256-gcm" {
            return Err(CryptoError::InvalidPayload);
        }

        let bytes = BASE64
            .decode(envelope.payload.as_bytes())
            .map_err(|_| CryptoError::InvalidPayload)?;
        if bytes.len() < 13 {
            return Err(CryptoError::InvalidPayload);
        }

        let (nonce_bytes, ciphertext) = bytes.split_at(12);
        let cipher = self.engine();
        let nonce = Nonce::from_slice(nonce_bytes);
        let decrypted = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::Decrypt)?;

        String::from_utf8(decrypted).map_err(|_| CryptoError::InvalidPayload)
    }
}
