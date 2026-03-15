use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const LEGACY_ALGORITHM: &str = "aes-256-gcm";
const CURRENT_ALGORITHM: &str = "aes-256-gcm+argon2id-v1";
const CURRENT_KEY_ID: &str = "static-passphrase-v1";
const KDF_SALT: &[u8] = b"secret-engine-master-key-v1";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key derivation failure")]
    KeyDerivation,
    #[error("encryption failure")]
    Encrypt,
    #[error("decryption failure")]
    Decrypt,
    #[error("invalid payload format")]
    InvalidPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextEnvelope {
    pub key_id: String,
    pub algorithm: String,
    pub payload: String,
}

#[async_trait]
pub trait SecretCipher: Send + Sync {
    async fn encrypt(
        &self,
        plaintext: &str,
        key_id: &str,
    ) -> Result<CiphertextEnvelope, CryptoError>;
    async fn decrypt(&self, envelope: &CiphertextEnvelope) -> Result<String, CryptoError>;
}

#[derive(Debug, Clone)]
pub struct AesGcmCipher {
    passphrase: String,
    legacy_key: [u8; 32],
}

impl AesGcmCipher {
    pub fn from_passphrase(passphrase: &str) -> Result<Self, CryptoError> {
        let digest = Sha256::digest(passphrase.as_bytes());
        let mut legacy_key = [0_u8; 32];
        legacy_key.copy_from_slice(&digest);

        Ok(Self {
            passphrase: passphrase.to_string(),
            legacy_key,
        })
    }

    pub fn default_key_id() -> &'static str {
        CURRENT_KEY_ID
    }

    pub fn current_algorithm_for(key_id: &str) -> String {
        format!("{CURRENT_ALGORITHM}:{key_id}")
    }

    fn derive_current_key(&self, key_id: &str) -> Result<[u8; 32], CryptoError> {
        let mut key = [0_u8; 32];
        let params =
            Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| CryptoError::KeyDerivation)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut salt = KDF_SALT.to_vec();
        salt.push(b':');
        salt.extend_from_slice(key_id.as_bytes());

        argon2
            .hash_password_into(self.passphrase.as_bytes(), &salt, &mut key)
            .map_err(|_| CryptoError::KeyDerivation)?;
        Ok(key)
    }

    fn engine(key_bytes: &[u8; 32]) -> Aes256Gcm {
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key_bytes);
        Aes256Gcm::new(key)
    }

    fn encrypt_with_key(
        &self,
        plaintext: &str,
        key_bytes: &[u8; 32],
        algorithm: &str,
    ) -> Result<CiphertextEnvelope, CryptoError> {
        let mut nonce_bytes = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = Self::engine(key_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| CryptoError::Encrypt)?;

        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&encrypted);

        Ok(CiphertextEnvelope {
            key_id: key_id_from_algorithm(algorithm)
                .unwrap_or(CURRENT_KEY_ID)
                .to_string(),
            algorithm: algorithm.to_string(),
            payload: BASE64.encode(combined),
        })
    }

    fn decrypt_with_key(
        &self,
        envelope: &CiphertextEnvelope,
        key_bytes: &[u8; 32],
    ) -> Result<String, CryptoError> {
        let bytes = BASE64
            .decode(envelope.payload.as_bytes())
            .map_err(|_| CryptoError::InvalidPayload)?;
        if bytes.len() < 13 {
            return Err(CryptoError::InvalidPayload);
        }

        let (nonce_bytes, ciphertext) = bytes.split_at(12);
        let cipher = Self::engine(key_bytes);
        let nonce = Nonce::from_slice(nonce_bytes);
        let decrypted = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::Decrypt)?;

        String::from_utf8(decrypted).map_err(|_| CryptoError::InvalidPayload)
    }

    fn key_for_algorithm(&self, algorithm: &str) -> Option<&[u8; 32]> {
        if algorithm == LEGACY_ALGORITHM {
            return Some(&self.legacy_key);
        }

        None
    }
}

#[async_trait]
impl SecretCipher for AesGcmCipher {
    async fn encrypt(
        &self,
        plaintext: &str,
        key_id: &str,
    ) -> Result<CiphertextEnvelope, CryptoError> {
        let key = self.derive_current_key(key_id)?;
        self.encrypt_with_key(plaintext, &key, &Self::current_algorithm_for(key_id))
    }

    async fn decrypt(&self, envelope: &CiphertextEnvelope) -> Result<String, CryptoError> {
        if let Some(key) = self.key_for_algorithm(&envelope.algorithm) {
            return self.decrypt_with_key(envelope, key);
        }

        let expected_algorithm = Self::current_algorithm_for(&envelope.key_id);
        if envelope.algorithm != expected_algorithm {
            return Err(CryptoError::InvalidPayload);
        }

        let key = self.derive_current_key(&envelope.key_id)?;
        self.decrypt_with_key(envelope, &key)
    }
}

fn key_id_from_algorithm(algorithm: &str) -> Option<&str> {
    algorithm.split_once(':').map(|(_, key_id)| key_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_uses_versioned_argon2id_algorithm() {
        let cipher = AesGcmCipher::from_passphrase("test-passphrase").expect("cipher");
        let key = cipher
            .derive_current_key(AesGcmCipher::default_key_id())
            .expect("derive current key");
        let envelope = cipher
            .encrypt_with_key(
                "secret",
                &key,
                &AesGcmCipher::current_algorithm_for(AesGcmCipher::default_key_id()),
            )
            .expect("encrypt");

        assert_eq!(
            envelope.algorithm,
            "aes-256-gcm+argon2id-v1:static-passphrase-v1"
        );
        assert_eq!(envelope.key_id, "static-passphrase-v1");
    }

    #[test]
    fn decrypt_accepts_legacy_sha256_payloads() {
        let cipher = AesGcmCipher::from_passphrase("test-passphrase").expect("cipher");
        let envelope = cipher
            .encrypt_with_key("secret", &cipher.legacy_key, LEGACY_ALGORITHM)
            .expect("legacy encrypt");
        let plaintext = cipher
            .decrypt_with_key(&envelope, &cipher.legacy_key)
            .expect("decrypt");

        assert_eq!(plaintext, "secret");
    }

    #[test]
    fn decrypt_supports_rotated_key_ids() {
        let cipher = AesGcmCipher::from_passphrase("test-passphrase").expect("cipher");
        let key = cipher
            .derive_current_key("key-20260314")
            .expect("derive current key");
        let envelope = cipher
            .encrypt_with_key("secret", &key, "aes-256-gcm+argon2id-v1:key-20260314")
            .expect("encrypt");
        let plaintext = cipher.decrypt_with_key(&envelope, &key).expect("decrypt");

        assert_eq!(plaintext, "secret");
        assert_eq!(envelope.algorithm, "aes-256-gcm+argon2id-v1:key-20260314");
        assert_eq!(envelope.key_id, "key-20260314");
    }
}
