use crate::error::{Result, StegoError};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

pub const SALT_LENGTH: usize = 16;
pub const IV_LENGTH: usize = 12;
pub const PBKDF2_ITERATIONS: u32 = 10_000;

pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_iv() -> [u8; IV_LENGTH] {
    let mut iv = [0u8; IV_LENGTH];
    OsRng.fill_bytes(&mut iv);
    iv
}

pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

pub fn encrypt(data: &[u8], password: &str, salt: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let key_bytes = derive_key(password, salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);

    cipher
        .encrypt(nonce, data)
        .map_err(|_| StegoError::DecryptionFailed)
}

pub fn decrypt(ciphertext: &[u8], password: &str, salt: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let key_bytes = derive_key(password, salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| StegoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Top secret warfare message 123!";
        let password = "super_secure_password";
        let salt = generate_salt();
        let iv = generate_iv();

        let encrypted = encrypt(plaintext, password, &salt, &iv).expect("Encryption failed");
        assert_ne!(encrypted, plaintext);

        let decrypted = decrypt(&encrypted, password, &salt, &iv).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_invalid_password() {
        let plaintext = b"Secret data";
        let salt = generate_salt();
        let iv = generate_iv();
        let encrypted = encrypt(plaintext, "correct_pass", &salt, &iv).unwrap();

        assert!(decrypt(&encrypted, "wrong_pass", &salt, &iv).is_err());
    }
}
