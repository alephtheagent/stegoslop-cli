use thiserror::Error;

#[derive(Error, Debug)]
pub enum StegoError {
    #[error("Container too short: {0} bytes")]
    ContainerTooShort(usize),

    #[error("Invalid magic bytes: expected 'SLOP'")]
    InvalidMagic,

    #[error("Unknown payload type code: {0}")]
    UnknownPayloadType(u8),

    #[error("Unsupported bits per unit: {0}. Must be 1, 2, or 4.")]
    UnsupportedBitsPerUnit(usize),

    #[error("Container truncated: expected {expected} payload bytes, found {found}")]
    ContainerTruncated { expected: usize, found: usize },

    #[error("CRC32 checksum mismatch: expected {expected:#010x}, got {actual:#010x}")]
    CrcMismatch { expected: u32, actual: u32 },

    #[error("Password required for encrypted payload")]
    PasswordRequired,

    #[error("Decryption failed: invalid password or corrupted data")]
    DecryptionFailed,

    #[error("Payload size ({payload_size} bytes) exceeds carrier capacity ({capacity} bytes)")]
    CapacityExceeded { payload_size: usize, capacity: usize },

    #[error("Carrier too small to contain SLOP header")]
    CarrierTooSmall,

    #[error("Invalid WAV file: {0}")]
    InvalidWav(String),

    #[error("Invalid image: {0}")]
    InvalidImage(String),

    #[error("Zero-width stego error: {0}")]
    ZeroWidthError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StegoError>;
