use crate::crypto::{self, IV_LENGTH, SALT_LENGTH};
use crate::error::{Result, StegoError};
use crc32fast::Hasher;

pub const MAGIC_BYTES: [u8; 4] = *b"SLOP";
pub const HEADER_MIN_LENGTH: usize = 14;
pub const FLAG_ENCRYPTED: u8 = 0x01;
pub const FLAG_HAS_FILENAME: u8 = 0x08;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    Text = 0x01,
    Image = 0x02,
    Audio = 0x03,
    File = 0x04,
}

impl PayloadType {
    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            0x01 => Ok(PayloadType::Text),
            0x02 => Ok(PayloadType::Image),
            0x03 => Ok(PayloadType::Audio),
            0x04 => Ok(PayloadType::File),
            other => Err(StegoError::UnknownPayloadType(other)),
        }
    }

    pub fn code(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackedPayload {
    pub payload_type: PayloadType,
    pub data: Vec<u8>,
    pub is_encrypted: bool,
    pub bits_per_unit: usize,
    pub file_name: Option<String>,
    pub is_corrupted: bool,
}

pub fn pack_payload(
    payload_type: PayloadType,
    data: &[u8],
    password: Option<&str>,
    bits_per_unit: usize,
    file_name: Option<&str>,
) -> Result<Vec<u8>> {
    let is_encrypted = password.map_or(false, |p| !p.is_empty());
    let bpu_code = match bits_per_unit {
        1 => 0u8,
        2 => 1u8,
        4 => 2u8,
        other => return Err(StegoError::UnsupportedBitsPerUnit(other)),
    };

    let mut flags = bpu_code << 1;
    if is_encrypted {
        flags |= FLAG_ENCRYPTED;
    }

    let file_name_bytes = if let Some(name) = file_name {
        flags |= FLAG_HAS_FILENAME;
        let bytes = name.as_bytes();
        if bytes.len() > 255 {
            return Err(StegoError::InvalidMagic); // Filename too long
        }
        Some(bytes)
    } else {
        None
    };

    let (payload_data, salt, iv) = if is_encrypted {
        let salt = crypto::generate_salt();
        let iv = crypto::generate_iv();
        let encrypted = crypto::encrypt(data, password.unwrap(), &salt, &iv)?;
        (encrypted, Some(salt), Some(iv))
    } else {
        (data.to_vec(), None, None)
    };

    let mut hasher = Hasher::new();
    hasher.update(&payload_data);
    let crc = hasher.finalize();

    let file_name_len = file_name_bytes.map_or(0, |b| 1 + b.len());
    let header_len = HEADER_MIN_LENGTH
        + if is_encrypted {
            SALT_LENGTH + IV_LENGTH
        } else {
            0
        }
        + file_name_len;
    let total_size = header_len + payload_data.len();

    let mut buffer = Vec::with_capacity(total_size);
    buffer.extend_from_slice(&MAGIC_BYTES);
    buffer.push(payload_type.code());
    buffer.push(flags);
    buffer.extend_from_slice(&(payload_data.len() as u32).to_be_bytes());
    buffer.extend_from_slice(&crc.to_be_bytes());

    if is_encrypted {
        buffer.extend_from_slice(&salt.unwrap());
        buffer.extend_from_slice(&iv.unwrap());
    }

    if let Some(bytes) = file_name_bytes {
        buffer.push(bytes.len() as u8);
        buffer.extend_from_slice(bytes);
    }

    buffer.extend_from_slice(&payload_data);
    Ok(buffer)
}

pub fn unpack_payload(container: &[u8], password: Option<&str>) -> Result<UnpackedPayload> {
    unpack_internal(container, password, false)
}

pub fn unpack_payload_forced(container: &[u8], password: Option<&str>) -> Result<UnpackedPayload> {
    unpack_internal(container, password, true)
}

fn unpack_internal(
    container: &[u8],
    password: Option<&str>,
    force: bool,
) -> Result<UnpackedPayload> {
    if container.len() < HEADER_MIN_LENGTH {
        return Err(StegoError::ContainerTooShort(container.len()));
    }

    if &container[0..4] != &MAGIC_BYTES {
        return Err(StegoError::InvalidMagic);
    }

    let payload_type = PayloadType::from_code(container[4])?;
    let flags = container[5];
    let is_encrypted = (flags & FLAG_ENCRYPTED) != 0;
    let bpu_code = (flags >> 1) & 0x03;
    let bits_per_unit = match bpu_code {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => return Err(StegoError::UnsupportedBitsPerUnit(bpu_code as usize)),
    };

    let payload_len = u32::from_be_bytes(container[6..10].try_into().unwrap()) as usize;
    let expected_crc = u32::from_be_bytes(container[10..14].try_into().unwrap());

    let mut cursor = 14;

    let salt_iv = if is_encrypted {
        if container.len() < cursor + SALT_LENGTH + IV_LENGTH {
            return Err(StegoError::ContainerTruncated {
                expected: cursor + SALT_LENGTH + IV_LENGTH,
                found: container.len(),
            });
        }
        let salt = &container[cursor..cursor + SALT_LENGTH];
        cursor += SALT_LENGTH;
        let iv = &container[cursor..cursor + IV_LENGTH];
        cursor += IV_LENGTH;
        Some((salt, iv))
    } else {
        None
    };

    let file_name = if (flags & FLAG_HAS_FILENAME) != 0 {
        if container.len() < cursor + 1 {
            return Err(StegoError::ContainerTruncated {
                expected: cursor + 1,
                found: container.len(),
            });
        }
        let fn_len = container[cursor] as usize;
        cursor += 1;
        if container.len() < cursor + fn_len {
            return Err(StegoError::ContainerTruncated {
                expected: cursor + fn_len,
                found: container.len(),
            });
        }
        let name_str = String::from_utf8_lossy(&container[cursor..cursor + fn_len]).to_string();
        cursor += fn_len;
        Some(name_str)
    } else {
        None
    };

    if container.len() < cursor + payload_len {
        return Err(StegoError::ContainerTruncated {
            expected: payload_len,
            found: container.len().saturating_sub(cursor),
        });
    }

    let raw_payload_data = &container[cursor..cursor + payload_len];

    let mut hasher = Hasher::new();
    hasher.update(raw_payload_data);
    let actual_crc = hasher.finalize();

    let mut is_corrupted = false;
    if actual_crc != expected_crc {
        if force {
            is_corrupted = true;
        } else {
            return Err(StegoError::CrcMismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }
    }

    let final_data = if is_encrypted {
        let (salt, iv) = salt_iv.unwrap();
        match password {
            Some(pwd) if !pwd.is_empty() => {
                match crypto::decrypt(raw_payload_data, pwd, salt, iv) {
                    Ok(dec) => dec,
                    Err(_) if force => {
                        is_corrupted = true;
                        raw_payload_data.to_vec()
                    }
                    Err(e) => return Err(e),
                }
            }
            _ => return Err(StegoError::PasswordRequired),
        }
    } else {
        raw_payload_data.to_vec()
    };

    Ok(UnpackedPayload {
        payload_type,
        data: final_data,
        is_encrypted,
        bits_per_unit,
        file_name,
        is_corrupted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_roundtrip() {
        let payload = b"Hello, StegoSlop in Rust!";
        let packed = pack_payload(
            PayloadType::Text,
            payload,
            None,
            2,
            Some("message.txt"),
        )
        .unwrap();

        let unpacked = unpack_payload(&packed, None).unwrap();
        assert_eq!(unpacked.payload_type, PayloadType::Text);
        assert_eq!(unpacked.data, payload);
        assert_eq!(unpacked.bits_per_unit, 2);
        assert_eq!(unpacked.file_name.as_deref(), Some("message.txt"));
        assert!(!unpacked.is_encrypted);
        assert!(!unpacked.is_corrupted);
    }

    #[test]
    fn test_encrypted_roundtrip() {
        let payload = b"Classified warfare coordinates 47.123, 39.456";
        let packed = pack_payload(
            PayloadType::Audio,
            payload,
            Some("bismuth_pass_2026"),
            1,
            Some("intel.opus"),
        )
        .unwrap();

        let unpacked = unpack_payload(&packed, Some("bismuth_pass_2026")).unwrap();
        assert_eq!(unpacked.payload_type, PayloadType::Audio);
        assert_eq!(unpacked.data, payload);
        assert_eq!(unpacked.file_name.as_deref(), Some("intel.opus"));
        assert!(unpacked.is_encrypted);
    }
}
