use crate::crypto::{self, IV_LENGTH, SALT_LENGTH};
use crate::error::{Result, StegoError};

pub const CHAR_ZERO: char = '\u{200C}';   // Bit 0 (ZWNJ)
pub const CHAR_ONE: char = '\u{200D}';    // Bit 1 (ZWJ)
pub const CHAR_DELIM: char = '\u{2060}';  // Delimiter (Word Joiner)
pub const CHAR_HEADER: char = '\u{FEFF}'; // Magic Header (BOM / ZWNBSP)

pub const SIGNATURE: [u8; 4] = *b"SLOP";

pub fn has_hidden_data(text: &str) -> bool {
    if let Some(idx) = text.find(CHAR_HEADER) {
        if let Some(next) = text[idx + CHAR_HEADER.len_utf8()..].chars().next() {
            return next == CHAR_ZERO || next == CHAR_ONE || next == CHAR_DELIM;
        }
    }
    false
}

pub fn encode(cover_text: &str, secret_data: &[u8], password: Option<&str>) -> Result<String> {
    let is_encrypted = password.map_or(false, |p| !p.is_empty());
    let (payload, flags) = if is_encrypted {
        let salt = crypto::generate_salt();
        let iv = crypto::generate_iv();
        let cipher_text = crypto::encrypt(secret_data, password.unwrap(), &salt, &iv)?;
        let mut p = Vec::with_capacity(SALT_LENGTH + IV_LENGTH + cipher_text.len());
        p.extend_from_slice(&salt);
        p.extend_from_slice(&iv);
        p.extend_from_slice(&cipher_text);
        (p, 0x01u8)
    } else {
        (secret_data.to_vec(), 0x00u8)
    };

    let total_size = SIGNATURE.len() + 1 + 4 + payload.len();
    let mut packet = Vec::with_capacity(total_size);
    packet.extend_from_slice(&SIGNATURE);
    packet.push(flags);
    packet.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    packet.extend_from_slice(&payload);

    let mut zw_str = String::new();
    zw_str.push(CHAR_HEADER);

    for b in packet {
        for bit in (0..8).rev() {
            if ((b >> bit) & 1) == 1 {
                zw_str.push(CHAR_ONE);
            } else {
                zw_str.push(CHAR_ZERO);
            }
        }
    }
    zw_str.push(CHAR_DELIM);

    // Insert after first space/punctuation or append
    if let Some(pos) = cover_text.find(|c: char| c.is_whitespace() || c.is_ascii_punctuation()) {
        let insert_idx = pos + cover_text[pos..].chars().next().unwrap().len_utf8();
        let mut result = String::with_capacity(cover_text.len() + zw_str.len());
        result.push_str(&cover_text[..insert_idx]);
        result.push_str(&zw_str);
        result.push_str(&cover_text[insert_idx..]);
        Ok(result)
    } else {
        let mut result = String::with_capacity(cover_text.len() + zw_str.len());
        result.push_str(cover_text);
        result.push_str(&zw_str);
        Ok(result)
    }
}

pub fn decode(stego_text: &str, password: Option<&str>) -> Result<Vec<u8>> {
    let header_idx = stego_text
        .find(CHAR_HEADER)
        .ok_or_else(|| StegoError::ZeroWidthError("No zero-width stego header found".into()))?;

    let content_start = header_idx + CHAR_HEADER.len_utf8();
    let sub = &stego_text[content_start..];
    let delim_idx = sub
        .find(CHAR_DELIM)
        .ok_or_else(|| StegoError::ZeroWidthError("No zero-width delimiter found".into()))?;

    let zw_bits = &sub[..delim_idx];

    let mut bits = Vec::new();
    for c in zw_bits.chars() {
        if c == CHAR_ZERO {
            bits.push(0u8);
        } else if c == CHAR_ONE {
            bits.push(1u8);
        }
    }

    if bits.len() < 8 {
        return Err(StegoError::ZeroWidthError("Insufficient zero-width data".into()));
    }

    let byte_count = bits.len() / 8;
    let mut packet = Vec::with_capacity(byte_count);

    for i in 0..byte_count {
        let mut byte_val = 0u8;
        for b in 0..8 {
            byte_val = (byte_val << 1) | bits[i * 8 + b];
        }
        packet.push(byte_val);
    }

    if packet.len() < 9 {
        return Err(StegoError::ZeroWidthError("Packet too short".into()));
    }

    if &packet[0..4] != &SIGNATURE {
        return Err(StegoError::InvalidMagic);
    }

    let flags = packet[4];
    let is_encrypted = (flags & 0x01) != 0;
    let payload_len = u32::from_be_bytes(packet[5..9].try_into().unwrap()) as usize;

    if packet.len() < 9 + payload_len {
        return Err(StegoError::ContainerTruncated {
            expected: payload_len,
            found: packet.len().saturating_sub(9),
        });
    }

    let payload = &packet[9..9 + payload_len];

    if is_encrypted {
        let pwd = password.ok_or(StegoError::PasswordRequired)?;
        if payload.len() < SALT_LENGTH + IV_LENGTH {
            return Err(StegoError::ContainerTruncated {
                expected: SALT_LENGTH + IV_LENGTH,
                found: payload.len(),
            });
        }
        let salt = &payload[..SALT_LENGTH];
        let iv = &payload[SALT_LENGTH..SALT_LENGTH + IV_LENGTH];
        let cipher_text = &payload[SALT_LENGTH + IV_LENGTH..];
        crypto::decrypt(cipher_text, pwd, salt, iv)
    } else {
        Ok(payload.to_vec())
    }
}

pub fn strip_hidden_data(text: &str) -> String {
    text.chars()
        .filter(|&c| c != CHAR_HEADER && c != CHAR_ZERO && c != CHAR_ONE && c != CHAR_DELIM)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_width_plain() {
        let cover = "O-oooooooooo AAAAE-A-A-I-A-U- JO-oooooooooooo";
        let secret = b"Brain Power secret message!";

        let encoded = encode(cover, secret, None).unwrap();
        assert!(has_hidden_data(&encoded));

        let decoded = decode(&encoded, None).unwrap();
        assert_eq!(decoded, secret);

        let clean = strip_hidden_data(&encoded);
        assert_eq!(clean, cover);
    }

    #[test]
    fn test_zero_width_encrypted() {
        let cover = "Classified operative report.";
        let secret = b"Target location: 44.5N 39.8E";

        let encoded = encode(cover, secret, Some("warfare_bismuth")).unwrap();
        assert!(has_hidden_data(&encoded));

        let decoded = decode(&encoded, Some("warfare_bismuth")).unwrap();
        assert_eq!(decoded, secret);
    }
}
