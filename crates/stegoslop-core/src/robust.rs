use crate::crypto;
use crate::error::{Result, StegoError};

pub const BLOCK_SIZE: usize = 8;
pub const DELTA: f32 = 4.5;
pub const HEADER_LEN_BYTES: usize = 11;
pub const HEADER_LEN_BITS: usize = HEADER_LEN_BYTES * 8; // 88 bits
pub const HEADER_REP: usize = 4;
pub const HEADER_BLOCKS: usize = HEADER_LEN_BITS * HEADER_REP; // 352 blocks

pub const ROBUST_MAGIC: &[u8; 4] = b"RSLP";
pub const FLAG_ENCRYPTED: u8 = 0x01;

// 8x8 2D Haar mid-frequency orthogonal pattern (cancels linear gradients, sum == 0)
pub const PATTERN: [f32; 64] = [
     1.0,  1.0, -1.0, -1.0,  1.0,  1.0, -1.0, -1.0,
     1.0,  1.0, -1.0, -1.0,  1.0,  1.0, -1.0, -1.0,
    -1.0, -1.0,  1.0,  1.0, -1.0, -1.0,  1.0,  1.0,
    -1.0, -1.0,  1.0,  1.0, -1.0, -1.0,  1.0,  1.0,
     1.0,  1.0, -1.0, -1.0,  1.0,  1.0, -1.0, -1.0,
     1.0,  1.0, -1.0, -1.0,  1.0,  1.0, -1.0, -1.0,
    -1.0, -1.0,  1.0,  1.0, -1.0, -1.0,  1.0,  1.0,
    -1.0, -1.0,  1.0,  1.0, -1.0, -1.0,  1.0,  1.0,
];

pub fn compute_robust_capacity(width: u32, height: u32, is_encrypted: bool) -> usize {
    let blocks_w = (width as usize) / BLOCK_SIZE;
    let blocks_h = (height as usize) / BLOCK_SIZE;
    let total_blocks = blocks_w * blocks_h;

    if total_blocks <= HEADER_BLOCKS {
        return 0;
    }

    let avail_bytes = (total_blocks - HEADER_BLOCKS) / 8;
    if is_encrypted {
        // 16 bytes salt + 12 bytes IV + 16 bytes GCM tag
        if avail_bytes <= 44 {
            0
        } else {
            avail_bytes - 44
        }
    } else {
        avail_bytes
    }
}

pub fn embed_robust_in_rgba(
    rgba: &mut [u8],
    width: u32,
    height: u32,
    data: &[u8],
    password: Option<&str>,
) -> Result<()> {
    let expected_len = (width as usize) * (height as usize) * 4;
    if rgba.len() != expected_len {
        return Err(StegoError::InvalidImage(format!(
            "Buffer size mismatch: expected {} bytes, got {}",
            expected_len,
            rgba.len()
        )));
    }

    let blocks_w = (width as usize) / BLOCK_SIZE;
    let blocks_h = (height as usize) / BLOCK_SIZE;
    let total_blocks = blocks_w * blocks_h;

    if total_blocks < HEADER_BLOCKS {
        return Err(StegoError::CarrierTooSmall);
    }

    let (flags, payload_bytes) = if let Some(pwd) = password.filter(|s| !s.is_empty()) {
        let salt = crypto::generate_salt();
        let iv = crypto::generate_iv();
        let ciphertext = crypto::encrypt(data, pwd, &salt, &iv)?;

        let mut payload = Vec::with_capacity(crypto::SALT_LENGTH + crypto::IV_LENGTH + ciphertext.len());
        payload.extend_from_slice(&salt);
        payload.extend_from_slice(&iv);
        payload.extend_from_slice(&ciphertext);
        (FLAG_ENCRYPTED, payload)
    } else {
        (0x00, data.to_vec())
    };

    let avail_payload_blocks = total_blocks - HEADER_BLOCKS;
    let payload_num_bits = payload_bytes.len() * 8;
    if avail_payload_blocks < payload_num_bits {
        return Err(StegoError::CapacityExceeded {
            payload_size: payload_bytes.len(),
            capacity: avail_payload_blocks / 8,
        });
    }

    let mut crc_hasher = crc32fast::Hasher::new();
    crc_hasher.update(&payload_bytes);
    let crc = crc_hasher.finalize();

    // Build 11-byte header: [MAGIC 4B] [FLAGS 1B] [LEN 2B] [CRC32 4B]
    let mut header_bytes = Vec::with_capacity(HEADER_LEN_BYTES);
    header_bytes.extend_from_slice(ROBUST_MAGIC);
    header_bytes.push(flags);
    header_bytes.extend_from_slice(&(payload_bytes.len() as u16).to_be_bytes());
    header_bytes.extend_from_slice(&crc.to_be_bytes());

    // Extract bits
    let mut header_bits = Vec::with_capacity(HEADER_LEN_BITS);
    for &b in &header_bytes {
        for bit_idx in (0..8).rev() {
            header_bits.push((b >> bit_idx) & 1);
        }
    }

    let mut payload_bits = Vec::with_capacity(payload_num_bits);
    for &b in &payload_bytes {
        for bit_idx in (0..8).rev() {
            payload_bits.push((b >> bit_idx) & 1);
        }
    }

    let w_usize = width as usize;

    // 1. Embed header (repeated HEADER_REP times)
    for b_idx in 0..HEADER_BLOCKS {
        let bit = header_bits[b_idx % HEADER_LEN_BITS];
        let sign = if bit == 1 { 1.0f32 } else { -1.0f32 };
        let bi = b_idx / blocks_w;
        let bj = b_idx % blocks_w;

        for by in 0..BLOCK_SIZE {
            let py = bi * BLOCK_SIZE + by;
            for bx in 0..BLOCK_SIZE {
                let px = bj * BLOCK_SIZE + bx;
                let offset = (py * w_usize + px) * 4;
                let delta = sign * DELTA * PATTERN[by * BLOCK_SIZE + bx];

                rgba[offset] = (rgba[offset] as f32 + delta).clamp(0.0, 255.0) as u8;
                rgba[offset + 1] = (rgba[offset + 1] as f32 + delta).clamp(0.0, 255.0) as u8;
                rgba[offset + 2] = (rgba[offset + 2] as f32 + delta).clamp(0.0, 255.0) as u8;
            }
        }
    }

    // 2. Embed payload (repeated across all remaining blocks)
    for b_idx in HEADER_BLOCKS..total_blocks {
        let rel_idx = b_idx - HEADER_BLOCKS;
        let bit = payload_bits[rel_idx % payload_num_bits];
        let sign = if bit == 1 { 1.0f32 } else { -1.0f32 };
        let bi = b_idx / blocks_w;
        let bj = b_idx % blocks_w;

        for by in 0..BLOCK_SIZE {
            let py = bi * BLOCK_SIZE + by;
            for bx in 0..BLOCK_SIZE {
                let px = bj * BLOCK_SIZE + bx;
                let offset = (py * w_usize + px) * 4;
                let delta = sign * DELTA * PATTERN[by * BLOCK_SIZE + bx];

                rgba[offset] = (rgba[offset] as f32 + delta).clamp(0.0, 255.0) as u8;
                rgba[offset + 1] = (rgba[offset + 1] as f32 + delta).clamp(0.0, 255.0) as u8;
                rgba[offset + 2] = (rgba[offset + 2] as f32 + delta).clamp(0.0, 255.0) as u8;
            }
        }
    }

    Ok(())
}

pub fn extract_robust_from_rgba(
    rgba: &[u8],
    width: u32,
    height: u32,
    password: Option<&str>,
) -> Result<Vec<u8>> {
    let expected_len = (width as usize) * (height as usize) * 4;
    if rgba.len() != expected_len {
        return Err(StegoError::InvalidImage(format!(
            "Buffer size mismatch: expected {} bytes, got {}",
            expected_len,
            rgba.len()
        )));
    }

    let blocks_w = (width as usize) / BLOCK_SIZE;
    let blocks_h = (height as usize) / BLOCK_SIZE;
    let total_blocks = blocks_w * blocks_h;

    if total_blocks < HEADER_BLOCKS {
        return Err(StegoError::CarrierTooSmall);
    }

    let w_usize = width as usize;

    // Helper: calculate correlation for a block
    let calc_corr = |bi: usize, bj: usize| -> f32 {
        let mut corr = 0.0f32;
        for by in 0..BLOCK_SIZE {
            let py = bi * BLOCK_SIZE + by;
            for bx in 0..BLOCK_SIZE {
                let px = bj * BLOCK_SIZE + bx;
                let offset = (py * w_usize + px) * 4;
                // Integer Luminance: (77*R + 150*G + 29*B) / 256.0
                let y = (77.0 * (rgba[offset] as f32)
                    + 150.0 * (rgba[offset + 1] as f32)
                    + 29.0 * (rgba[offset + 2] as f32))
                    / 256.0;
                corr += y * PATTERN[by * BLOCK_SIZE + bx];
            }
        }
        corr
    };

    // 1. Decode header bits with accumulation
    let mut header_accum = [0.0f32; HEADER_LEN_BITS];
    for b_idx in 0..HEADER_BLOCKS {
        let bi = b_idx / blocks_w;
        let bj = b_idx % blocks_w;
        let corr = calc_corr(bi, bj);
        header_accum[b_idx % HEADER_LEN_BITS] += corr;
    }

    let mut header_bytes = [0u8; HEADER_LEN_BYTES];
    for byte_idx in 0..HEADER_LEN_BYTES {
        let mut byte_val = 0u8;
        for bit_idx in 0..8 {
            let corr = header_accum[byte_idx * 8 + bit_idx];
            let bit = if corr > 0.0 { 1 } else { 0 };
            byte_val = (byte_val << 1) | bit;
        }
        header_bytes[byte_idx] = byte_val;
    }

    if &header_bytes[0..4] != ROBUST_MAGIC {
        return Err(StegoError::InvalidRobustMagic);
    }

    let flags = header_bytes[4];
    let payload_len = u16::from_be_bytes([header_bytes[5], header_bytes[6]]) as usize;
    let expected_crc = u32::from_be_bytes([
        header_bytes[7],
        header_bytes[8],
        header_bytes[9],
        header_bytes[10],
    ]);

    let payload_num_bits = payload_len * 8;
    let avail_payload_blocks = total_blocks - HEADER_BLOCKS;
    if avail_payload_blocks < payload_num_bits {
        return Err(StegoError::ContainerTruncated {
            expected: payload_len,
            found: avail_payload_blocks / 8,
        });
    }

    // 2. Decode payload bits with accumulation across remaining blocks
    let mut payload_accum = vec![0.0f32; payload_num_bits];
    for b_idx in HEADER_BLOCKS..total_blocks {
        let rel_idx = b_idx - HEADER_BLOCKS;
        let bi = b_idx / blocks_w;
        let bj = b_idx % blocks_w;
        let corr = calc_corr(bi, bj);
        payload_accum[rel_idx % payload_num_bits] += corr;
    }

    let mut raw_payload = Vec::with_capacity(payload_len);
    for byte_idx in 0..payload_len {
        let mut byte_val = 0u8;
        for bit_idx in 0..8 {
            let corr = payload_accum[byte_idx * 8 + bit_idx];
            let bit = if corr > 0.0 { 1 } else { 0 };
            byte_val = (byte_val << 1) | bit;
        }
        raw_payload.push(byte_val);
    }

    // Verify CRC32
    let mut actual_crc_hasher = crc32fast::Hasher::new();
    actual_crc_hasher.update(&raw_payload);
    let actual_crc = actual_crc_hasher.finalize();

    if actual_crc != expected_crc {
        return Err(StegoError::CrcMismatch {
            expected: expected_crc,
            actual: actual_crc,
        });
    }

    // Handle decryption if encrypted
    if (flags & FLAG_ENCRYPTED) != 0 {
        let pwd = password
            .filter(|s| !s.is_empty())
            .ok_or(StegoError::PasswordRequired)?;

        if raw_payload.len() < crypto::SALT_LENGTH + crypto::IV_LENGTH {
            return Err(StegoError::ContainerTooShort(raw_payload.len()));
        }

        let salt = &raw_payload[..crypto::SALT_LENGTH];
        let iv = &raw_payload[crypto::SALT_LENGTH..crypto::SALT_LENGTH + crypto::IV_LENGTH];
        let ciphertext = &raw_payload[crypto::SALT_LENGTH + crypto::IV_LENGTH..];

        crypto::decrypt(ciphertext, pwd, salt, iv)
    } else {
        Ok(raw_payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_robust_roundtrip_unencrypted() {
        let width = 256;
        let height = 256;
        let mut rgba = vec![128u8; width * height * 4];
        let secret = b"WARFARE 1337 BISMUTH STEGOSLOP!";

        embed_robust_in_rgba(&mut rgba, width as u32, height as u32, secret, None).unwrap();
        let extracted = extract_robust_from_rgba(&rgba, width as u32, height as u32, None).unwrap();
        assert_eq!(extracted, secret);
    }

    #[test]
    fn test_robust_roundtrip_encrypted() {
        let width = 512;
        let height = 512;
        let mut rgba = vec![100u8; width * height * 4];
        let secret = b"Classified military coordinates: 45.123, 38.456";
        let password = "super_secure_bismuth_pass";

        embed_robust_in_rgba(
            &mut rgba,
            width as u32,
            height as u32,
            secret,
            Some(password),
        )
        .unwrap();

        // Extract with wrong password -> must fail
        assert!(extract_robust_from_rgba(
            &rgba,
            width as u32,
            height as u32,
            Some("wrong_pass")
        )
        .is_err());

        // Extract with correct password -> must match
        let extracted = extract_robust_from_rgba(
            &rgba,
            width as u32,
            height as u32,
            Some(password),
        )
        .unwrap();
        assert_eq!(extracted, secret);
    }
}
