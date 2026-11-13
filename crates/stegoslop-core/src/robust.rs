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

pub struct RobustExtraction {
    pub data: Vec<u8>,
    pub is_encrypted: bool,
    pub is_corrupted: bool,
}

pub fn extract_robust_from_rgba(
    rgba: &[u8],
    width: u32,
    height: u32,
    password: Option<&str>,
) -> Result<Vec<u8>> {
    let res = extract_robust_from_rgba_ext(rgba, width, height, password, false)?;
    Ok(res.data)
}

pub fn extract_robust_from_rgba_forced(
    rgba: &[u8],
    width: u32,
    height: u32,
    password: Option<&str>,
) -> Result<RobustExtraction> {
    extract_robust_from_rgba_ext(rgba, width, height, password, true)
}

fn extract_robust_from_rgba_ext(
    rgba: &[u8],
    width: u32,
    height: u32,
    password: Option<&str>,
    forced: bool,
) -> Result<RobustExtraction> {
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

    let is_corrupted = actual_crc != expected_crc;
    if is_corrupted && !forced {
        return Err(StegoError::CrcMismatch {
            expected: expected_crc,
            actual: actual_crc,
        });
    }

    // Handle decryption if encrypted
    let is_encrypted = (flags & FLAG_ENCRYPTED) != 0;
    let data = if is_encrypted {
        let pwd = password
            .filter(|s| !s.is_empty())
            .ok_or(StegoError::PasswordRequired)?;

        if raw_payload.len() < crypto::SALT_LENGTH + crypto::IV_LENGTH {
            return Err(StegoError::ContainerTooShort(raw_payload.len()));
        }

        let salt = &raw_payload[..crypto::SALT_LENGTH];
        let iv = &raw_payload[crypto::SALT_LENGTH..crypto::SALT_LENGTH + crypto::IV_LENGTH];
        let ciphertext = &raw_payload[crypto::SALT_LENGTH + crypto::IV_LENGTH..];

        crypto::decrypt(ciphertext, pwd, salt, iv)?
    } else {
        raw_payload
    };

    Ok(RobustExtraction {
        data,
        is_encrypted,
        is_corrupted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use image::codecs::jpeg::JpegEncoder;
    use image::ImageEncoder;

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

        // Extract with no password -> must fail with PasswordRequired
        match extract_robust_from_rgba(&rgba, width as u32, height as u32, None) {
            Err(StegoError::PasswordRequired) => {},
            other => panic!("Expected PasswordRequired, got {:?}", other),
        }

        // Extract with wrong password -> must fail with DecryptionFailed
        match extract_robust_from_rgba(&rgba, width as u32, height as u32, Some("wrong_pass")) {
            Err(StegoError::DecryptionFailed) => {},
            other => panic!("Expected DecryptionFailed, got {:?}", other),
        }

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

    #[test]
    fn test_robust_capacity_calculations_and_bounds() {
        // 64x64 -> 8x8 = 64 blocks (< 352 header blocks)
        assert_eq!(compute_robust_capacity(64, 64, false), 0);
        assert_eq!(compute_robust_capacity(64, 64, true), 0);

        // 256x256 -> 32x32 = 1024 blocks.
        // Avail bytes = (1024 - 352) / 8 = 672 / 8 = 84 bytes
        assert_eq!(compute_robust_capacity(256, 256, false), 84);
        // Encrypted: 84 - 44 = 40 bytes
        assert_eq!(compute_robust_capacity(256, 256, true), 40);

        // 512x512 -> 64x64 = 4096 blocks.
        // Avail bytes = (4096 - 352) / 8 = 3744 / 8 = 468 bytes
        assert_eq!(compute_robust_capacity(512, 512, false), 468);
        assert_eq!(compute_robust_capacity(512, 512, true), 424);

        // Overflow test: try to embed 100 bytes into a 256x256 image (capacity 84)
        let mut rgba = vec![128u8; 256 * 256 * 4];
        let oversized_secret = vec![0x42u8; 100];
        match embed_robust_in_rgba(&mut rgba, 256, 256, &oversized_secret, None) {
            Err(StegoError::CapacityExceeded { payload_size, capacity }) => {
                assert_eq!(payload_size, 100);
                assert_eq!(capacity, 84);
            }
            other => panic!("Expected CapacityExceeded, got {:?}", other),
        }
    }

    #[test]
    fn test_robust_survives_real_jpeg_compression_quality_75() {
        // Test survival across realistic lossy JPEG compression at quality 75 (Telegram standard)
        let width = 512;
        let height = 512;
        let mut rgba = vec![0u8; width * height * 4];

        // Synthesize a realistic image with gradients and textures
        for y in 0..height {
            for x in 0..width {
                let offset = (y * width + x) * 4;
                let grad = ((x * 150 / width) + (y * 80 / height)) as u8;
                let noise = ((x ^ y) & 0x1F) as u8;
                rgba[offset] = grad.saturating_add(noise);
                rgba[offset + 1] = grad.saturating_add(noise / 2);
                rgba[offset + 2] = 180u8.saturating_sub(grad / 2);
                rgba[offset + 3] = 255;
            }
        }

        let secret = b"Ea-nasir: you sent me ingots of bad copper in my yard! WARFARE 2026";
        embed_robust_in_rgba(&mut rgba, width as u32, height as u32, secret, None).unwrap();

        // Convert RGBA to RGB for JPEG encoding
        let mut rgb = Vec::with_capacity(width * height * 3);
        for chunk in rgba.chunks_exact(4) {
            rgb.push(chunk[0]);
            rgb.push(chunk[1]);
            rgb.push(chunk[2]);
        }

        // Encode to lossy JPEG at quality 75 (simulating Telegram's transcode)
        let mut jpeg_buf = Cursor::new(Vec::new());
        let encoder = JpegEncoder::new_with_quality(&mut jpeg_buf, 75);
        encoder
            .write_image(&rgb, width as u32, height as u32, image::ExtendedColorType::Rgb8)
            .unwrap();

        let jpeg_bytes = jpeg_buf.into_inner();
        assert!(!jpeg_bytes.is_empty());

        // Decode JPEG back to RGBA
        let decoded_img = image::load_from_memory_with_format(&jpeg_bytes, image::ImageFormat::Jpeg)
            .unwrap()
            .to_rgba8();

        let decoded_raw = decoded_img.into_raw();

        // Extract secret from the lossy JPEG!
        let extracted = extract_robust_from_rgba(&decoded_raw, width as u32, height as u32, None)
            .expect("Extraction from lossy JPEG quality 75 failed");

        assert_eq!(extracted, secret, "Extracted secret from JPEG did not match original!");
    }

    #[test]
    fn test_robust_survives_aggressive_jpeg_quality_60() {
        // Even at aggressive quality 60 (heavy compression artifacts)
        let width = 512;
        let height = 512;
        let mut rgba = vec![120u8; width * height * 4];

        let secret = b"Resistant to aggressive lossy quantization!";
        embed_robust_in_rgba(&mut rgba, width as u32, height as u32, secret, None).unwrap();

        let mut rgb = Vec::with_capacity(width * height * 3);
        for chunk in rgba.chunks_exact(4) {
            rgb.push(chunk[0]);
            rgb.push(chunk[1]);
            rgb.push(chunk[2]);
        }

        let mut jpeg_buf = Cursor::new(Vec::new());
        let encoder = JpegEncoder::new_with_quality(&mut jpeg_buf, 60);
        encoder
            .write_image(&rgb, width as u32, height as u32, image::ExtendedColorType::Rgb8)
            .unwrap();

        let jpeg_bytes = jpeg_buf.into_inner();
        let decoded_img = image::load_from_memory(&jpeg_bytes).unwrap().to_rgba8();

        let extracted = extract_robust_from_rgba(decoded_img.as_raw(), width as u32, height as u32, None)
            .expect("Extraction from aggressive JPEG quality 60 failed");

        assert_eq!(extracted, secret);
    }

    #[test]
    fn test_robust_invalid_magic_on_unmarked_image() {
        let width = 256;
        let height = 256;
        let clean_rgba = vec![128u8; width * height * 4];

        // An image without RSLP stego must fail with InvalidRobustMagic
        match extract_robust_from_rgba(&clean_rgba, width as u32, height as u32, None) {
            Err(StegoError::InvalidRobustMagic) => {},
            other => panic!("Expected InvalidRobustMagic on clean image, got {:?}", other),
        }
    }
}
