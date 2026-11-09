use crate::error::{Result, StegoError};
use crate::protocol::{FLAG_ENCRYPTED, FLAG_HAS_FILENAME, HEADER_MIN_LENGTH, MAGIC_BYTES};

pub fn compute_capacity(width: u32, height: u32, bits_per_channel: usize) -> Result<usize> {
    if !matches!(bits_per_channel, 1 | 2 | 4) {
        return Err(StegoError::UnsupportedBitsPerUnit(bits_per_channel));
    }
    let total_pixels = width as usize * height as usize;
    Ok((total_pixels * 3 * bits_per_channel) / 8)
}

/// Embeds payload container bytes into RGBA pixel slice.
/// Modifies R, G, B channels sequentially and leaves A (alpha) untouched.
pub fn embed_in_rgba(
    rgba_pixels: &mut [u8],
    payload_container: &[u8],
    bits_per_channel: usize,
) -> Result<()> {
    if !matches!(bits_per_channel, 1 | 2 | 4) {
        return Err(StegoError::UnsupportedBitsPerUnit(bits_per_channel));
    }

    let total_pixels = rgba_pixels.len() / 4;
    let capacity = (total_pixels * 3 * bits_per_channel) / 8;
    if payload_container.len() > capacity {
        return Err(StegoError::CapacityExceeded {
            payload_size: payload_container.len(),
            capacity,
        });
    }

    let mask = ((1usize << bits_per_channel) - 1) as u8;
    let clear_mask = !mask;
    let mut channel_count = 0usize;

    for &b in payload_container {
        for shift in (0..8).step_by(bits_per_channel).rev() {
            let chunk = (b >> shift) & mask;
            let pixel_idx = channel_count / 3;
            let channel_offset = channel_count % 3; // 0 = R, 1 = G, 2 = B

            let byte_idx = pixel_idx * 4 + channel_offset;
            rgba_pixels[byte_idx] = (rgba_pixels[byte_idx] & clear_mask) | chunk;
            channel_count += 1;
        }
    }

    Ok(())
}

/// Extracts payload container bytes from RGBA pixel slice.
pub fn extract_from_rgba(rgba_pixels: &[u8], bits_per_channel: usize) -> Result<Vec<u8>> {
    if !matches!(bits_per_channel, 1 | 2 | 4) {
        return Err(StegoError::UnsupportedBitsPerUnit(bits_per_channel));
    }

    let total_pixels = rgba_pixels.len() / 4;
    let capacity = (total_pixels * 3 * bits_per_channel) / 8;
    if capacity < HEADER_MIN_LENGTH {
        return Err(StegoError::CarrierTooSmall);
    }

    let chunks_per_byte = 8 / bits_per_channel;
    let mask = ((1usize << bits_per_channel) - 1) as u8;
    let mut channel_count = 0usize;

    let read_byte = |channel_count: &mut usize| -> u8 {
        let mut byte_val = 0u8;
        for _ in 0..chunks_per_byte {
            let pixel_idx = *channel_count / 3;
            let channel_offset = *channel_count % 3;
            let byte_idx = pixel_idx * 4 + channel_offset;
            let chunk = rgba_pixels[byte_idx] & mask;
            byte_val = (byte_val << bits_per_channel) | chunk;
            *channel_count += 1;
        }
        byte_val
    };

    // 1. Read first 14 header bytes
    let mut header = [0u8; HEADER_MIN_LENGTH];
    for b in header.iter_mut() {
        *b = read_byte(&mut channel_count);
    }

    // 2. Validate SLOP magic
    if &header[0..4] != &MAGIC_BYTES {
        return Err(StegoError::InvalidMagic);
    }

    let flags = header[5];
    let is_encrypted = (flags & FLAG_ENCRYPTED) != 0;
    let has_filename = (flags & FLAG_HAS_FILENAME) != 0;

    let payload_len = u32::from_be_bytes(header[6..10].try_into().unwrap()) as usize;

    // 3. Read variable header components (salt + IV)
    let mut variable_header = Vec::new();
    if is_encrypted {
        for _ in 0..28 {
            variable_header.push(read_byte(&mut channel_count));
        }
    }

    // 4. Read filename length + filename bytes if present
    if has_filename {
        let fn_len = read_byte(&mut channel_count) as usize;
        variable_header.push(fn_len as u8);
        for _ in 0..fn_len {
            variable_header.push(read_byte(&mut channel_count));
        }
    }

    let total_container_len = HEADER_MIN_LENGTH + variable_header.len() + payload_len;
    if total_container_len > capacity {
        return Err(StegoError::ContainerTruncated {
            expected: total_container_len,
            found: capacity,
        });
    }

    // 5. Read payload bytes
    let mut payload = Vec::with_capacity(payload_len);
    for _ in 0..payload_len {
        payload.push(read_byte(&mut channel_count));
    }

    let mut full_container = Vec::with_capacity(total_container_len);
    full_container.extend_from_slice(&header);
    full_container.extend_from_slice(&variable_header);
    full_container.extend_from_slice(&payload);

    Ok(full_container)
}

/// Dumps raw LSB bits from RGBA pixels without SLOP header validation.
pub fn extract_raw_bits_from_rgba(
    rgba_pixels: &[u8],
    bits_per_channel: usize,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if !matches!(bits_per_channel, 1 | 2 | 4) {
        return Err(StegoError::UnsupportedBitsPerUnit(bits_per_channel));
    }

    let total_pixels = rgba_pixels.len() / 4;
    let capacity = (total_pixels * 3 * bits_per_channel) / 8;
    let bytes_to_extract = capacity.min(max_bytes);
    if bytes_to_extract == 0 {
        return Ok(Vec::new());
    }

    let chunks_per_byte = 8 / bits_per_channel;
    let mask = ((1usize << bits_per_channel) - 1) as u8;
    let mut channel_count = 0usize;
    let mut result = Vec::with_capacity(bytes_to_extract);

    for _ in 0..bytes_to_extract {
        let mut byte_val = 0u8;
        for _ in 0..chunks_per_byte {
            let pixel_idx = channel_count / 3;
            let channel_offset = channel_count % 3;
            let byte_idx = pixel_idx * 4 + channel_offset;
            let chunk = rgba_pixels[byte_idx] & mask;
            byte_val = (byte_val << bits_per_channel) | chunk;
            channel_count += 1;
        }
        result.push(byte_val);
    }

    Ok(result)
}

/// Generates a grayscale RGBA bitmap where the bit at bit_index (0..7) is amplified to 0 or 255.
pub fn generate_bit_plane(rgba_pixels: &[u8], bit_index: usize) -> Vec<u8> {
    let mut plane = vec![0u8; rgba_pixels.len()];
    let bit_mask = 1u8 << (bit_index.min(7));

    for i in (0..rgba_pixels.len()).step_by(4) {
        let r_bit = if (rgba_pixels[i] & bit_mask) != 0 { 255 } else { 0 };
        let g_bit = if (rgba_pixels[i + 1] & bit_mask) != 0 { 255 } else { 0 };
        let b_bit = if (rgba_pixels[i + 2] & bit_mask) != 0 { 255 } else { 0 };

        // Average across RGB bit planes
        let gray = ((r_bit as u16 + g_bit as u16 + b_bit as u16) / 3) as u8;
        plane[i] = gray;
        plane[i + 1] = gray;
        plane[i + 2] = gray;
        plane[i + 3] = 0xFF; // Solid alpha
    }

    plane
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{pack_payload, unpack_payload, PayloadType};

    #[test]
    fn test_image_lsb_roundtrip() {
        let width = 64;
        let height = 64;
        let mut pixels = vec![0xFF; width * height * 4];

        let secret = b"StegoSlop image LSB test payload 2026!";
        let container = pack_payload(PayloadType::Text, secret, None, 2, Some("secret.txt")).unwrap();

        embed_in_rgba(&mut pixels, &container, 2).unwrap();
        let extracted_container = extract_from_rgba(&pixels, 2).unwrap();
        assert_eq!(extracted_container, container);

        let unpacked = unpack_payload(&extracted_container, None).unwrap();
        assert_eq!(unpacked.data, secret);
        assert_eq!(unpacked.file_name.as_deref(), Some("secret.txt"));
    }
}
