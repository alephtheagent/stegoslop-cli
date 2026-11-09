use crate::error::{Result, StegoError};
use crate::protocol::{FLAG_ENCRYPTED, FLAG_HAS_FILENAME, HEADER_MIN_LENGTH, MAGIC_BYTES};

#[derive(Debug, Clone)]
pub struct WavInfo {
    pub data_offset: usize,
    pub data_size: usize,
    pub bits_per_sample: u16,
    pub num_channels: u16,
    pub sample_rate: u32,
}

impl WavInfo {
    pub fn duration_seconds(&self) -> f64 {
        let bytes_per_frame = (self.num_channels as usize) * (self.bits_per_sample as usize / 8);
        if bytes_per_frame == 0 || self.sample_rate == 0 {
            return 0.0;
        }
        let total_frames = self.data_size / bytes_per_frame;
        total_frames as f64 / self.sample_rate as f64
    }

    pub fn total_samples(&self) -> usize {
        self.data_size / (self.bits_per_sample as usize / 8)
    }

    pub fn capacity(&self, bits_per_sample: usize) -> usize {
        (self.total_samples() * bits_per_sample) / 8
    }
}

pub fn parse_wav(wav_bytes: &[u8]) -> Result<WavInfo> {
    if wav_bytes.len() < 12 {
        return Err(StegoError::InvalidWav("File too small for WAV header".into()));
    }

    if &wav_bytes[0..4] != b"RIFF" || &wav_bytes[8..12] != b"WAVE" {
        return Err(StegoError::InvalidWav("Missing RIFF/WAVE header".into()));
    }

    let mut offset = 12;
    let mut data_offset = None;
    let mut data_size = 0;
    let mut bits_per_sample = 16;
    let mut num_channels = 1;
    let mut sample_rate = 44100;

    while offset + 8 <= wav_bytes.len() {
        let chunk_id = &wav_bytes[offset..offset + 4];
        let chunk_size = u32::from_le_bytes(wav_bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let chunk_data_offset = offset + 8;

        if chunk_id == b"fmt " {
            if chunk_size_valid(chunk_size, chunk_data_offset, wav_bytes.len()) {
                let audio_format = u16::from_le_bytes(wav_bytes[chunk_data_offset..chunk_data_offset + 2].try_into().unwrap());
                if audio_format != 1 {
                    return Err(StegoError::InvalidWav(format!("Unsupported audio format {} (must be 1 for PCM)", audio_format)));
                }
                num_channels = u16::from_le_bytes(wav_bytes[chunk_data_offset + 2..chunk_data_offset + 4].try_into().unwrap());
                sample_rate = u32::from_le_bytes(wav_bytes[chunk_data_offset + 4..chunk_data_offset + 8].try_into().unwrap());
                bits_per_sample = u16::from_le_bytes(wav_bytes[chunk_data_offset + 14..chunk_data_offset + 16].try_into().unwrap());
                if bits_per_sample != 16 {
                    return Err(StegoError::InvalidWav(format!("Unsupported bits per sample: {} (must be 16-bit PCM)", bits_per_sample)));
                }
            }
        } else if chunk_id == b"data" {
            data_offset = Some(chunk_data_offset);
            data_size = chunk_size.min(wav_bytes.len().saturating_sub(chunk_data_offset));
        }

        offset += 8 + chunk_size;
    }

    let data_offset = data_offset.ok_or_else(|| StegoError::InvalidWav("Missing 'data' chunk".into()))?;

    Ok(WavInfo {
        data_offset,
        data_size,
        bits_per_sample,
        num_channels,
        sample_rate,
    })
}

fn chunk_size_valid(chunk_size: usize, chunk_data_offset: usize, total_len: usize) -> bool {
    chunk_size >= 16 && chunk_data_offset + 16 <= total_len
}

/// Embeds payload container bytes into the 16-bit PCM samples of a WAV file.
pub fn embed_in_wav(wav_bytes: &[u8], payload_container: &[u8], bits_per_sample: usize) -> Result<Vec<u8>> {
    if !matches!(bits_per_sample, 1 | 2 | 4) {
        return Err(StegoError::UnsupportedBitsPerUnit(bits_per_sample));
    }

    let info = parse_wav(wav_bytes)?;
    let capacity = info.capacity(bits_per_sample);
    if payload_container.len() > capacity {
        return Err(StegoError::CapacityExceeded {
            payload_size: payload_container.len(),
            capacity,
        });
    }

    let mut result = wav_bytes.to_vec();
    let mask = ((1usize << bits_per_sample) - 1) as u16;
    let clear_mask = !mask;
    let mut sample_index = 0usize;

    for &b in payload_container {
        for shift in (0..8).step_by(bits_per_sample).rev() {
            let chunk = ((b >> shift) as u16) & mask;
            let sample_offset = info.data_offset + sample_index * 2;

            let sample = u16::from_le_bytes([result[sample_offset], result[sample_offset + 1]]);
            let new_sample = (sample & clear_mask) | chunk;
            let bytes = new_sample.to_le_bytes();
            result[sample_offset] = bytes[0];
            result[sample_offset + 1] = bytes[1];

            sample_index += 1;
        }
    }

    Ok(result)
}

/// Extracts payload container bytes from 16-bit PCM RIFF WAV audio bytes.
pub fn extract_from_wav(wav_bytes: &[u8], bits_per_sample: usize) -> Result<Vec<u8>> {
    if !matches!(bits_per_sample, 1 | 2 | 4) {
        return Err(StegoError::UnsupportedBitsPerUnit(bits_per_sample));
    }

    let info = parse_wav(wav_bytes)?;
    let capacity = info.capacity(bits_per_sample);
    if capacity < HEADER_MIN_LENGTH {
        return Err(StegoError::CarrierTooSmall);
    }

    let chunks_per_byte = 8 / bits_per_sample;
    let mask = ((1usize << bits_per_sample) - 1) as u16;
    let mut sample_index = 0usize;

    let read_byte = |sample_index: &mut usize| -> u8 {
        let mut byte_val = 0u8;
        for _ in 0..chunks_per_byte {
            let sample_offset = info.data_offset + *sample_index * 2;
            let sample = u16::from_le_bytes([wav_bytes[sample_offset], wav_bytes[sample_offset + 1]]);
            let chunk = (sample & mask) as u8;
            byte_val = (byte_val << bits_per_sample) | chunk;
            *sample_index += 1;
        }
        byte_val
    };

    // 1. Read first 14 header bytes
    let mut header = [0u8; HEADER_MIN_LENGTH];
    for b in header.iter_mut() {
        *b = read_byte(&mut sample_index);
    }

    // 2. Validate SLOP magic
    if &header[0..4] != &MAGIC_BYTES {
        return Err(StegoError::InvalidMagic);
    }

    let flags = header[5];
    let is_encrypted = (flags & FLAG_ENCRYPTED) != 0;
    let has_filename = (flags & FLAG_HAS_FILENAME) != 0;

    let payload_len = u32::from_be_bytes(header[6..10].try_into().unwrap()) as usize;

    // 3. Read salt and IV if encrypted
    let mut variable_header = Vec::new();
    if is_encrypted {
        for _ in 0..28 {
            variable_header.push(read_byte(&mut sample_index));
        }
    }

    // 4. Read filename length and string bytes if present
    if has_filename {
        let fn_len = read_byte(&mut sample_index) as usize;
        variable_header.push(fn_len as u8);
        for _ in 0..fn_len {
            variable_header.push(read_byte(&mut sample_index));
        }
    }

    let total_container_len = HEADER_MIN_LENGTH + variable_header.len() + payload_len;
    if total_container_len > capacity {
        return Err(StegoError::ContainerTruncated {
            expected: total_container_len,
            found: capacity,
        });
    }

    // 5. Read payload data
    let mut payload = Vec::with_capacity(payload_len);
    for _ in 0..payload_len {
        payload.push(read_byte(&mut sample_index));
    }

    let mut full_container = Vec::with_capacity(total_container_len);
    full_container.extend_from_slice(&header);
    full_container.extend_from_slice(&variable_header);
    full_container.extend_from_slice(&payload);

    Ok(full_container)
}

/// Dumps raw LSB bits from WAV samples without SLOP header validation.
pub fn extract_raw_bits_from_wav(
    wav_bytes: &[u8],
    bits_per_sample: usize,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if !matches!(bits_per_sample, 1 | 2 | 4) {
        return Err(StegoError::UnsupportedBitsPerUnit(bits_per_sample));
    }

    let info = parse_wav(wav_bytes)?;
    let capacity = info.capacity(bits_per_sample);
    let bytes_to_extract = capacity.min(max_bytes);
    if bytes_to_extract == 0 {
        return Ok(Vec::new());
    }

    let chunks_per_byte = 8 / bits_per_sample;
    let mask = ((1usize << bits_per_sample) - 1) as u16;
    let mut sample_index = 0usize;
    let mut result = Vec::with_capacity(bytes_to_extract);

    for _ in 0..bytes_to_extract {
        let mut byte_val = 0u8;
        for _ in 0..chunks_per_byte {
            let sample_offset = info.data_offset + sample_index * 2;
            let sample = u16::from_le_bytes([wav_bytes[sample_offset], wav_bytes[sample_offset + 1]]);
            let chunk = (sample & mask) as u8;
            byte_val = (byte_val << bits_per_sample) | chunk;
            sample_index += 1;
        }
        result.push(byte_val);
    }

    Ok(result)
}

pub fn create_synthetic_wav(sample_count: usize, sample_rate: u32, num_channels: u16) -> Vec<u8> {
    let data_size = sample_count * 2;
    let file_size = 36 + data_size;
    let mut wav = Vec::with_capacity(44 + data_size);

    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(file_size as u32).to_le_bytes());
    wav.extend_from_slice(b"WAVE");

    wav.extend_from_slice(b"fmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes()); // PCM format
    wav.extend_from_slice(&num_channels.to_le_bytes());
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    let byte_rate = sample_rate * (num_channels as u32) * 2;
    wav.extend_from_slice(&byte_rate.to_le_bytes());
    let block_align = num_channels * 2;
    wav.extend_from_slice(&block_align.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes()); // 16-bit

    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&(data_size as u32).to_le_bytes());

    // Generate dummy samples
    for i in 0..sample_count {
        let sample = (i as i16).to_le_bytes();
        wav.extend_from_slice(&sample);
    }

    wav
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{pack_payload, unpack_payload, PayloadType};

    #[test]
    fn test_audio_lsb_roundtrip() {
        let wav = create_synthetic_wav(10_000, 44100, 2);
        let secret = b"Secret sound stego packet";
        let container = pack_payload(PayloadType::Audio, secret, None, 2, Some("voice.opus")).unwrap();

        let embedded = embed_in_wav(&wav, &container, 2).unwrap();
        let extracted = extract_from_wav(&embedded, 2).unwrap();
        assert_eq!(extracted, container);

        let unpacked = unpack_payload(&extracted, None).unwrap();
        assert_eq!(unpacked.data, secret);
        assert_eq!(unpacked.file_name.as_deref(), Some("voice.opus"));
    }
}
