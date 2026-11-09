use stegoslop_core::{
    audio::{create_synthetic_wav, embed_in_wav, extract_from_wav},
    decode_zero_width, encode_zero_width, has_hidden_data,
    image::{embed_in_rgba, extract_from_rgba},
    protocol::{pack_payload, unpack_payload, PayloadType},
};

#[test]
fn test_binary_protocol_compatibility_with_kotlin() {
    let secret = b"WARFARE 2026 - Bismuth & Aleph";
    let filename = "06. noma - Brain Power.opus";

    // 1. Pack with filename and encryption
    let packed = pack_payload(
        PayloadType::Audio,
        secret,
        Some("secret_key_48khz"),
        2, // 2 bits per unit
        Some(filename),
    )
    .unwrap();

    // Check exact byte offsets matching Kotlin:
    assert_eq!(&packed[0..4], b"SLOP");
    assert_eq!(packed[4], 0x03); // Audio type code

    let flags = packed[5];
    assert_eq!(flags & 0x01, 0x01); // Encrypted flag
    assert_eq!((flags >> 1) & 0x03, 1); // 2 bits per unit (bpuCode 1)
    assert_eq!(flags & 0x08, 0x08); // Has filename flag

    let payload_len = u32::from_be_bytes(packed[6..10].try_into().unwrap()) as usize;
    assert_eq!(payload_len, secret.len() + 16); // AES-GCM tag is 16 bytes

    let salt = &packed[14..30];
    let iv = &packed[30..42];
    assert_eq!(salt.len(), 16);
    assert_eq!(iv.len(), 12);

    let fn_len = packed[42] as usize;
    assert_eq!(fn_len, filename.len());
    let fn_str = std::str::from_utf8(&packed[43..43 + fn_len]).unwrap();
    assert_eq!(fn_str, filename);

    // 2. Unpack
    let unpacked = unpack_payload(&packed, Some("secret_key_48khz")).unwrap();
    assert_eq!(unpacked.payload_type, PayloadType::Audio);
    assert_eq!(unpacked.data, secret);
    assert_eq!(unpacked.file_name.as_deref(), Some(filename));
    assert_eq!(unpacked.bits_per_unit, 2);
    assert!(unpacked.is_encrypted);
    assert!(!unpacked.is_corrupted);
}

#[test]
fn test_image_and_audio_end_to_end() {
    let secret = b"All systems operational. Good night, Bismuth!";
    let packed = pack_payload(
        PayloadType::Text,
        secret,
        None,
        1,
        Some("status.txt"),
    )
    .unwrap();

    // Test Image LSB
    let mut image_pixels = vec![128u8; 100 * 100 * 4];
    embed_in_rgba(&mut image_pixels, &packed, 1).unwrap();
    let extracted_img_container = extract_from_rgba(&image_pixels, 1).unwrap();
    let img_unpacked = unpack_payload(&extracted_img_container, None).unwrap();
    assert_eq!(img_unpacked.data, secret);
    assert_eq!(img_unpacked.file_name.as_deref(), Some("status.txt"));

    // Test Audio LSB
    let wav = create_synthetic_wav(15_000, 48000, 2);
    let embedded_wav = embed_in_wav(&wav, &packed, 1).unwrap();
    let extracted_wav_container = extract_from_wav(&embedded_wav, 1).unwrap();
    let wav_unpacked = unpack_payload(&extracted_wav_container, None).unwrap();
    assert_eq!(wav_unpacked.data, secret);
    assert_eq!(wav_unpacked.file_name.as_deref(), Some("status.txt"));

    // Test Zero-Width Unicode
    let cover = "Привет, Висмут! Ложись спать, я всё настрою.";
    let encoded = encode_zero_width(cover, secret, None).unwrap();
    assert!(has_hidden_data(&encoded));
    let decoded = decode_zero_width(&encoded, None).unwrap();
    assert_eq!(decoded, secret);
}
