use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_stegoslop")
}

fn create_test_png(width: u32, height: u32) -> Vec<u8> {
    let mut rgba = Vec::with_capacity((width * height * 4) as usize);
    for y in 0..height {
        for x in 0..width {
            rgba.push(((x * 7) % 256) as u8);
            rgba.push(((y * 13) % 256) as u8);
            rgba.push(((x + y) % 256) as u8);
            rgba.push(255);
        }
    }
    stegoslop_cli::io_utils::encode_png(width, height, rgba).unwrap()
}

fn create_test_wav(sample_count: usize) -> Vec<u8> {
    stegoslop_core::audio::create_synthetic_wav(sample_count, 44100, 2)
}

#[test]
fn test_png_inject_extract_basic() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.png");
    let payload_path = dir.path().join("secret.txt");
    let stego_path = dir.path().join("stego.png");
    let extracted_path = dir.path().join("extracted.txt");

    let png_bytes = create_test_png(100, 100);
    std::fs::write(&carrier_path, &png_bytes).unwrap();
    let secret = b"StegoSlop PNG E2E test secret content!";
    std::fs::write(&payload_path, secret).unwrap();

    // 1. Inject
    let status = Command::new(bin_path())
        .args([
            "inject",
            "-c",
            carrier_path.to_str().unwrap(),
            "-p",
            payload_path.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-b",
            "1",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(stego_path.exists());

    // 2. Extract
    let status = Command::new(bin_path())
        .args([
            "extract",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            extracted_path.to_str().unwrap(),
            "-b",
            "1",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(std::fs::read(&extracted_path).unwrap(), secret);
}

#[test]
fn test_png_inject_extract_encrypted_with_preserve_name() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.png");
    let payload_path = dir.path().join("classified_intel.txt");
    let stego_path = dir.path().join("carrier_stego.png");

    let png_bytes = create_test_png(120, 120);
    std::fs::write(&carrier_path, &png_bytes).unwrap();
    let secret = b"Top secret agent operations 2026. Bismuth & Aleph.";
    std::fs::write(&payload_path, secret).unwrap();

    let password = "super_secure_bismuth_password_42";

    // 1. Inject with password and preserve-name
    let status = Command::new(bin_path())
        .args([
            "inject",
            "-c",
            carrier_path.to_str().unwrap(),
            "-p",
            payload_path.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-b",
            "2",
            "--password",
            password,
            "--preserve-name",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    // 2. Extract with wrong password -> should fail
    let status = Command::new(bin_path())
        .args([
            "extract",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            dir.path().join("fail.txt").to_str().unwrap(),
            "--password",
            "wrong_password",
        ])
        .status()
        .unwrap();
    assert!(!status.success());

    // 3. Extract with preserve-name into tempdir
    let status = Command::new(bin_path())
        .args([
            "extract",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            dir.path().to_str().unwrap(),
            "--password",
            password,
            "--preserve-name",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let restored_file = dir.path().join("classified_intel.txt");
    assert!(restored_file.exists());
    assert_eq!(std::fs::read(&restored_file).unwrap(), secret);
}

#[test]
fn test_wav_inject_extract_and_info() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("audio.wav");
    let payload_path = dir.path().join("speech.txt");
    let stego_path = dir.path().join("audio_stego.wav");
    let extracted_path = dir.path().join("extracted_speech.txt");

    let wav_bytes = create_test_wav(20_000);
    std::fs::write(&carrier_path, &wav_bytes).unwrap();
    let secret = b"Echo coordinates: 55.7558 N, 37.6173 E. Transmit at dawn.";
    std::fs::write(&payload_path, secret).unwrap();

    // 1. Test info on clean carrier
    let output = Command::new(bin_path())
        .args(["info", "-c", carrier_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let info_str = String::from_utf8_lossy(&output.stdout);
    assert!(info_str.contains("RIFF WAVE Audio"));
    assert!(info_str.contains("No StegoSlop payload detected"));

    // 2. Inject into WAV with 2 bits
    let status = Command::new(bin_path())
        .args([
            "inject",
            "-c",
            carrier_path.to_str().unwrap(),
            "-p",
            payload_path.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-b",
            "2",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    // 3. Test info on stego WAV
    let output = Command::new(bin_path())
        .args(["info", "-c", stego_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let info_str = String::from_utf8_lossy(&output.stdout);
    assert!(info_str.contains("StegoSlop payload FOUND at 2 bit(s)/unit"));

    // 4. Extract with auto-detecting bits
    let status = Command::new(bin_path())
        .args([
            "extract",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            extracted_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(std::fs::read(&extracted_path).unwrap(), secret);
}

#[test]
fn test_pipe_stdin_stdout_roundtrip() {
    let png_bytes = create_test_png(80, 80);
    let secret = b"Streaming steganography through Unix pipes!";

    // Pipe test: carrier via file, payload via stdin '-', output to stdout '-'
    let dir = tempdir().unwrap();
    let carrier_file = dir.path().join("carrier.png");
    std::fs::write(&carrier_file, &png_bytes).unwrap();

    let mut inject_child = Command::new(bin_path())
        .args([
            "inject",
            "-c",
            carrier_file.to_str().unwrap(),
            "-p",
            "-",
            "-o",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    inject_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(secret)
        .unwrap();
    let inject_out = inject_child.wait_with_output().unwrap();
    assert!(inject_out.status.success());
    let stego_png_bytes = inject_out.stdout;
    assert!(!stego_png_bytes.is_empty());
    assert_eq!(&stego_png_bytes[0..8], b"\x89PNG\r\n\x1a\n");

    // Extract: pass stego PNG via stdin (-c -), write secret to stdout (-o -)
    let mut extract_child = Command::new(bin_path())
        .args(["extract", "-c", "-", "-o", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    extract_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&stego_png_bytes)
        .unwrap();
    let extract_out = extract_child.wait_with_output().unwrap();
    assert!(extract_out.status.success());
    assert_eq!(extract_out.stdout, secret);
}

#[test]
fn test_dump_raw_command() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.png");
    let png_bytes = create_test_png(50, 50);
    std::fs::write(&carrier_path, &png_bytes).unwrap();

    let output = Command::new(bin_path())
        .args([
            "dump-raw",
            "-c",
            carrier_path.to_str().unwrap(),
            "-b",
            "1",
            "-n",
            "64",
            "-o",
            "-",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout.len(), 64);
}

#[test]
fn test_bitplane_command() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.png");
    let plane_path = dir.path().join("plane_0.png");
    let png_bytes = create_test_png(60, 60);
    std::fs::write(&carrier_path, &png_bytes).unwrap();

    let status = Command::new(bin_path())
        .args([
            "bitplane",
            "-c",
            carrier_path.to_str().unwrap(),
            "-o",
            plane_path.to_str().unwrap(),
            "-b",
            "0",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(plane_path.exists());

    let bitplane_bytes = std::fs::read(&plane_path).unwrap();
    assert_eq!(&bitplane_bytes[0..8], b"\x89PNG\r\n\x1a\n");

    // Also test bitplane to stdout with -o -
    let output = Command::new(bin_path())
        .args([
            "bitplane",
            "-c",
            carrier_path.to_str().unwrap(),
            "-o",
            "-",
            "-b",
            "1",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(&output.stdout[0..8], b"\x89PNG\r\n\x1a\n");
}

#[test]
fn test_zero_width_full_workflow() {
    let dir = tempdir().unwrap();
    let cover_path = dir.path().join("cover.txt");
    let stego_path = dir.path().join("stego.txt");
    let clean_path = dir.path().join("clean.txt");

    let cover_text = "Good evening agent. The drop off will occur at the bridge.";
    let secret_msg = "Launch key 987654321-ALPHA";
    std::fs::write(&cover_path, cover_text).unwrap();

    // 1. Test detect on clean text
    let output = Command::new(bin_path())
        .args(["zero-width", "detect", "-c", cover_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("NO"));

    // 2. Encode with password using subcommand
    let status = Command::new(bin_path())
        .args([
            "zero-width",
            "encode",
            "-c",
            cover_path.to_str().unwrap(),
            "-p",
            secret_msg,
            "-o",
            stego_path.to_str().unwrap(),
            "--password",
            "zw_pwd_2026",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(stego_path.exists());

    // 3. Test detect on stego text
    let output = Command::new(bin_path())
        .args(["zero-width", "detect", "-c", stego_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("YES"));

    // 4. Decode with wrong password -> fail
    let status = Command::new(bin_path())
        .args([
            "zero-width",
            "decode",
            "-c",
            stego_path.to_str().unwrap(),
            "--password",
            "wrong_pwd",
        ])
        .status()
        .unwrap();
    assert!(!status.success());

    // 5. Decode with correct password
    let output = Command::new(bin_path())
        .args([
            "zero-width",
            "decode",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            "-",
            "--password",
            "zw_pwd_2026",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, secret_msg.as_bytes());

    // 6. Also test flag-based syntax: zero-width --decode
    let output = Command::new(bin_path())
        .args([
            "zero-width",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            "-",
            "--password",
            "zw_pwd_2026",
            "--decode",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, secret_msg.as_bytes());

    // 7. Strip zero-width data
    let status = Command::new(bin_path())
        .args([
            "zero-width",
            "strip",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            clean_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let cleaned_content = std::fs::read_to_string(&clean_path).unwrap();
    assert_eq!(cleaned_content, cover_text);
}

#[test]
fn test_force_extract_flag() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.png");
    let stego_path = dir.path().join("stego.png");
    let out_path = dir.path().join("out.txt");

    let png_bytes = create_test_png(100, 100);
    std::fs::write(&carrier_path, &png_bytes).unwrap();
    let secret = b"Resilient communication through partial data destruction.";

    // Inject
    let status = Command::new(bin_path())
        .args([
            "inject",
            "-c",
            carrier_path.to_str().unwrap(),
            "-p",
            std::str::from_utf8(secret).unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-b",
            "1",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    // Intentionally corrupt bytes in the embedded carrier pixel area (without destroying SLOP magic)
    // Decode PNG, alter a byte deep inside payload, re-encode
    let stego_bytes = std::fs::read(&stego_path).unwrap();
    let (w, h, mut rgba) = stegoslop_cli::io_utils::decode_png(&stego_bytes).unwrap();

    // The header is 14 bytes = 14 * 8 = 112 channels. Let's flip a bit at channel 200 (in the payload):
    rgba[200] ^= 0x01;
    let corrupted_png = stegoslop_cli::io_utils::encode_png(w, h, rgba).unwrap();
    let corrupted_path = dir.path().join("corrupted.png");
    std::fs::write(&corrupted_path, corrupted_png).unwrap();

    // Normal extract should fail due to CRC32 mismatch
    let status = Command::new(bin_path())
        .args([
            "extract",
            "-c",
            corrupted_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-b",
            "1",
        ])
        .status()
        .unwrap();
    assert!(!status.success());

    // Extract with --force should succeed despite CRC mismatch!
    let status = Command::new(bin_path())
        .args([
            "extract",
            "-c",
            corrupted_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-b",
            "1",
            "--force",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(out_path.exists());
}
