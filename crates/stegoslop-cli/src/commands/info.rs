use crate::io_utils::{self, CarrierType};
use anyhow::{anyhow, Result};
use clap::Args;
use stegoslop_core::protocol::unpack_payload;

#[derive(Args, Debug, Clone)]
pub struct InfoArgs {
    /// Carrier file to inspect, or '-' for stdin
    #[arg(short = 'c', long = "carrier")]
    pub carrier: Option<String>,

    /// Positional carrier file if -c is omitted
    #[arg(value_name = "CARRIER")]
    pub carrier_pos: Option<String>,

    /// Specific bits per unit to test (1, 2, or 4). Default: test all.
    #[arg(short = 'b', long = "bits")]
    pub bits: Option<usize>,

    /// Password to test decryption if payload is encrypted
    #[arg(long = "password")]
    pub password: Option<String>,
}

pub fn execute(args: InfoArgs) -> Result<()> {
    let carrier_src = args
        .carrier
        .or(args.carrier_pos)
        .ok_or_else(|| anyhow!("Carrier file must be specified with -c/--carrier or as argument"))?;

    let carrier_bytes = io_utils::read_bytes(&carrier_src)?;
    let carrier_type =
        io_utils::detect_carrier_type_with_path(&carrier_bytes, Some(&carrier_src));

    let bits_to_test = match args.bits {
        Some(b) => {
            if !matches!(b, 1 | 2 | 4) {
                return Err(anyhow!(
                    "Unsupported bits per unit: {}. Allowed values: 1, 2, 4.",
                    b
                ));
            }
            vec![b]
        }
        None => vec![1, 2, 4],
    };

    println!("=== StegoSlop Carrier Analysis ===");
    println!("Source: {}", carrier_src);

    match carrier_type {
        CarrierType::Wav => {
            let wav_info = stegoslop_core::audio::parse_wav(&carrier_bytes)?;
            println!("Format:          RIFF WAVE Audio (16-bit PCM)");
            println!("Channels:        {}", wav_info.num_channels);
            println!("Sample Rate:     {} Hz", wav_info.sample_rate);
            println!("Bits Per Sample: {}", wav_info.bits_per_sample);
            println!("Total Samples:   {}", wav_info.total_samples());
            println!("Duration:        {:.3} s", wav_info.duration_seconds());
            println!("Audio Data Size: {} bytes", wav_info.data_size);
            println!("\nSteganographic Capacity:");
            println!(
                "  1 bit/sample:  {} bytes ({:.2} KB)",
                wav_info.capacity(1),
                wav_info.capacity(1) as f64 / 1024.0
            );
            println!(
                "  2 bits/sample: {} bytes ({:.2} KB)",
                wav_info.capacity(2),
                wav_info.capacity(2) as f64 / 1024.0
            );
            println!(
                "  4 bits/sample: {} bytes ({:.2} KB)",
                wav_info.capacity(4),
                wav_info.capacity(4) as f64 / 1024.0
            );

            println!("\nPayload Detection Scan:");
            let mut detected = false;
            for &b in &bits_to_test {
                if let Ok(container) = stegoslop_core::audio::extract_from_wav(&carrier_bytes, b) {
                    if print_container_details(&container, b, args.password.as_deref()) {
                        detected = true;
                    }
                }
            }
            if !detected {
                println!("  [-] No StegoSlop payload detected at tested bit rates.");
            }
        }
        CarrierType::Png => {
            let (width, height, rgba) = io_utils::decode_png(&carrier_bytes)?;
            let total_pixels = width as usize * height as usize;
            println!("Format:          PNG Image (RGBA)");
            println!("Dimensions:      {}x{} ({} pixels)", width, height, total_pixels);
            println!("Usable Channels: 3 (R, G, B)");
            println!("\nSteganographic Capacity:");
            let cap1 = stegoslop_core::image::compute_capacity(width, height, 1)?;
            let cap2 = stegoslop_core::image::compute_capacity(width, height, 2)?;
            let cap4 = stegoslop_core::image::compute_capacity(width, height, 4)?;
            println!("  1 bit/channel:  {} bytes ({:.2} KB)", cap1, cap1 as f64 / 1024.0);
            println!("  2 bits/channel: {} bytes ({:.2} KB)", cap2, cap2 as f64 / 1024.0);
            println!("  4 bits/channel: {} bytes ({:.2} KB)", cap4, cap4 as f64 / 1024.0);

            println!("\nPayload Detection Scan:");
            let mut detected = false;
            for &b in &bits_to_test {
                if let Ok(container) = stegoslop_core::image::extract_from_rgba(&rgba, b) {
                    if print_container_details(&container, b, args.password.as_deref()) {
                        detected = true;
                    }
                }
            }
            if !detected {
                println!("  [-] No StegoSlop payload detected at tested bit rates.");
            }
        }
        CarrierType::Text => {
            let text = std::str::from_utf8(&carrier_bytes).unwrap_or("");
            println!("Format:          Unicode / UTF-8 Plain Text");
            println!("Length:          {} chars ({} bytes)", text.chars().count(), text.len());
            let has_zw = stegoslop_core::zero_width::has_hidden_data(text);
            println!("Zero-Width Stego: {}", if has_zw { "DETECTED" } else { "None" });
            if has_zw {
                match stegoslop_core::zero_width::decode(text, args.password.as_deref()) {
                    Ok(data) => {
                        println!("  [+] Successfully decoded payload: {} bytes", data.len());
                        if let Ok(utf8_msg) = std::str::from_utf8(&data) {
                            println!("      Preview: {}", utf8_msg);
                        }
                    }
                    Err(e) => {
                        println!("  [!] Hidden data present but decode failed: {e}");
                    }
                }
            }
        }
        CarrierType::SlopContainer => {
            println!("Format:          Raw StegoSlop Binary Container");
            println!("Container Size:  {} bytes", carrier_bytes.len());
            print_container_details(&carrier_bytes, 0, args.password.as_deref());
        }
        CarrierType::Unknown => {
            println!("Format:          Unknown / Unsupported Binary Carrier");
            println!("Size:            {} bytes", carrier_bytes.len());
        }
    }

    Ok(())
}

fn print_container_details(container: &[u8], bits: usize, password: Option<&str>) -> bool {
    let bit_str = if bits > 0 {
        format!(" at {} bit(s)/unit", bits)
    } else {
        String::new()
    };

    match unpack_payload(container, password) {
        Ok(unpacked) => {
            println!("  [+] StegoSlop payload FOUND{}!", bit_str);
            println!("      Payload Type:   {:?}", unpacked.payload_type);
            println!("      Payload Length: {} bytes", unpacked.data.len());
            println!("      Encrypted:      {}", unpacked.is_encrypted);
            println!(
                "      Filename:       {}",
                unpacked.file_name.as_deref().unwrap_or("<none>")
            );
            println!(
                "      CRC32 Status:   {}",
                if unpacked.is_corrupted { "CORRUPTED" } else { "VALID" }
            );
            true
        }
        Err(stegoslop_core::StegoError::PasswordRequired) => {
            println!("  [+] StegoSlop payload FOUND{}!", bit_str);
            println!("      Encrypted:      YES (Password required to view metadata)");
            true
        }
        Err(stegoslop_core::StegoError::DecryptionFailed) => {
            println!("  [+] StegoSlop payload FOUND{}!", bit_str);
            println!("      Encrypted:      YES (Decryption failed with provided password)");
            true
        }
        Err(_) => false,
    }
}
