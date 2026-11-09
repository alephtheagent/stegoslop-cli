use crate::io_utils::{self, CarrierType};
use anyhow::{anyhow, Result};
use clap::Args;
use std::io::{self, Write};
use std::path::Path;
use stegoslop_core::protocol::{unpack_payload, unpack_payload_forced, UnpackedPayload};

#[derive(Args, Debug, Clone)]
pub struct ExtractArgs {
    /// Carrier file (PNG or WAV), or '-' for stdin
    #[arg(short = 'c', long = "carrier")]
    pub carrier: Option<String>,

    /// Positional carrier file if -c is omitted
    #[arg(value_name = "CARRIER")]
    pub carrier_pos: Option<String>,

    /// Output file or directory, or '-' for stdout
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Bits per unit (channel/sample): 1, 2, or 4. Auto-detected if omitted.
    #[arg(short = 'b', long = "bits")]
    pub bits: Option<usize>,

    /// Password for AES-256-GCM decryption
    #[arg(long = "password")]
    pub password: Option<String>,

    /// Force extraction even if CRC32 check fails or data is corrupted
    #[arg(long = "force")]
    pub force: bool,

    /// Restore extracted file using original filename stored in container
    #[arg(long = "preserve-name")]
    pub preserve_name: bool,
}

pub fn execute(args: ExtractArgs) -> Result<()> {
    let carrier_src = args
        .carrier
        .or(args.carrier_pos)
        .ok_or_else(|| anyhow!("Carrier file must be specified with -c/--carrier or as argument"))?;

    let carrier_bytes = io_utils::read_bytes(&carrier_src)?;
    let carrier_type =
        io_utils::detect_carrier_type_with_path(&carrier_bytes, Some(&carrier_src));

    let bits_candidates: Vec<usize> = match args.bits {
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

    let mut unpacked_payload: Option<UnpackedPayload> = None;
    let mut last_error = None;

    for &b in &bits_candidates {
        let container_result = match carrier_type {
            CarrierType::Wav => stegoslop_core::audio::extract_from_wav(&carrier_bytes, b),
            CarrierType::Png => {
                match io_utils::decode_png(&carrier_bytes) {
                    Ok((_w, _h, rgba)) => stegoslop_core::image::extract_from_rgba(&rgba, b),
                    Err(e) => {
                        last_error = Some(e);
                        continue;
                    }
                }
            }
            _ => {
                return Err(anyhow!(
                    "Unsupported carrier format. StegoSlop requires PNG image or 16-bit PCM WAV audio."
                ));
            }
        };

        match container_result {
            Ok(container) => {
                let unpack_res = if args.force {
                    unpack_payload_forced(&container, args.password.as_deref())
                } else {
                    unpack_payload(&container, args.password.as_deref())
                };

                match unpack_res {
                    Ok(unpacked) => {
                        unpacked_payload = Some(unpacked);
                        break;
                    }
                    Err(e) => {
                        last_error = Some(anyhow!(e));
                    }
                }
            }
            Err(e) => {
                last_error = Some(anyhow!(e));
            }
        }
    }

    let unpacked = match unpacked_payload {
        Some(p) => p,
        None => {
            if let Some(err) = last_error {
                return Err(anyhow!(
                    "Failed to extract payload (tested bits {:?}): {}",
                    bits_candidates,
                    err
                ));
            } else {
                return Err(anyhow!("No valid StegoSlop container found in carrier."));
            }
        }
    };

    if unpacked.is_corrupted {
        eprintln!("[!] Warning: Payload CRC mismatch! Data may be corrupted.");
    }

    let is_stdout = match args.output.as_deref() {
        Some("-") => true,
        _ => false,
    };

    if is_stdout {
        let mut stdout = io::stdout().lock();
        stdout.write_all(&unpacked.data)?;
        stdout.flush()?;
        return Ok(());
    }

    // Determine target output file path
    let target_path = if args.preserve_name {
        if let Some(ref name) = unpacked.file_name {
            if let Some(ref out) = args.output {
                let p = Path::new(out);
                if p.is_dir() {
                    Some(p.join(name))
                } else {
                    Some(p.to_path_buf())
                }
            } else {
                Some(Path::new(name).to_path_buf())
            }
        } else if let Some(ref out) = args.output {
            Some(Path::new(out).to_path_buf())
        } else {
            None
        }
    } else if let Some(ref out) = args.output {
        let p = Path::new(out);
        if p.is_dir() {
            if let Some(ref name) = unpacked.file_name {
                Some(p.join(name))
            } else {
                Some(p.join("extracted.bin"))
            }
        } else {
            Some(p.to_path_buf())
        }
    } else if let Some(ref name) = unpacked.file_name {
        Some(Path::new(name).to_path_buf())
    } else {
        None
    };

    if let Some(path) = target_path {
        std::fs::write(&path, &unpacked.data)
            .map_err(|e| anyhow!("Failed to write to '{}': {e}", path.display()))?;
        eprintln!(
            "[+] Extracted {} bytes successfully -> '{}'",
            unpacked.data.len(),
            path.display()
        );
    } else {
        // Fallback: output to stdout
        let mut stdout = io::stdout().lock();
        stdout.write_all(&unpacked.data)?;
        stdout.flush()?;
    }

    Ok(())
}
