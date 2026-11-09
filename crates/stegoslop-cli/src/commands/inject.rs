use crate::io_utils::{self, CarrierType};
use anyhow::{anyhow, Result};
use clap::Args;
use std::path::Path;

#[derive(Args, Debug, Clone)]
pub struct InjectArgs {
    /// Carrier file (PNG or WAV), or '-' for stdin
    #[arg(short = 'c', long = "carrier")]
    pub carrier: Option<String>,

    /// Positional carrier file if -c is omitted
    #[arg(value_name = "CARRIER")]
    pub carrier_pos: Option<String>,

    /// Payload file, raw string, or '-' for stdin
    #[arg(short = 'p', long = "payload")]
    pub payload: Option<String>,

    /// Positional payload if -p is omitted
    #[arg(value_name = "PAYLOAD")]
    pub payload_pos: Option<String>,

    /// Output file path, or '-' for stdout
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Bits per unit (channel/sample): 1, 2, or 4
    #[arg(short = 'b', long = "bits", default_value = "1")]
    pub bits: usize,

    /// Password for AES-256-GCM encryption
    #[arg(long = "password")]
    pub password: Option<String>,

    /// Embed and preserve the original filename in payload metadata
    #[arg(long = "preserve-name")]
    pub preserve_name: bool,

    /// Override payload type: text, image, audio, file (default: auto-detected)
    #[arg(long = "type")]
    pub payload_type: Option<String>,
}

pub fn execute(args: InjectArgs) -> Result<()> {
    let carrier_src = args
        .carrier
        .or(args.carrier_pos)
        .ok_or_else(|| anyhow!("Carrier file must be specified with -c/--carrier or as argument"))?;

    let payload_src = args
        .payload
        .or(args.payload_pos)
        .ok_or_else(|| anyhow!("Payload must be specified with -p/--payload or as argument"))?;

    if !matches!(args.bits, 1 | 2 | 4) {
        return Err(anyhow!(
            "Unsupported bits per unit: {}. Allowed values: 1, 2, 4.",
            args.bits
        ));
    }

    let carrier_bytes = io_utils::read_bytes(&carrier_src)?;
    let carrier_type =
        io_utils::detect_carrier_type_with_path(&carrier_bytes, Some(&carrier_src));

    let payload_input = io_utils::read_payload(&payload_src)?;
    let file_name_to_embed = if args.preserve_name {
        payload_input.file_name.as_deref()
    } else {
        None
    };

    let p_type = io_utils::detect_payload_type(
        args.payload_type.as_deref(),
        payload_input.file_name.as_deref(),
        &payload_input.data,
    );

    let packed = stegoslop_core::protocol::pack_payload(
        p_type,
        &payload_input.data,
        args.password.as_deref(),
        args.bits,
        file_name_to_embed,
    )?;

    let output_bytes = match carrier_type {
        CarrierType::Wav => {
            stegoslop_core::audio::embed_in_wav(&carrier_bytes, &packed, args.bits)?
        }
        CarrierType::Png => {
            let (width, height, mut rgba) = io_utils::decode_png(&carrier_bytes)?;
            stegoslop_core::image::embed_in_rgba(&mut rgba, &packed, args.bits)?;
            io_utils::encode_png(width, height, rgba)?
        }
        _ => {
            return Err(anyhow!(
                "Unsupported carrier format. StegoSlop requires PNG image or 16-bit PCM WAV audio."
            ));
        }
    };

    let dest = match args.output {
        Some(o) => o,
        None => {
            if carrier_src == "-" {
                "-".to_string()
            } else {
                let p = Path::new(&carrier_src);
                let stem = p
                    .file_stem()
                    .map(|s| s.to_string_lossy())
                    .unwrap_or_default();
                let ext = p
                    .extension()
                    .map(|e| format!(".{}", e.to_string_lossy()))
                    .unwrap_or_default();
                let parent = p.parent().unwrap_or(Path::new(""));
                parent
                    .join(format!("{}_stego{}", stem, ext))
                    .to_string_lossy()
                    .to_string()
            }
        }
    };

    io_utils::write_bytes(Some(&dest), &output_bytes)?;

    if dest != "-" {
        eprintln!(
            "[+] Injected {} bytes of payload into '{}' (bits: {}, encrypted: {})",
            payload_input.data.len(),
            dest,
            args.bits,
            args.password.is_some()
        );
    }

    Ok(())
}
