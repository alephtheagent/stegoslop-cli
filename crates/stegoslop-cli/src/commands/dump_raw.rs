use crate::io_utils::{self, CarrierType};
use anyhow::{anyhow, Result};
use clap::Args;

#[derive(Args, Debug, Clone)]
pub struct DumpRawArgs {
    /// Carrier file (PNG or WAV), or '-' for stdin
    #[arg(short = 'c', long = "carrier")]
    pub carrier: Option<String>,

    /// Positional carrier file if -c is omitted
    #[arg(value_name = "CARRIER")]
    pub carrier_pos: Option<String>,

    /// Output file path, or '-' for stdout
    #[arg(short = 'o', long = "output", default_value = "-")]
    pub output: String,

    /// Bits per unit (channel/sample): 1, 2, or 4
    #[arg(short = 'b', long = "bits", default_value = "1")]
    pub bits: usize,

    /// Maximum number of bytes to dump (default: all carrier capacity)
    #[arg(short = 'n', long = "bytes")]
    pub bytes: Option<usize>,
}

pub fn execute(args: DumpRawArgs) -> Result<()> {
    let carrier_src = args
        .carrier
        .or(args.carrier_pos)
        .ok_or_else(|| anyhow!("Carrier file must be specified with -c/--carrier or as argument"))?;

    if !matches!(args.bits, 1 | 2 | 4) {
        return Err(anyhow!(
            "Unsupported bits per unit: {}. Allowed values: 1, 2, 4.",
            args.bits
        ));
    }

    let carrier_bytes = io_utils::read_bytes(&carrier_src)?;
    let carrier_type =
        io_utils::detect_carrier_type_with_path(&carrier_bytes, Some(&carrier_src));

    let max_bytes = args.bytes.unwrap_or(usize::MAX);

    let raw_bytes = match carrier_type {
        CarrierType::Wav => {
            stegoslop_core::audio::extract_raw_bits_from_wav(&carrier_bytes, args.bits, max_bytes)?
        }
        CarrierType::Png => {
            let (_w, _h, rgba) = io_utils::decode_png(&carrier_bytes)?;
            stegoslop_core::image::extract_raw_bits_from_rgba(&rgba, args.bits, max_bytes)?
        }
        _ => {
            return Err(anyhow!(
                "Unsupported carrier format. StegoSlop requires PNG image or 16-bit PCM WAV audio."
            ));
        }
    };

    io_utils::write_bytes(Some(&args.output), &raw_bytes)?;

    if args.output != "-" {
        eprintln!(
            "[+] Dumped {} raw bytes to '{}' (bits: {})",
            raw_bytes.len(),
            args.output,
            args.bits
        );
    }

    Ok(())
}
