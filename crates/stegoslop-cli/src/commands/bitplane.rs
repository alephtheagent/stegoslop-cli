use crate::io_utils::{self, CarrierType};
use anyhow::{anyhow, Result};
use clap::Args;
use std::path::Path;

#[derive(Args, Debug, Clone)]
pub struct BitplaneArgs {
    /// Carrier image file (PNG), or '-' for stdin
    #[arg(short = 'c', long = "carrier")]
    pub carrier: Option<String>,

    /// Positional carrier file if -c is omitted
    #[arg(value_name = "CARRIER")]
    pub carrier_pos: Option<String>,

    /// Output PNG file, or '-' for stdout
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Bit plane index (0 = LSB, 7 = MSB)
    #[arg(short = 'b', long = "bit", visible_alias = "bits", default_value = "0")]
    pub bit: usize,
}

pub fn execute(args: BitplaneArgs) -> Result<()> {
    let carrier_src = args
        .carrier
        .or(args.carrier_pos)
        .ok_or_else(|| anyhow!("Carrier file must be specified with -c/--carrier or as argument"))?;

    if args.bit > 7 {
        return Err(anyhow!(
            "Bitplane index must be between 0 (LSB) and 7 (MSB). Got {}.",
            args.bit
        ));
    }

    let carrier_bytes = io_utils::read_bytes(&carrier_src)?;
    let carrier_type =
        io_utils::detect_carrier_type_with_path(&carrier_bytes, Some(&carrier_src));

    if carrier_type != CarrierType::Png {
        return Err(anyhow!(
            "Bitplane extraction is only supported for PNG images."
        ));
    }

    let (width, height, rgba) = io_utils::decode_png(&carrier_bytes)?;
    let plane_rgba = stegoslop_core::image::generate_bit_plane(&rgba, args.bit);
    let output_png = io_utils::encode_png(width, height, plane_rgba)?;

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
                let parent = p.parent().unwrap_or(Path::new(""));
                parent
                    .join(format!("{}_bitplane_{}.png", stem, args.bit))
                    .to_string_lossy()
                    .to_string()
            }
        }
    };

    io_utils::write_bytes(Some(&dest), &output_png)?;

    if dest != "-" {
        eprintln!(
            "[+] Generated bitplane {} visualization -> '{}'",
            args.bit, dest
        );
    }

    Ok(())
}
