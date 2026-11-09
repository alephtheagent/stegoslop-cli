use crate::io_utils;
use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use std::io::{self, Write};

#[derive(Args, Debug, Clone)]
pub struct ZeroWidthArgs {
    /// Action subcommand: encode, decode, detect, strip
    #[command(subcommand)]
    pub action: Option<ZeroWidthSubcommand>,

    /// Cover or stego text or file, or '-' for stdin
    #[arg(short = 'c', long = "carrier")]
    pub carrier: Option<String>,

    /// Positional carrier text or file
    #[arg(value_name = "CARRIER")]
    pub carrier_pos: Option<String>,

    /// Payload secret text or file, or '-' for stdin
    #[arg(short = 'p', long = "payload")]
    pub payload: Option<String>,

    /// Positional payload secret text or file
    #[arg(value_name = "PAYLOAD")]
    pub payload_pos: Option<String>,

    /// Output file or '-' for stdout
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Password for AES-256-GCM encryption/decryption
    #[arg(long = "password")]
    pub password: Option<String>,

    /// Detect if text contains hidden zero-width data
    #[arg(long = "detect")]
    pub detect: bool,

    /// Strip all hidden zero-width characters from text
    #[arg(long = "strip")]
    pub strip: bool,

    /// Decode hidden data from text
    #[arg(long = "decode")]
    pub decode: bool,

    /// Encode hidden data into cover text
    #[arg(long = "encode")]
    pub encode: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ZeroWidthSubcommand {
    /// Hide secret data into cover text
    Encode(ZeroWidthActionArgs),
    /// Extract secret data from stego text
    Decode(ZeroWidthActionArgs),
    /// Detect if text contains hidden zero-width data
    Detect(ZeroWidthActionArgs),
    /// Strip hidden zero-width characters from text
    Strip(ZeroWidthActionArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ZeroWidthActionArgs {
    /// Cover or stego text or file, or '-' for stdin
    #[arg(short = 'c', long = "carrier")]
    pub carrier: Option<String>,

    /// Positional carrier text or file
    #[arg(value_name = "CARRIER")]
    pub carrier_pos: Option<String>,

    /// Payload secret text or file, or '-' for stdin
    #[arg(short = 'p', long = "payload")]
    pub payload: Option<String>,

    /// Positional payload secret text or file
    #[arg(value_name = "PAYLOAD")]
    pub payload_pos: Option<String>,

    /// Output file or '-' for stdout
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Password for AES-256-GCM encryption/decryption
    #[arg(long = "password")]
    pub password: Option<String>,
}

pub fn execute(args: ZeroWidthArgs) -> Result<()> {
    match args.action {
        Some(ZeroWidthSubcommand::Encode(a)) => run_encode(a),
        Some(ZeroWidthSubcommand::Decode(a)) => run_decode(a),
        Some(ZeroWidthSubcommand::Detect(a)) => run_detect(a),
        Some(ZeroWidthSubcommand::Strip(a)) => run_strip(a),
        None => {
            let action_args = ZeroWidthActionArgs {
                carrier: args.carrier.or(args.carrier_pos),
                carrier_pos: None,
                payload: args.payload.or(args.payload_pos),
                payload_pos: None,
                output: args.output,
                password: args.password,
            };

            if args.detect {
                run_detect(action_args)
            } else if args.strip {
                run_strip(action_args)
            } else if args.decode {
                run_decode(action_args)
            } else if args.encode || action_args.payload.is_some() {
                run_encode(action_args)
            } else {
                // If neither payload nor encode is specified, default to decode
                run_decode(action_args)
            }
        }
    }
}

fn run_encode(args: ZeroWidthActionArgs) -> Result<()> {
    let carrier_src = args
        .carrier
        .or(args.carrier_pos)
        .ok_or_else(|| anyhow!("Cover text must be specified with -c/--carrier or as argument"))?;

    let payload_src = args.payload.or(args.payload_pos).ok_or_else(|| {
        anyhow!("Secret payload must be specified with -p/--payload or as argument")
    })?;

    let cover_text = io_utils::read_text(&carrier_src)?;
    let payload_input = io_utils::read_payload(&payload_src)?;

    let encoded_text = stegoslop_core::zero_width::encode(
        &cover_text,
        &payload_input.data,
        args.password.as_deref(),
    )?;

    io_utils::write_bytes(args.output.as_deref(), encoded_text.as_bytes())?;

    if let Some(ref dest) = args.output {
        if dest != "-" {
            eprintln!(
                "[+] Zero-width data successfully encoded into '{}'",
                dest
            );
        }
    }

    Ok(())
}

fn run_decode(args: ZeroWidthActionArgs) -> Result<()> {
    let carrier_src = args
        .carrier
        .or(args.carrier_pos)
        .ok_or_else(|| anyhow!("Stego text must be specified with -c/--carrier or as argument"))?;

    let stego_text = io_utils::read_text(&carrier_src)?;
    let secret_bytes =
        stegoslop_core::zero_width::decode(&stego_text, args.password.as_deref())?;

    if let Some(ref dest) = args.output {
        if dest != "-" {
            std::fs::write(dest, &secret_bytes)
                .map_err(|e| anyhow!("Failed to write to file '{}': {e}", dest))?;
            eprintln!(
                "[+] Decoded {} bytes -> '{}'",
                secret_bytes.len(),
                dest
            );
            return Ok(());
        }
    }

    // Default or output == "-": write to stdout
    let mut stdout = io::stdout().lock();
    stdout.write_all(&secret_bytes)?;
    stdout.flush()?;
    Ok(())
}

fn run_detect(args: ZeroWidthActionArgs) -> Result<()> {
    let carrier_src = args
        .carrier
        .or(args.carrier_pos)
        .ok_or_else(|| anyhow!("Text to inspect must be specified with -c/--carrier or as argument"))?;

    let text = io_utils::read_text(&carrier_src)?;
    let has_stego = stegoslop_core::zero_width::has_hidden_data(&text);

    if has_stego {
        println!("[+] Zero-width hidden data detected: YES");
    } else {
        println!("[-] Zero-width hidden data detected: NO");
    }

    Ok(())
}

fn run_strip(args: ZeroWidthActionArgs) -> Result<()> {
    let carrier_src = args
        .carrier
        .or(args.carrier_pos)
        .ok_or_else(|| anyhow!("Text to clean must be specified with -c/--carrier or as argument"))?;

    let text = io_utils::read_text(&carrier_src)?;
    let clean_text = stegoslop_core::zero_width::strip_hidden_data(&text);

    io_utils::write_bytes(args.output.as_deref(), clean_text.as_bytes())?;

    if let Some(ref dest) = args.output {
        if dest != "-" {
            eprintln!("[+] Cleaned text written to '{}'", dest);
        }
    }

    Ok(())
}
