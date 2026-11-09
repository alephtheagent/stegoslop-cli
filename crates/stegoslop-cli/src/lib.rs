use anyhow::Result;
use clap::{Parser, Subcommand};

pub mod commands;
pub mod io_utils;

use commands::{
    bitplane::{self, BitplaneArgs},
    dump_raw::{self, DumpRawArgs},
    extract::{self, ExtractArgs},
    info::{self, InfoArgs},
    inject::{self, InjectArgs},
    zero_width::{self, ZeroWidthArgs},
};

#[derive(Parser, Debug)]
#[command(
    name = "stegoslop",
    author = "Nous Research / StegoSlop Contributors",
    version,
    about = "StegoSlop: Advanced LSB steganography in images and audio, and zero-width text steganography",
    long_about = "StegoSlop CLI provides unified steganography tools:\n\
                  - Inject payloads into PNG images or 16-bit PCM WAV audio\n\
                  - Extract embedded payloads with optional password decryption\n\
                  - Dump raw LSB bit streams without header parsing\n\
                  - Generate visual bit-plane slices (0-7)\n\
                  - Encode, decode, detect, and strip zero-width Unicode steganography in text\n\
                  - Inspect carrier capacity and scan for hidden payloads"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Embed secret payload into an image (PNG) or audio (WAV) carrier
    Inject(InjectArgs),
    /// Extract secret payload from an image (PNG) or audio (WAV) carrier
    Extract(ExtractArgs),
    /// Dump raw LSB bits from carrier without SLOP container parsing
    DumpRaw(DumpRawArgs),
    /// Visualize bit planes (0-7) of an image carrier as PNG
    Bitplane(BitplaneArgs),
    /// Encode, decode, detect, or strip zero-width steganography in text
    ZeroWidth(ZeroWidthArgs),
    /// Analyze carrier metadata, steganographic capacity, and detect hidden payloads
    Info(InfoArgs),
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    run_with_cli(cli)
}

pub fn run_with_cli(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Inject(args) => inject::execute(args),
        Commands::Extract(args) => extract::execute(args),
        Commands::DumpRaw(args) => dump_raw::execute(args),
        Commands::Bitplane(args) => bitplane::execute(args),
        Commands::ZeroWidth(args) => zero_width::execute(args),
        Commands::Info(args) => info::execute(args),
    }
}
