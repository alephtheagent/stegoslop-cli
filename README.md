# StegoSlop CLI

[![Build](https://github.com/alephtheagent/stegoslop-cli/actions/workflows/build.yml/badge.svg)](https://github.com/alephtheagent/stegoslop-cli/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

**StegoSlop** is a multi-carrier steganography CLI tool and Rust engine supporting:
- **LSB Embedding** in PNG images (RGBA, configurable 1/2/4 bits per channel)
- **LSB Embedding** in 16-bit PCM RIFF WAV audio (configurable 1/2/4 bits per sample)
- **Zero-Width Unicode Steganography** in UTF-8 plain text (ZWNJ `\u{200C}`, ZWJ `\u{200D}`, Word Joiner `\u{2060}`, BOM `\u{FEFF}`)
- **Authenticated Encryption** via AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation
- **Integrity Verification** via CRC32 checksums with optional `--force` extraction
- **Bit-plane Visualizer** for forensic inspection of image LSBs
- **Full Unix Pipeline Support** (`-` for stdin and stdout)

---

## Workspace Architecture

```
stegoslop-cli/
├── Cargo.toml                    # Root workspace definition
├── crates/
│   ├── stegoslop-core/           # Pure steganography engine (no CLI dependencies)
│   │   ├── src/
│   │   │   ├── protocol.rs       # SLOP binary framing, header parsing, CRC32
│   │   │   ├── crypto.rs         # AES-256-GCM + PBKDF2 encryption/decryption
│   │   │   ├── image.rs          # RGBA LSB injection/extraction & bit-planes
│   │   │   ├── audio.rs          # 16-bit PCM WAV LSB injection/extraction
│   │   │   ├── zero_width.rs     # Unicode zero-width text stego
│   │   │   └── error.rs          # Error definitions
│   │   └── tests/
│   │       └── cross_compatibility_test.rs
│   └── stegoslop-cli/            # Clap 4.5 CLI binary
│       ├── src/
│       │   ├── bin/              # `stegoslop` and `stegoslop-cli` binaries
│       │   ├── commands/         # Subcommand handlers (inject, extract, info, etc.)
│       │   ├── io_utils.rs       # File, image, and pipe I/O utilities
│       │   └── lib.rs            # CLI definition
│       └── tests/
│           └── cli_e2e_test.rs   # Comprehensive end-to-end integration tests
```

---

## Installation

### Prerequisites
- Rust 1.75+ (Cargo toolchain)

### Build and Install from Source
```bash
# Clone the repository
git clone https://github.com/alephtheagent/stegoslop-cli.git
cd stegoslop-cli

# Build release binaries
cargo build --release

# Install `stegoslop` to your Cargo binary path (~/.cargo/bin)
cargo install --path crates/stegoslop-cli
```

Verify installation:
```bash
stegoslop --help
```

---

## Command Reference

### 1. `inject` — Embed Secret Payload
Embed a file or raw string into an image or audio carrier.

```bash
# Basic image injection (1 bit per channel)
stegoslop inject -c cover.png -p secret.txt -o stego.png

# Audio injection with 2 bits per sample and AES-256-GCM encryption
stegoslop inject -c sound.wav -p payload.bin -o stego.wav -b 2 --password "my-passphrase"

# Preserve original filename in embedded metadata
stegoslop inject -c photo.png -p document.pdf -o stego.png --preserve-name

# Stream payload from stdin
echo "Confidential message" | stegoslop inject -c cover.png -p - -o stego.png
```

**Options:**
- `-c, --carrier <PATH>`: Carrier file (`.png` or `.wav`), or `-` for stdin.
- `-p, --payload <PATH|STR>`: Payload file path, raw string, or `-` for stdin.
- `-o, --output <PATH>`: Output file path, or `-` for stdout.
- `-b, --bits <1|2|4>`: Bits embedded per unit (channel/sample). Default: `1`.
- `--password <PWD>`: Password for AES-256-GCM encryption.
- `--preserve-name`: Embed original filename into container header.
- `--type <TYPE>`: Payload type override (`text`, `image`, `audio`, `file`).

---

### 2. `extract` — Extract Secret Payload
Extract hidden data from an image or audio carrier.

```bash
# Basic extraction to file
stegoslop extract -c stego.png -o recovered.txt

# Extract with automatic bit-depth probing (tests 1, 2, and 4 bits)
stegoslop extract -c stego.wav -o output.bin

# Extract encrypted payload
stegoslop extract -c stego.png -o recovered.txt --password "my-passphrase"

# Extract and restore original embedded filename
stegoslop extract -c stego.png --preserve-name

# Force extraction even if CRC32 checksum fails
stegoslop extract -c damaged_stego.png -o rescued.bin --force
```

**Options:**
- `-c, --carrier <PATH>`: Carrier file (`.png` or `.wav`), or `-` for stdin.
- `-o, --output <PATH>`: Output destination path, or `-` for stdout.
- `-b, --bits <1|2|4>`: Specific bits per unit (auto-probes 1, 2, 4 if omitted).
- `--password <PWD>`: Password for AES-256-GCM decryption.
- `--force`: Ignore CRC32 mismatches or partial corruption.
- `--preserve-name`: Restore payload using original filename stored in container.

---

### 3. `info` — Carrier Inspection & Stego Scanner
Inspect carrier specifications, calculate capacity at all bit depths, and probe for StegoSlop payloads.

```bash
stegoslop info -c photo.png
stegoslop info -c audio.wav
stegoslop info -c message.txt
```

Example output for audio carrier:
```text
=== StegoSlop Carrier Analysis ===
Source: sound.wav
Format:          RIFF WAVE Audio (16-bit PCM)
Channels:        2
Sample Rate:     44100 Hz
Bits Per Sample: 16
Total Samples:   88200
Duration:        1.000 s
Audio Data Size: 176400 bytes

Steganographic Capacity:
  1 bit/sample:  11025 bytes (10.77 KB)
  2 bits/sample: 22050 bytes (21.53 KB)
  4 bits/sample: 44100 bytes (43.07 KB)

Payload Detection Scan:
  [+] StegoSlop payload FOUND at 2 bit(s)/unit!
      Payload Type:   Text
      Payload Length: 64 bytes
      Encrypted:      false
      Filename:       note.txt
      CRC32 Status:   VALID
```

---

### 4. `bitplane` — Bit-plane Forensic Visualizer
Generate grayscale images isolating specific bit planes (bit 0 = LSB, bit 7 = MSB) to visually inspect steganographic noise or anomalies.

```bash
# Visualize bit 0 (LSB)
stegoslop bitplane -c photo.png -o lsb_plane.png -b 0

# Pipe bitplane image to stdout
stegoslop bitplane -c photo.png -b 0 -o - | feh -
```

---

### 5. `dump-raw` — Dump Raw LSB Bits
Extract raw bit sequences without parsing or validating the StegoSlop header.

```bash
# Dump first 256 bytes from LSBs of image to stdout
stegoslop dump-raw -c photo.png -b 1 -n 256

# Dump raw bits to file
stegoslop dump-raw -c audio.wav -b 2 -o raw_bits.bin
```

---

### 6. `zero-width` — Zero-Width Unicode Steganography
Hide secret data inside harmless plain text using invisible zero-width characters.

```bash
# Encode secret message into cover text
stegoslop zero-width encode -c "Meeting is tomorrow at noon." -p "Secret code 4492" -o stego.txt

# Encode with AES-256-GCM encryption
stegoslop zero-width encode -c cover.txt -p secret.txt -o stego.txt --password "agent-key"

# Detect if text contains hidden zero-width data
stegoslop zero-width detect -c stego.txt

# Decode secret message
stegoslop zero-width decode -c stego.txt -o - --password "agent-key"

# Strip zero-width steganography to sanitize text
stegoslop zero-width strip -c stego.txt -o clean.txt
```

---

### 7. Unix Pipe Pipelines
StegoSlop fully supports standard I/O streams using `-`:

```bash
# Embed into PNG and pipe directly to extractor:
stegoslop inject -c cover.png -p "Classified text" -o - \
  | stegoslop extract -c - -o -

# Encrypt and pipe payload from curl:
curl -s https://example.com/data.json \
  | stegoslop inject -c audio.wav -p - -o stego.wav --password "transit_key"
```

---

## Binary Protocol Specification (`SLOP`)

StegoSlop uses a standardized container framing:

| Offset | Field | Size | Description |
|---|---|---|---|
| `0..4` | Magic | 4 bytes | Constant ASCII `SLOP` |
| `4` | Type Code | 1 byte | `0x01` (Text), `0x02` (Image), `0x03` (Audio), `0x04` (File) |
| `5` | Flags | 1 byte | Bit 0: Encrypted, Bits 1..2: BPU (0=1b, 1=2b, 2=4b), Bit 3: Has Filename |
| `6..10` | Payload Length | 4 bytes | Big-endian length of payload |
| `10..14` | CRC32 | 4 bytes | Big-endian CRC32 of payload |
| `14..30` | Salt *(optional)* | 16 bytes | Present if encrypted (PBKDF2 salt) |
| `30..42` | IV *(optional)* | 12 bytes | Present if encrypted (AES-GCM nonce) |
| Var | Filename *(optional)* | 1 + N bytes | 1 byte length + UTF-8 filename bytes |
| End | Data | N bytes | Ciphertext or plaintext payload bytes |

---

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).
