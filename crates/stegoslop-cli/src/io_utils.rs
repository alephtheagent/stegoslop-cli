use anyhow::{anyhow, Result};
use image::{ImageBuffer, ImageFormat, RgbaImage};
use std::io::{self, Cursor, Read, Write};
use std::path::Path;
use stegoslop_core::PayloadType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierType {
    Png,
    Wav,
    Text,
    SlopContainer,
    Unknown,
}

pub fn detect_carrier_type(bytes: &[u8]) -> CarrierType {
    if bytes.len() >= 8 && &bytes[0..8] == b"\x89PNG\r\n\x1a\n" {
        CarrierType::Png
    } else if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WAVE" {
        CarrierType::Wav
    } else if bytes.len() >= 4 && &bytes[0..4] == b"SLOP" {
        CarrierType::SlopContainer
    } else if !bytes.is_empty() && std::str::from_utf8(bytes).is_ok() {
        CarrierType::Text
    } else {
        CarrierType::Unknown
    }
}

pub fn detect_carrier_type_with_path(bytes: &[u8], path: Option<&str>) -> CarrierType {
    let detected = detect_carrier_type(bytes);
    if detected != CarrierType::Unknown {
        return detected;
    }
    if let Some(p) = path {
        let lower = p.to_lowercase();
        if lower.ends_with(".png") {
            return CarrierType::Png;
        } else if lower.ends_with(".wav") {
            return CarrierType::Wav;
        } else if lower.ends_with(".txt") || lower.ends_with(".md") {
            return CarrierType::Text;
        }
    }
    CarrierType::Unknown
}

pub fn read_bytes(source: &str) -> Result<Vec<u8>> {
    if source == "-" {
        let mut buffer = Vec::new();
        io::stdin()
            .lock()
            .read_to_end(&mut buffer)
            .map_err(|e| anyhow!("Failed to read stdin: {e}"))?;
        Ok(buffer)
    } else {
        std::fs::read(source).map_err(|e| anyhow!("Failed to read file '{}': {e}", source))
    }
}

pub fn read_text(source: &str) -> Result<String> {
    if source == "-" {
        let mut buffer = String::new();
        io::stdin()
            .lock()
            .read_to_string(&mut buffer)
            .map_err(|e| anyhow!("Failed to read stdin: {e}"))?;
        Ok(buffer)
    } else if Path::new(source).exists() {
        std::fs::read_to_string(source)
            .map_err(|e| anyhow!("Failed to read file '{}': {e}", source))
    } else {
        // Treat as literal text string
        Ok(source.to_string())
    }
}

pub struct PayloadInput {
    pub data: Vec<u8>,
    pub file_name: Option<String>,
}

pub fn read_payload(source: &str) -> Result<PayloadInput> {
    if source == "-" {
        let mut data = Vec::new();
        io::stdin()
            .lock()
            .read_to_end(&mut data)
            .map_err(|e| anyhow!("Failed to read payload from stdin: {e}"))?;
        Ok(PayloadInput {
            data,
            file_name: None,
        })
    } else if Path::new(source).exists() {
        let data = std::fs::read(source)
            .map_err(|e| anyhow!("Failed to read payload file '{}': {e}", source))?;
        let file_name = Path::new(source)
            .file_name()
            .map(|s| s.to_string_lossy().to_string());
        Ok(PayloadInput { data, file_name })
    } else {
        // Treat as literal string input
        Ok(PayloadInput {
            data: source.as_bytes().to_vec(),
            file_name: None,
        })
    }
}

pub fn write_bytes(dest: Option<&str>, data: &[u8]) -> Result<()> {
    match dest {
        Some("-") | None => {
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(data)
                .map_err(|e| anyhow!("Failed to write to stdout: {e}"))?;
            stdout
                .flush()
                .map_err(|e| anyhow!("Failed to flush stdout: {e}"))?;
            Ok(())
        }
        Some(path) => std::fs::write(path, data)
            .map_err(|e| anyhow!("Failed to write to file '{}': {e}", path)),
    }
}

pub fn detect_payload_type(
    type_override: Option<&str>,
    file_name: Option<&str>,
    data: &[u8],
) -> PayloadType {
    if let Some(t) = type_override {
        match t.to_lowercase().as_str() {
            "text" | "txt" => return PayloadType::Text,
            "image" | "img" => return PayloadType::Image,
            "audio" | "snd" => return PayloadType::Audio,
            "file" | "bin" => return PayloadType::File,
            _ => {}
        }
    }

    if let Some(name) = file_name {
        let lower = name.to_lowercase();
        if lower.ends_with(".txt")
            || lower.ends_with(".md")
            || lower.ends_with(".json")
            || lower.ends_with(".csv")
            || lower.ends_with(".xml")
            || lower.ends_with(".html")
        {
            return PayloadType::Text;
        } else if lower.ends_with(".png")
            || lower.ends_with(".jpg")
            || lower.ends_with(".jpeg")
            || lower.ends_with(".webp")
            || lower.ends_with(".bmp")
            || lower.ends_with(".gif")
        {
            return PayloadType::Image;
        } else if lower.ends_with(".wav")
            || lower.ends_with(".mp3")
            || lower.ends_with(".ogg")
            || lower.ends_with(".opus")
            || lower.ends_with(".flac")
        {
            return PayloadType::Audio;
        }
    }

    if std::str::from_utf8(data).is_ok() {
        PayloadType::Text
    } else {
        PayloadType::File
    }
}

pub fn decode_png(bytes: &[u8]) -> Result<(u32, u32, Vec<u8>)> {
    let img = image::load_from_memory_with_format(bytes, ImageFormat::Png)
        .or_else(|_| image::load_from_memory(bytes))
        .map_err(|e| anyhow!("Failed to decode PNG image: {e}"))?;
    let rgba = img.to_rgba8();
    let (width, height) = (rgba.width(), rgba.height());
    Ok((width, height, rgba.into_raw()))
}

pub fn encode_png(width: u32, height: u32, rgba_data: Vec<u8>) -> Result<Vec<u8>> {
    let img: RgbaImage = ImageBuffer::from_raw(width, height, rgba_data)
        .ok_or_else(|| anyhow!("Failed to create ImageBuffer: buffer size mismatch"))?;
    let mut buf = Vec::new();
    let mut cursor = Cursor::new(&mut buf);
    img.write_to(&mut cursor, ImageFormat::Png)
        .map_err(|e| anyhow!("Failed to encode image to PNG: {e}"))?;
    Ok(buf)
}
