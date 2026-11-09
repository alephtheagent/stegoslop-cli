pub mod audio;
pub mod crypto;
pub mod error;
pub mod image;
pub mod protocol;
pub mod zero_width;

pub use audio::{embed_in_wav, extract_from_wav, extract_raw_bits_from_wav, parse_wav, WavInfo};
pub use error::{Result, StegoError};
pub use image::{
    compute_capacity, embed_in_rgba, extract_from_rgba, extract_raw_bits_from_rgba,
    generate_bit_plane,
};
pub use protocol::{
    pack_payload, unpack_payload, unpack_payload_forced, PayloadType, UnpackedPayload,
};
pub use zero_width::{
    decode as decode_zero_width, encode as encode_zero_width, has_hidden_data, strip_hidden_data,
};
