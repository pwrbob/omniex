#![forbid(unsafe_code)]
#![allow(clippy::chunks_exact_to_as_chunks)]

//! `omniex` public facade: hash types, registry, and derive re-export.
//!
//! The data model lives in `omniex-core`. This crate holds the concrete hash
//! types and the registry the CLI dispatches through.

extern crate self as omniex;

pub use omniex_core::*;
pub use omniex_macros::HashType;

pub mod extract;
pub mod format;
pub mod json;

pub mod parse;
pub mod registry;
pub mod types;

/// Decodes one JSON field value using its recorded encoding.
pub trait FromFieldValue: Sized {
    /// Decodes `value` according to `encoding`.
    fn from_field_value(value: &str, encoding: Encoding) -> Result<Self, String>;
}

impl FromFieldValue for String {
    fn from_field_value(value: &str, encoding: Encoding) -> Result<Self, String> {
        match encoding {
            Encoding::Ascii | Encoding::Decimal => Ok(value.to_owned()),
            Encoding::Hex => Ok(String::from_utf8(
                hex::decode(value).map_err(|error| format!("invalid hex: {error}"))?,
            )
            .map_err(|error| format!("invalid UTF-8: {error}"))?),
            Encoding::Base64 => Ok(String::from_utf8(
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
                    .map_err(|error| format!("invalid base64: {error}"))?,
            )
            .map_err(|error| format!("invalid UTF-8: {error}"))?),
            Encoding::Raw => Err("cannot decode raw values".to_owned()),
        }
    }
}

impl FromFieldValue for Vec<u8> {
    fn from_field_value(value: &str, encoding: Encoding) -> Result<Self, String> {
        match encoding {
            Encoding::Ascii => Ok(value.as_bytes().to_vec()),
            Encoding::Hex => hex::decode(value).map_err(|error| format!("invalid hex: {error}")),
            Encoding::Base64 => {
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
                    .map_err(|error| format!("invalid base64: {error}"))
            }
            other => Err(format!("cannot decode {other:?} into bytes")),
        }
    }
}

impl<const N: usize> FromFieldValue for [u8; N] {
    fn from_field_value(value: &str, encoding: Encoding) -> Result<Self, String> {
        let bytes = Vec::<u8>::from_field_value(value, encoding)?;
        bytes
            .try_into()
            .map_err(|_| format!("expected {N} bytes, got {}", value.len()))
    }
}

macro_rules! decimal_field {
    ($($ty:ty),* $(,)?) => {
        $(
            impl FromFieldValue for $ty {
                fn from_field_value(value: &str, encoding: Encoding) -> Result<Self, String> {
                    match encoding {
                        Encoding::Decimal => value
                            .parse::<$ty>()
                            .map_err(|error| format!("invalid decimal: {error}")),
                        other => Err(format!("cannot decode {other:?} into {}", stringify!($ty))),
                    }
                }
            }
        )*
    };
}

decimal_field!(u8, u16, u32, u64);
