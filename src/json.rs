//! JSON hash documents used by the `json` output tool.

use omniex_core::{Encoding, FieldRole, HashTypeDescriptor, HashValue};

/// Builds an `omniex.hash.v1` document for one hash value.
#[must_use]
pub fn hash_document(descriptor: &HashTypeDescriptor, value: &dyn HashValue) -> serde_json::Value {
    let fields = value
        .describe()
        .into_iter()
        .map(|entry| {
            (
                entry.field.name.to_owned(),
                serde_json::json!({
                    "role": role_name(entry.field.role),
                    "encoding": encoding_name(entry.field.encoding),
                    "value": entry.value,
                }),
            )
        })
        .collect::<serde_json::Map<String, serde_json::Value>>();

    serde_json::json!({
        "schema": "omniex.hash.v1",
        "type": descriptor.slug,
        "fields": fields,
    })
}

/// Human-readable name for a field role.
#[must_use]
pub fn role_name(role: FieldRole) -> &'static str {
    match role {
        FieldRole::Salt => "salt",
        FieldRole::Key => "key",
        FieldRole::Digest => "digest",
        FieldRole::Iv => "iv",
        FieldRole::Ciphertext => "ciphertext",
        FieldRole::Iterations => "iterations",
        FieldRole::Username => "username",
        FieldRole::Other => "other",
    }
}

/// Human-readable name for a field encoding.
#[must_use]
pub fn encoding_name(encoding: Encoding) -> &'static str {
    match encoding {
        Encoding::Raw => "raw",
        Encoding::Hex => "hex",
        Encoding::Base64 => "base64",
        Encoding::Decimal => "decimal",
        Encoding::Ascii => "ascii",
    }
}
