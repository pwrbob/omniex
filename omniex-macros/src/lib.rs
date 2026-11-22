#![forbid(unsafe_code)]

//! Derive macro for hash-type metadata.
//!
//! See `internals/MACROS.md` for the supported attribute syntax. The derive only
//! generates metadata and the inherent descriptor; `Parse` and `Render` are
//! implemented by hand.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{ToTokens, quote};
use syn::spanned::Spanned;
use syn::{
    Attribute, Data, DeriveInput, Expr, ExprArray, ExprLit, Field, Fields, Ident, Lit, LitStr,
    Path, parse_macro_input,
};

#[proc_macro_derive(HashType, attributes(hash, field))]
pub fn derive_hash_type(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

struct HashAttrs {
    name: LitStr,
    slug: LitStr,
    hashcat: Vec<u32>,
    john: Vec<String>,
    modes_fn: Option<Path>,
}

struct FieldAttrs {
    role: String,
    encoding: String,
    rename: Option<String>,
    ty: Option<String>,
}

fn expand(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(
            input.generics.span(),
            "HashType cannot be derived for generic structs",
        ));
    }

    let data = match &input.data {
        Data::Struct(data) => data,
        Data::Enum(_) | Data::Union(_) => {
            return Err(syn::Error::new(
                input.span(),
                "HashType can only be derived for structs",
            ));
        }
    };

    let fields = match &data.fields {
        Fields::Named(fields) => &fields.named,
        Fields::Unnamed(_) | Fields::Unit => {
            return Err(syn::Error::new(
                data.fields.span(),
                "HashType requires a struct with named fields",
            ));
        }
    };

    let hash_attrs = parse_hash_attrs(&input.attrs)?;
    let ident = &input.ident;
    let name = &hash_attrs.name;
    let slug = &hash_attrs.slug;

    let mut field_entries = Vec::with_capacity(fields.len());
    let mut describe_entries = Vec::with_capacity(fields.len());
    let mut json_fields = Vec::with_capacity(fields.len());
    let mut seen_renames = Vec::with_capacity(fields.len());

    for (index, field) in fields.iter().enumerate() {
        let field_ident = field.ident.as_ref().expect("named field");
        let attrs = parse_field_attrs(field)?;
        let description = doc_comment(field)?;
        let rename = attrs.rename.unwrap_or_else(|| field_ident.to_string());

        if seen_renames.contains(&rename) {
            return Err(syn::Error::new(
                field_ident.span(),
                format!("duplicate field name `{rename}`"),
            ));
        }
        seen_renames.push(rename.clone());

        let role = role_variant(&attrs.role)?;
        let encoding = encoding_variant(&attrs.encoding)?;
        let ty = attrs.ty.unwrap_or_else(|| compact_type(&field.ty));

        field_entries.push(quote! {
            ::omniex::Field {
                name: #rename,
                description: #description,
                ty: #ty,
                role: ::omniex::FieldRole::#role,
                encoding: ::omniex::Encoding::#encoding,
            }
        });

        let value = describe_value(field_ident, &attrs.encoding)?;
        let index = syn::Index::from(index);
        describe_entries.push(quote! {
            ::omniex::FieldValue {
                field: &Self::FIELDS[#index],
                value: #value,
            }
        });

        let field_ty = &field.ty;
        json_fields.push(quote! {
            #field_ident: <#field_ty as ::omniex::FromFieldValue>::from_field_value(
                document
                    .get("fields")
                    .and_then(::serde_json::Value::as_object)
                    .and_then(|fields| fields.get(#rename))
                    .and_then(|field| field.get("value"))
                    .and_then(::serde_json::Value::as_str)
                    .ok_or_else(|| json_error(::std::format!("missing field `{}`", #rename)))?,
                ::omniex::Encoding::#encoding,
            )
            .map_err(|error| json_error(::std::format!("invalid field `{}`: {}", #rename, error)))?,
        });
    }

    let mut modes = Vec::with_capacity(hash_attrs.hashcat.len() + hash_attrs.john.len());
    for mode in &hash_attrs.hashcat {
        modes.push(quote!(::omniex::Mode::Hashcat(#mode)));
    }
    for label in &hash_attrs.john {
        modes.push(quote!(::omniex::Mode::John(#label)));
    }

    let modes_impl = match &hash_attrs.modes_fn {
        Some(function) => quote! {
            fn modes(&self) -> ::std::vec::Vec<::omniex::Mode> {
                let mut modes = #function(self);
                for mode in Self::DESCRIPTOR.all_modes {
                    if matches!(mode, ::omniex::Mode::John(_)) && !modes.contains(mode) {
                        modes.push(*mode);
                    }
                }
                modes
            }
        },
        None => quote! {
            fn modes(&self) -> ::std::vec::Vec<::omniex::Mode> {
                Self::DESCRIPTOR.all_modes.to_vec()
            }
        },
    };

    Ok(quote! {
        impl ::omniex::HashType for #ident {
            const NAME: &'static str = #name;
            const SLUG: &'static str = #slug;
            const FIELDS: &'static [::omniex::Field] = &[#(#field_entries),*];
        }

        impl ::omniex::Describe for #ident {
            fn describe(&self) -> ::std::vec::Vec<::omniex::FieldValue> {
                ::std::vec![#(#describe_entries),*]
            }
        }

        impl ::omniex::ModeCompat for #ident {
            #modes_impl
        }

        impl #ident {
            /// Type-erased registry entry generated by `#[derive(HashType)]`.
            pub const DESCRIPTOR: ::omniex::HashTypeDescriptor = ::omniex::HashTypeDescriptor {
                name: <Self as ::omniex::HashType>::NAME,
                slug: <Self as ::omniex::HashType>::SLUG,
                fields: <Self as ::omniex::HashType>::FIELDS,
                all_modes: &[#(#modes),*],
                parse: |input, opts| {
                    ::std::result::Result::Ok(::std::boxed::Box::new(
                        <Self as ::omniex::Parse>::parse(input, opts)?,
                    ))
                },
                parse_json: |input| {
                    let json_error = |message: ::std::string::String| ::omniex::ParseError {
                        kind: ::omniex::ParseErrorKind::Other,
                        offset: 0,
                        message,
                    };
                    let document: ::serde_json::Value = ::serde_json::from_str(input)
                        .map_err(|error| json_error(error.to_string()))?;
                    if document.get("schema").and_then(::serde_json::Value::as_str)
                        != ::std::option::Option::Some("omniex.hash.v1")
                    {
                        return ::std::result::Result::Err(json_error(
                            "unsupported JSON hash schema".to_owned(),
                        ));
                    }
                    if document.get("type").and_then(::serde_json::Value::as_str)
                        != ::std::option::Option::Some(#slug)
                    {
                        return ::std::result::Result::Err(json_error(
                            ::std::format!("JSON hash type is not `{}`", #slug),
                        ));
                    }
                    ::std::result::Result::Ok(::std::boxed::Box::new(Self {
                        #(#json_fields)*
                    }))
                },
            };
        }
    })
}

fn parse_hash_attrs(attrs: &[Attribute]) -> syn::Result<HashAttrs> {
    let mut name: Option<LitStr> = None;
    let mut slug: Option<LitStr> = None;
    let mut hashcat: Option<Vec<u32>> = None;
    let mut john: Option<Vec<String>> = None;
    let mut modes_fn: Option<Path> = None;
    let mut found = false;

    for attr in attrs {
        if !attr.path().is_ident("hash") {
            continue;
        }
        if found {
            return Err(syn::Error::new(
                attr.span(),
                "multiple `#[hash(...)]` attributes",
            ));
        }
        found = true;

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("name") {
                if name.is_some() {
                    return Err(meta.error("duplicate `name` key"));
                }
                name = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("slug") {
                if slug.is_some() {
                    return Err(meta.error("duplicate `slug` key"));
                }
                slug = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("hashcat") {
                if hashcat.is_some() {
                    return Err(meta.error("duplicate `hashcat` key"));
                }
                let array: ExprArray = meta.value()?.parse()?;
                let mut modes = Vec::with_capacity(array.elems.len());
                for expr in array.elems {
                    let mode = parse_u32(&expr)?;
                    if modes.contains(&mode) {
                        return Err(syn::Error::new(expr.span(), "duplicate hashcat mode"));
                    }
                    modes.push(mode);
                }
                hashcat = Some(modes);
            } else if meta.path.is_ident("john") {
                if john.is_some() {
                    return Err(meta.error("duplicate `john` key"));
                }
                let array: ExprArray = meta.value()?.parse()?;
                let mut labels = Vec::with_capacity(array.elems.len());
                for expr in array.elems {
                    let label = parse_string(&expr)?;
                    if labels.contains(&label) {
                        return Err(syn::Error::new(expr.span(), "duplicate John label"));
                    }
                    labels.push(label);
                }
                john = Some(labels);
            } else if meta.path.is_ident("modes_fn") {
                if modes_fn.is_some() {
                    return Err(meta.error("duplicate `modes_fn` key"));
                }
                modes_fn = Some(meta.value()?.parse()?);
            } else {
                return Err(meta.error("unknown `#[hash]` key"));
            }
            Ok(())
        })?;
    }

    if !found {
        return Err(syn::Error::new(
            Span::call_site(),
            "missing `#[hash(...)]` attribute",
        ));
    }

    let name = name.ok_or_else(|| {
        syn::Error::new(Span::call_site(), "missing required `name` in `#[hash]`")
    })?;
    let slug = slug.ok_or_else(|| {
        syn::Error::new(Span::call_site(), "missing required `slug` in `#[hash]`")
    })?;
    validate_slug(&slug)?;

    let hashcat = hashcat.unwrap_or_default();
    let john = john.unwrap_or_default();
    if hashcat.is_empty() && john.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "at least one hashcat or John mode is required",
        ));
    }

    Ok(HashAttrs {
        name,
        slug,
        hashcat,
        john,
        modes_fn,
    })
}

fn parse_field_attrs(field: &Field) -> syn::Result<FieldAttrs> {
    let mut role: Option<String> = None;
    let mut encoding: Option<String> = None;
    let mut rename: Option<String> = None;
    let mut ty: Option<String> = None;

    for attr in &field.attrs {
        if !attr.path().is_ident("field") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("role") {
                if role.is_some() {
                    return Err(meta.error("duplicate `role` key"));
                }
                let ident: Ident = meta.value()?.parse()?;
                role = Some(ident.to_string());
            } else if meta.path.is_ident("encoding") {
                if encoding.is_some() {
                    return Err(meta.error("duplicate `encoding` key"));
                }
                let ident: Ident = meta.value()?.parse()?;
                encoding = Some(ident.to_string());
            } else if meta.path.is_ident("rename") {
                if rename.is_some() {
                    return Err(meta.error("duplicate `rename` key"));
                }
                let value: LitStr = meta.value()?.parse()?;
                rename = Some(value.value());
            } else if meta.path.is_ident("ty") {
                if ty.is_some() {
                    return Err(meta.error("duplicate `ty` key"));
                }
                let value: LitStr = meta.value()?.parse()?;
                ty = Some(value.value());
            } else {
                return Err(meta.error("unknown `#[field]` key"));
            }
            Ok(())
        })?;
    }

    Ok(FieldAttrs {
        role: role.unwrap_or_else(|| "other".to_owned()),
        encoding: encoding.unwrap_or_else(|| "raw".to_owned()),
        rename,
        ty,
    })
}

fn doc_comment(field: &Field) -> syn::Result<LitStr> {
    let mut lines = Vec::new();

    for attr in &field.attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        if let syn::Meta::NameValue(value) = &attr.meta
            && let Expr::Lit(ExprLit {
                lit: Lit::Str(text),
                ..
            }) = &value.value
        {
            lines.push(text.value().trim().to_owned());
        }
    }

    let text = lines.join("\n");
    if text.trim().is_empty() {
        return Err(syn::Error::new(
            field.span(),
            "every field requires a doc comment",
        ));
    }

    Ok(LitStr::new(&text, field.span()))
}

fn describe_value(ident: &Ident, encoding: &str) -> syn::Result<proc_macro2::TokenStream> {
    match encoding {
        "raw" => Ok(quote!(::std::format!("{:?}", self.#ident))),
        "hex" => Ok(quote!(::omniex::format::hex(&self.#ident))),
        "base64" => Ok(quote!(::omniex::format::base64(&self.#ident))),
        "decimal" => Ok(quote!(::std::format!("{}", self.#ident))),
        "ascii" => Ok(quote! {
            ::std::string::String::from_utf8_lossy(
                ::std::convert::AsRef::<[u8]>::as_ref(&self.#ident),
            )
            .into_owned()
        }),
        other => Err(syn::Error::new(
            ident.span(),
            format!("unknown field encoding `{other}`"),
        )),
    }
}

fn role_variant(role: &str) -> syn::Result<Ident> {
    let variant = match role {
        "salt" => "Salt",
        "key" => "Key",
        "digest" => "Digest",
        "iv" => "Iv",
        "ciphertext" => "Ciphertext",
        "iterations" => "Iterations",
        "username" => "Username",
        "other" => "Other",
        other => {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("unknown field role `{other}`"),
            ));
        }
    };
    Ok(Ident::new(variant, Span::call_site()))
}

fn encoding_variant(encoding: &str) -> syn::Result<Ident> {
    let variant = match encoding {
        "raw" => "Raw",
        "hex" => "Hex",
        "decimal" => "Decimal",
        "ascii" => "Ascii",
        "base64" => "Base64",
        other => {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("unknown field encoding `{other}`"),
            ));
        }
    };
    Ok(Ident::new(variant, Span::call_site()))
}

fn validate_slug(slug: &LitStr) -> syn::Result<()> {
    let value = slug.value();
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(syn::Error::new(
            slug.span(),
            "slug must contain only lowercase ASCII letters, digits, and hyphens",
        ));
    }
    Ok(())
}

fn parse_u32(expr: &Expr) -> syn::Result<u32> {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Int(value),
            ..
        }) => value.base10_parse(),
        _ => Err(syn::Error::new(expr.span(), "expected a mode number")),
    }
}

fn parse_string(expr: &Expr) -> syn::Result<String> {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Str(value),
            ..
        }) => Ok(value.value()),
        _ => Err(syn::Error::new(
            expr.span(),
            "expected a quoted John format label",
        )),
    }
}

fn compact_type(ty: &syn::Type) -> String {
    let rendered = ty.to_token_stream().to_string();
    let mut out = String::with_capacity(rendered.len());
    let mut previous: Option<char> = None;

    for current in rendered.chars() {
        if current.is_whitespace() {
            if out.is_empty() || previous == Some(' ') || previous.is_some_and(no_space_after) {
                continue;
            }
            out.push(' ');
            previous = Some(' ');
            continue;
        }
        if space_sensitive(current) {
            while out.ends_with(' ') {
                out.pop();
            }
        }
        out.push(current);
        previous = Some(current);
    }

    out.trim().to_owned()
}

fn space_sensitive(character: char) -> bool {
    matches!(
        character,
        '[' | ']' | '<' | '>' | ',' | ';' | '&' | '(' | ')' | ':' | '\''
    )
}

fn no_space_after(character: char) -> bool {
    matches!(
        character,
        '[' | ']' | '<' | '>' | '(' | ')' | '&' | ':' | '\''
    )
}

#[cfg(test)]
mod tests {
    use super::compact_type;

    fn render(source: &str) -> String {
        let ty: syn::Type = syn::parse_str(source).expect("type parses");
        compact_type(&ty)
    }

    #[test]
    fn compacts_generic_and_array_types() {
        assert_eq!(render("Vec<u8>"), "Vec<u8>");
        assert_eq!(render("Vec<Vec<u8>>"), "Vec<Vec<u8>>");
        assert_eq!(render("[u8; 16]"), "[u8; 16]");
        assert_eq!(render("&'static str"), "&'static str");
        assert_eq!(render("Option<[u8; 4]>"), "Option<[u8; 4]>");
    }
}
