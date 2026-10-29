//! Derive macro for hash-type metadata.
//!
//! See `doc/MACROS.md` for the supported attribute syntax. The derive only
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
    family: Option<Path>,
    hashcat: Vec<u32>,
    john: Vec<String>,
    modes_fn: Option<Path>,
}

struct FieldAttrs {
    role: String,
    encoding: String,
    rename: Option<String>,
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

    let family = match &hash_attrs.family {
        Some(path) => {
            let variant = family_variant(path)?;
            quote!(::std::option::Option::Some(::omniex::Family::#variant))
        }
        None => quote!(::std::option::Option::None),
    };

    let mut field_entries = Vec::with_capacity(fields.len());
    let mut describe_entries = Vec::with_capacity(fields.len());
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
        let ty = compact_type(&field.ty);

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
                #function(self)
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
            const FAMILY: ::std::option::Option<::omniex::Family> = #family;
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
                family: <Self as ::omniex::HashType>::FAMILY,
                fields: <Self as ::omniex::HashType>::FIELDS,
                all_modes: &[#(#modes),*],
                parse: |input, opts| {
                    ::std::result::Result::Ok(::std::boxed::Box::new(
                        <Self as ::omniex::Parse>::parse(input, opts)?,
                    ))
                },
            };
        }
    })
}

fn parse_hash_attrs(attrs: &[Attribute]) -> syn::Result<HashAttrs> {
    let mut name: Option<LitStr> = None;
    let mut slug: Option<LitStr> = None;
    let mut family: Option<Path> = None;
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
                name = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("slug") {
                slug = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("family") {
                family = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("hashcat") {
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
        family,
        hashcat,
        john,
        modes_fn,
    })
}

fn parse_field_attrs(field: &Field) -> syn::Result<FieldAttrs> {
    let mut role = "other".to_owned();
    let mut encoding = "raw".to_owned();
    let mut rename = None;

    for attr in &field.attrs {
        if !attr.path().is_ident("field") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("role") {
                let ident: Ident = meta.value()?.parse()?;
                role = ident.to_string();
            } else if meta.path.is_ident("encoding") {
                let ident: Ident = meta.value()?.parse()?;
                encoding = ident.to_string();
            } else if meta.path.is_ident("rename") {
                let value: LitStr = meta.value()?.parse()?;
                rename = Some(value.value());
            } else {
                return Err(meta.error("unknown `#[field]` key"));
            }
            Ok(())
        })?;
    }

    Ok(FieldAttrs {
        role,
        encoding,
        rename,
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
        "decimal" => Ok(quote!(::std::format!("{}", self.#ident))),
        "ascii" => Ok(quote! {
            ::std::string::String::from_utf8_lossy(
                ::std::convert::AsRef::<[u8]>::as_ref(&self.#ident),
            )
            .into_owned()
        }),
        _ => Err(syn::Error::new(
            ident.span(),
            format!("base64 encoding is not implemented (found `{encoding}`)"),
        )),
    }
}

fn family_variant(path: &Path) -> syn::Result<Ident> {
    let segment = path
        .segments
        .last()
        .ok_or_else(|| syn::Error::new(path.span(), "family must name a `Family` variant"))?;
    let name = segment.ident.to_string();
    let allowed = [
        "Md5",
        "Sha1",
        "Sha2",
        "Sha3",
        "Blake2",
        "Ripemd",
        "Whirlpool",
        "Ntlm",
        "Lm",
        "Des",
        "Aes",
        "Other",
    ];
    if !allowed.contains(&name.as_str()) {
        return Err(syn::Error::new(
            segment.ident.span(),
            format!("unknown family `{name}`"),
        ));
    }
    Ok(segment.ident.clone())
}

fn role_variant(role: &str) -> syn::Result<Ident> {
    let variant = match role {
        "salt" => "Salt",
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
        "base64" => {
            return Err(syn::Error::new(
                Span::call_site(),
                "base64 encoding is not implemented",
            ));
        }
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
            if out.is_empty() || previous == Some(' ') {
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
