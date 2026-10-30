use omniex::{HashType, Mode, ModeCompat, Parse, ParseError, ParseOptions, Render, RenderOptions};

#[derive(HashType)]
#[hash(name = "Example", slug = "example", hashcat = [0])]
struct Example {
    /// First digest.
    #[field(role = digest, encoding = hex, rename = "value")]
    digest: [u8; 16],

    /// Second digest.
    #[field(role = digest, encoding = hex, rename = "value")]
    other: [u8; 16],
}

impl Parse for Example {
    fn parse(_input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        unimplemented!()
    }
}

impl Render for Example {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        String::new()
    }
}

impl ModeCompat for Example {
    fn modes(&self) -> Vec<Mode> {
        vec![Mode::Hashcat(0)]
    }
}

fn main() {}
