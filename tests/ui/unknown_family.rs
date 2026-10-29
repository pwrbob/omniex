use omniex::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

#[derive(HashType)]
#[hash(name = "Example", slug = "example", family = Sha999, hashcat = [0])]
struct Example {
    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    digest: [u8; 16],
}

impl Parse for Example {
    fn parse(_input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        unimplemented!()
    }
}

impl Render for Example {
    fn render(&self, _opts: &RenderOptions) -> String {
        String::new()
    }
}

fn main() {}
