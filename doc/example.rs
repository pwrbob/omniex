// md5($salt.$pass.$salt)
#[hash(hc=[3800,3900,3910])]
struct Md5_3800 {
    #[desc("the salt: prepended and appended")]
    salt: Vec<u8>,
    output: Vec<u8>
}

impl TryFrom<Str> for Md5_3800 {
    fn try_from(&str) -> Option<Md5_3800> {
    }
}

impl Extractable for Md5_3800 {
    fn extract(file: File) -> Md5_3800 {
        todo!();
    }
}

impl HashMode for Md5_3800 {
    fn render(&self) -> ..;
    fn render_json(&self) -> Json;
}
