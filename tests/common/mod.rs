//! Shared vectors and reference-tool discovery for conformance tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use omniex::{HashTypeDescriptor, Mode};

pub struct HashcatVector {
    pub mode: u32,
    pub hash: &'static str,
    pub fixture: Option<&'static str>,
    pub identify: bool,
    pub binary: bool,
}

impl HashcatVector {
    pub fn text(&self) -> String {
        if let Some(path) = self.fixture {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"));
            return std::fs::read_to_string(root.join(path))
                .unwrap_or_else(|error| panic!("read vector fixture `{path}`: {error}"))
                .trim_end()
                .to_owned();
        }
        self.hash.to_owned()
    }
}

pub struct JohnVector {
    pub format: &'static str,
    pub hash: &'static str,
    pub fixture: Option<&'static str>,
    pub conformance: bool,
}

impl JohnVector {
    pub fn text(&self) -> String {
        if let Some(path) = self.fixture {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"));
            return std::fs::read_to_string(root.join(path))
                .unwrap_or_else(|error| panic!("read vector fixture `{path}`: {error}"))
                .trim_end()
                .to_owned();
        }
        self.hash.to_owned()
    }
}

pub struct Vector {
    pub slug: &'static str,
    pub hashcat: &'static [HashcatVector],
    pub john: &'static [JohnVector],
}

macro_rules! hc {
    ($mode:literal, $hash:literal $(,)?) => {
        HashcatVector {
            mode: $mode,
            hash: $hash,
            fixture: None,
            identify: true,
            binary: false,
        }
    };
}

macro_rules! hc_binary {
    ($mode:literal, $hash:literal $(,)?) => {
        HashcatVector {
            mode: $mode,
            hash: $hash,
            fixture: None,
            identify: true,
            binary: true,
        }
    };
}

macro_rules! hc_fixture {
    ($mode:literal, $path:literal $(,)?) => {
        HashcatVector {
            mode: $mode,
            hash: "",
            fixture: Some($path),
            identify: true,
            binary: false,
        }
    };
}

macro_rules! hc_binary_only {
    ($mode:literal, $hash:literal $(,)?) => {
        HashcatVector {
            mode: $mode,
            hash: $hash,
            fixture: None,
            identify: false,
            binary: true,
        }
    };
}

macro_rules! hc_ambiguous {
    ($mode:literal, $hash:literal $(,)?) => {
        HashcatVector {
            mode: $mode,
            hash: $hash,
            fixture: None,
            identify: false,
            binary: false,
        }
    };
}

macro_rules! john {
    ($format:literal, $hash:literal) => {
        JohnVector {
            format: $format,
            hash: $hash,
            fixture: None,
            conformance: true,
        }
    };
}

macro_rules! john_fixture {
    ($format:literal, $path:literal) => {
        JohnVector {
            format: $format,
            hash: "",
            fixture: Some($path),
            conformance: false,
        }
    };
}

pub const VECTORS: &[Vector] = &[
    Vector {
        slug: "md4",
        hashcat: &[hc!(900, "afe04867ec7a3845145579a95f72eca7")],
        john: &[john!("Raw-MD4", "afe04867ec7a3845145579a95f72eca7")],
    },
    Vector {
        slug: "md5",
        hashcat: &[
            hc!(0, "8743b52063cd84097a65d1633f5c74f5"),
            hc!(70, "2303b15bfa48c74a74758135a0df1201"),
            hc!(2600, "a936af92b0ae20b1ff6c3347a72e5fbe"),
            hc!(3500, "9882d0778518b095917eb589f6998441"),
            hc!(4300, "b8c385461bb9f9d733d3af832cf60b27"),
            hc!(4400, "288496df99b33f8f75a7ce4837d1b480"),
        ],
        john: &[
            john!("Raw-MD5", "8743b52063cd84097a65d1633f5c74f5"),
            john!("Raw-MD5u", "16c47151c18ac087cd12b3a70746c790"),
        ],
    },
    Vector {
        slug: "salted-md5",
        hashcat: &[
            hc!(10, "3d83c8e717ff0e7ecfe187f088d69954:343141"),
            hc!(
                11,
                "b78f863f2c67410c41e617f724e22f34:89384528665349271307465505333378"
            ),
            hc!(
                12,
                "93a8cf6a7d43e3b5bcd2dc6abb3e02c6:27032153220030464358344758762807"
            ),
            hc!(20, "57ab8499d08c59a7211c77f557bf9425:4247"),
            hc!(21, "e983672a03adcc9767b24584338eb378:00"),
            hc!(23, "d04d74780881019341915c70d914db29:0675841"),
            hc!(24, "e983672a03adcc9767b24584338eb378:00"),
            hc!(30, "1169500a7dfece72e1f7fc9c9410867a:687430237020"),
            hc!(40, "23a8a90599fc5d0d15265d4d3b565f6e:58802707"),
            hc!(2611, "28f9975808ae2bdc5847b1cda26033ea:308"),
            hc!(2630, "0127eecea3120e34c8934ba3b72a390a:0"),
            hc!(
                2711,
                "0844fbb2fdeda31884a7a45ec2010bb6:324410183853308365427804872426"
            ),
            hc!(2811, "022f7e02b3314f7d0968f73c00ba759f:67588"),
            hc!(3610, "a0ab79f9e2b5a4434d2da61673b56362:1234"),
            hc!(3710, "a3aa0ae2b4a102a9974cdf40edeabee0:242812778074"),
            hc!(3800, "78274b1105fb8a7c415b43ffe35ec4a9:6"),
            hc!(3910, "d8281daba5da597503d12fe31808b4a7:283053"),
            hc!(4010, "82422514daaa8253be0aa43f3e263af5:7530326651137"),
            hc!(4110, "45b1005214e2d9472a7ad681578b2438:64268771004"),
            hc!(4410, "bc8319c0220bff8a0d7f5d703114a725:34659348756345251"),
            hc!(4420, "34ebbba3e5c98f6253c160eae53da092:6224378456121050285"),
            hc!(
                4430,
                "df0e9ede5b6c7d1f1b47199f86029002:59132809201799180722359939692710461886"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "sha1",
        hashcat: &[
            hc!(100, "b89eaac7e61417341b710b727768294d0e6a277b"),
            hc!(170, "b9798556b741befdbddcbf640d1dd59d19b1e193"),
            hc!(300, "fcf7c1b8749cf99d88e5f34271d636178fb5d130"),
            hc!(4500, "3db9184f5da4e463832b086211af8d2314919951"),
            hc!(4700, "92d85978d884eb1d99a51652b1139c8279fa8663"),
        ],
        john: &[
            john!("Raw-SHA1", "b89eaac7e61417341b710b727768294d0e6a277b"),
            john!(
                "Raw-SHA1-Linkedin",
                "000007f070b64a50e9d31ac3f9eda35120e29d6c"
            ),
        ],
    },
    Vector {
        slug: "salted-sha1",
        hashcat: &[
            hc!(110, "848952984db93bdd2d0151d4ecca6ea44fcf49e3:30007548152"),
            hc!(120, "a428863972744b16afef28e0087fc094b44bb7b1:465727565"),
            hc!(121, "d27c0a627a45db487af161fcc3a4005d88eb8a1f:25551135"),
            hc!(130, "0a9e4591f539a77cd3af67bae207d250bc86bac6:23240710432"),
            hc!(140, "03b83421e2aa6d872d1f8dee001dc226ef01722b:818436"),
            hc!(4510, "9138d472fce6fe50e2a32da4eec4ecdc8860f4d5:hashcat1"),
            hc!(
                4520,
                "59b80a295392eedb677ca377ad7bf3487928df96:136472340404074825440760227553028141804855170538"
            ),
            hc!(
                4521,
                "c18e826af2a78c7b9b7261452613233417e65817:28246535720688452723483475753333"
            ),
            hc!(
                4522,
                "9038129c474caa3f0de56f38db84033d0fe1d4b8:365563602032"
            ),
            hc!(4710, "53c724b7f34f09787ed3f1b316215fc35c789504:hashcat1"),
            hc!(4711, "53c724b7f34f09787ed3f1b316215fc35c789504:hashcat1"),
            hc!(4900, "75d280ca9a0c2ee18729603104ead576d9ca6285:347070"),
            hc!(
                5000,
                "05ac0c544060af48f993f9c3cdf2fc03937ea35b:232725102020"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "oracle-sha1",
        hashcat: &[hc!(
            112,
            "63ec5f6113843f5d229e2d49c068d983a9670d02:57677783202322766743"
        )],
        john: &[],
    },
    Vector {
        slug: "ldap-sha1",
        hashcat: &[hc!(101, "{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=")],
        john: &[],
    },
    Vector {
        slug: "ldap-ssha1",
        hashcat: &[hc!(111, "{SSHA}FLzWcQqyle6Mo7NvrwXCMAmRzXQxNjYxMTYzNw==")],
        john: &[john!(
            "Salted-SHA1",
            "{SSHA}bPXG4M1KkwZh2Hbgnuoszvpat0T/OS86"
        )],
    },
    Vector {
        slug: "macos-sha1",
        hashcat: &[hc!(122, "86586886b8bd3c379d2e176243a7225e6aae969d293fe9a9")],
        john: &[],
    },
    Vector {
        slug: "django-sha1",
        hashcat: &[hc!(
            124,
            "sha1$fe76b$02d5916550edf7fc8c886f044887f4b1abf9b013"
        )],
        john: &[],
    },
    Vector {
        slug: "aruba-sha1",
        hashcat: &[hc!(
            125,
            "83377286015bcebb857b23b94331e2b316b6ecbe9fbf26c4fc"
        )],
        john: &[],
    },
    Vector {
        slug: "mssql-2000",
        hashcat: &[hc!(
            131,
            "0x0100778883860000000000000000000000000000000000000000eda3604e067a06f2732b05b9cb90b8a710996939"
        )],
        john: &[john!(
            "mssql",
            "0x0100778883860000000000000000000000000000000000000000eda3604e067a06f2732b05b9cb90b8a710996939"
        )],
    },
    Vector {
        slug: "mssql-2005",
        hashcat: &[hc!(
            132,
            "0x010045083578bf13a6e30ca29c40e540813772754d54a5ffd325"
        )],
        john: &[john!(
            "mssql05",
            "0x010045083578bf13a6e30ca29c40e540813772754d54a5ffd325"
        )],
    },
    Vector {
        slug: "peoplesoft-sha1",
        hashcat: &[hc!(133, "uXmFVrdBvv293L9kDR3VnRmx4ZM=")],
        john: &[],
    },
    Vector {
        slug: "episerver",
        hashcat: &[hc!(
            141,
            "$episerver$*0*MjEwNA==*ZUgAmuaYTqAvisD0A427FA3oaWU"
        )],
        john: &[john!(
            "EPiServer",
            "$episerver$*0*fGJ2wn/5WlzqQoDeCA2kXA==*UQgnz/vPWap9UeD8Dhaw3h/fgFA"
        )],
    },
    Vector {
        slug: "mysql323",
        hashcat: &[hc!(200, "7196759210defdc0")],
        john: &[john!("mysql", "7196759210defdc0")],
    },
    Vector {
        slug: "phpass",
        hashcat: &[hc!(400, "$P$946647711V1klyitUYhtB8Yw5DMA/w.")],
        john: &[john!("phpass", "$P$946647711V1klyitUYhtB8Yw5DMA/w.")],
    },
    Vector {
        slug: "md5crypt",
        hashcat: &[hc!(500, "$1$38652870$DUjsu4TTlTsOe/xxZ05uf/")],
        john: &[
            john!("md5crypt", "$1$38652870$DUjsu4TTlTsOe/xxZ05uf/"),
            john!("md5crypt-long", "$1$12345678$aIccj83HRDBo6ux1bVx7D1"),
        ],
    },
    Vector {
        slug: "juniper-ive",
        hashcat: &[hc!(
            501,
            "3u+UR6n8AgABAAAAHxxdXKmiOmUoqKnZlf8lTOhlPYy93EAkbPfs5+49YLFd/B1+omSKbW7DoqNM40/EeVnwJ8kYoXv9zy9D5C5m5A=="
        )],
        john: &[],
    },
    Vector {
        slug: "juniper-screenos",
        hashcat: &[hc!(22, "nKjiFErqK7TPcZdFZsZMNWPtw4Pv8n:26506173")],
        john: &[],
    },
    Vector {
        slug: "blake2b-512",
        hashcat: &[hc!(
            600,
            "$BLAKE2$296c269e70ac5f0095e6fb47693480f0f7b97ccd0307f5c3bfa4df8f5ca5c9308a0e7108e80a0a9c0ebb715e8b7109b072046c6cd5e155b4cfd2f27216283b1e"
        )],
        john: &[john!(
            "Raw-Blake2",
            "$BLAKE2$296c269e70ac5f0095e6fb47693480f0f7b97ccd0307f5c3bfa4df8f5ca5c9308a0e7108e80a0a9c0ebb715e8b7109b072046c6cd5e155b4cfd2f27216283b1e"
        )],
    },
    Vector {
        slug: "salted-blake2b-512",
        hashcat: &[
            hc!(
                610,
                "$BLAKE2$41fcd44c789c735c08b43a871b81c8f617ca43918d38aee6cf8291c58a0b00a03115857425e5ff6f044be7a5bec8536b52d6c9992e21cd43cdca8a55bbf1f5c1:1033"
            ),
            hc!(
                620,
                "$BLAKE2$f0325fdfc3f82a014935442f7adbc069d4636d67276a85b09f8de368f122cf5195a0b780d7fee709fbf1dcd02ddcb581df84508cf1fb0f3393af1be0565491c6:3301"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "ntlm",
        hashcat: &[hc!(1000, "b4b9b02e6f09a9bd760f388b67351e2b")],
        john: &[
            john!("NT", "b4b9b02e6f09a9bd760f388b67351e2b"),
            john!("NT-long", "b4b9b02e6f09a9bd760f388b67351e2b"),
        ],
    },
    Vector {
        slug: "dcc",
        hashcat: &[
            hc!(1100, "c896b3c6963e03c86ade3a38370bbb09:54161084332"),
            hc_ambiguous!(31500, "c896b3c6963e03c86ade3a38370bbb09:54161084332"),
        ],
        john: &[],
    },
    Vector {
        slug: "sha224",
        hashcat: &[hc!(
            1300,
            "e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198"
        )],
        john: &[john!(
            "Raw-SHA224",
            "e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198"
        )],
    },
    Vector {
        slug: "sha256",
        hashcat: &[
            hc!(
                1400,
                "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"
            ),
            hc!(
                1470,
                "9e9283e633f4a7a42d3abc93701155be8afe5660da24c8758e7d3533e2f2dc82"
            ),
        ],
        john: &[john!(
            "Raw-SHA256",
            "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"
        )],
    },
    Vector {
        slug: "salted-sha256",
        hashcat: &[
            hc!(
                1410,
                "5bb7456f43e3610363f68ad6de82b8b96f3fc9ad24e9d1f1f8d8bd89638db7c0:12480864321"
            ),
            hc!(
                1420,
                "816d1ded1d621873595048912ea3405d9d42afd3b57665d9f5a2db4d89720854:36176620"
            ),
            hc!(
                1430,
                "b2d0db162e30dfef1bfd606689a3acbc213c47ef3fd11968394191886075249d:32002"
            ),
            hc!(
                1440,
                "84ebe1bc3d59919a8c4f9337d66bd163661586c828b24b8067a27a6dc4228c64:05662"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "hmailserver",
        hashcat: &[hc!(
            1421,
            "8fe7ca27a17adc337cd892b1d959b4e487b8f0ef09e32214f44fb1b07e461c532e9ec3"
        )],
        john: &[john!(
            "hMailServer",
            "8fe7ca27a17adc337cd892b1d959b4e487b8f0ef09e32214f44fb1b07e461c532e9ec3"
        )],
    },
    Vector {
        slug: "sha512",
        hashcat: &[
            hc!(
                1700,
                "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f"
            ),
            hc!(
                1770,
                "79bba09eb9354412d0f2c037c22a777b8bf549ab12d49b77d5b25faa839e4378d8f6fa11aceb6d9413977ae5ad5d011568bad2de4f998d75fd4ce916eda83697"
            ),
        ],
        john: &[john!(
            "Raw-SHA512",
            "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f"
        )],
    },
    Vector {
        slug: "salted-sha512",
        hashcat: &[
            hc!(
                1710,
                "3f749c84d00c6f94a6651b5c195c71dacae08f3cea6fed760232856cef701f7bf60d7f38a587f69f159d4e4cbe00435aeb9c8c0a4927b252d76a744e16e87e91:388026522082"
            ),
            hc!(
                1720,
                "efc5dd0e4145970917abdc311e1d4e23ba0afa9426d960cb28569f4d585cb031af5c936f57fbcb0a08368a1b302573cf582100d40bd7c632f3d8aecd1a1a8eb1:812"
            ),
            hc!(
                1730,
                "eefb67342d62a5d8ac84e8ae89d0f157f03749bd0427c80637003a4760feefdb36cbe11ba35ab2015b3691e2e83803178c986aa85f29e6f56938b469a31ccd7a:6576666"
            ),
            hc!(
                1740,
                "ce77bf8a8ca9b9cf0ed67edde58ed7fafd4542ce1378fc8bd87b05656ebf92e5711517d5930c18de93a71990e77e1037423e5b64c2f293be7d859d7b6921622e:1512373"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "ldap-ssha256",
        hashcat: &[hc!(
            1411,
            "{SSHA256}L5Wk0zPY2lmoR5pH20zngq37KkxFwgTquEhx95rxfVk3Ng=="
        )],
        john: &[],
    },
    Vector {
        slug: "episerver-net4",
        hashcat: &[hc!(
            1441,
            "$episerver$*1*NDg1NTIz*8BFCg/YJBAuZs/wjbH3OWKe69BLr5Lao26ybpnD48Zk"
        )],
        john: &[],
    },
    Vector {
        slug: "descrypt",
        hashcat: &[hc!(1500, "24leDr0hHfb3A")],
        john: &[
            john!("descrypt", "24leDr0hHfb3A"),
            john!("crypt", "24leDr0hHfb3A"),
        ],
    },
    Vector {
        slug: "apr1",
        hashcat: &[hc!(1600, "$apr1$62722340$zGjeAwVP2KwY6MtumUI1N/")],
        john: &[john!("md5crypt", "$apr1$62722340$zGjeAwVP2KwY6MtumUI1N/")],
    },
    Vector {
        slug: "ldap-ssha512",
        hashcat: &[hc!(
            1711,
            "{SSHA512}Bz8w5q6qEtB1Nnc8b1jfTvTXVTwohWag33oghQGOtLChnkZTw/cuJaHQlLJEI3AWKZGCRyLA6Phujdxo+is7AjA2MDcyNjY1Mg=="
        )],
        john: &[john!(
            "SSHA512",
            "{SSHA512}Bz8w5q6qEtB1Nnc8b1jfTvTXVTwohWag33oghQGOtLChnkZTw/cuJaHQlLJEI3AWKZGCRyLA6Phujdxo+is7AjA2MDcyNjY1Mg=="
        )],
    },
    Vector {
        slug: "macos-sha512",
        hashcat: &[hc!(
            1722,
            "07543781b07e905f6f947db8ae305c248b9e12f509b41097e852e2f450e824790e677ea7397b8a9a552b1c19ecf6a6e1dd3844fa5ee5db23976962859676f7d2fb85ca94"
        )],
        john: &[john!(
            "xsha512",
            "bb0489df7b073e715f19f83fd52d08ede24243554450f7159dd65c100298a5820525b55320f48182491b72b4c4ba50d7b0e281c1d98e06591a5e9c6167f42a742f0359c7"
        )],
    },
    Vector {
        slug: "mssql-2012",
        hashcat: &[hc!(
            1731,
            "0x02003788006711b2e74e7d8cb4be96b1d187c962c5591a02d5a6ae81b3a4a094b26b7877958b26733e45016d929a756ed30d0a5ee65d3ce1970f9b7bf946e705c595f07625b1"
        )],
        john: &[john!(
            "mssql12",
            "0x02003788006711b2e74e7d8cb4be96b1d187c962c5591a02d5a6ae81b3a4a094b26b7877958b26733e45016d929a756ed30d0a5ee65d3ce1970f9b7bf946e705c595f07625b1"
        )],
    },
    Vector {
        slug: "sha512crypt",
        hashcat: &[hc!(
            1800,
            "$6$72820166$U4DVzpcYxgw7MVVDGGvB2/H5lRistD5.Ah4upwENR5UtffLR4X4SxSzfREv8z6wVl0jRFX40/KnYVvK4829kD1"
        )],
        john: &[john!(
            "sha512crypt",
            "$6$72820166$U4DVzpcYxgw7MVVDGGvB2/H5lRistD5.Ah4upwENR5UtffLR4X4SxSzfREv8z6wVl0jRFX40/KnYVvK4829kD1"
        )],
    },
    Vector {
        slug: "dcc2",
        hashcat: &[
            hc_ambiguous!(31600, "$DCC2$10240#6848#e2829c8af2232fa53797e2f0e35e4626"),
            hc!(2100, "$DCC2$10240#6848#e2829c8af2232fa53797e2f0e35e4626"),
        ],
        john: &[john!(
            "mscash2",
            "$DCC2$10240#6848#e2829c8af2232fa53797e2f0e35e4626"
        )],
    },
    Vector {
        slug: "cisco-pix",
        hashcat: &[hc!(2400, "dRRVnUmUHXOTt9nk")],
        john: &[john!("pix-md5", "dRRVnUmUHXOTt9nk")],
    },
    Vector {
        slug: "cisco-asa",
        hashcat: &[hc!(2410, "YjDBNr.A0AN7DA8s:4684")],
        john: &[john!("asa-md5", "4684:YjDBNr.A0AN7DA8s")],
    },
    Vector {
        slug: "phps",
        hashcat: &[hc!(
            2612,
            "$PHPS$30353031383437363132$f02b0b2f25e5754edb04522c346ba243"
        )],
        john: &[
            john!("PHPS", "$PHPS$433925$5d756853cd63acee76e6dcd6d3728447"),
            john!("PHPS2", "$PHPS$433925$5d756853cd63acee76e6dcd6d3728447"),
        ],
    },
    Vector {
        slug: "lm",
        hashcat: &[hc!(3000, "299bd128c1101fd6")],
        john: &[],
    },
    Vector {
        slug: "oracle-h",
        hashcat: &[hc!(3100, "792fcb0ae31d8489:7284616727")],
        john: &[],
    },
    Vector {
        slug: "bcrypt",
        hashcat: &[
            hc!(
                30600,
                "$2b$10$FxDtpTNaL303lLcWtd6LFO2U6Gc63VJ07qycHcfqbQQ71GhO/qSzu"
            ),
            hc!(
                33800,
                "$2a$08$hashcatohohohohohohohegk6PN.SFkoXxDIkacAGKFN9AF8nx.Hi"
            ),
            hc!(
                3200,
                "$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou"
            ),
            hc_ambiguous!(
                75000,
                "$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou"
            ),
            hc_ambiguous!(
                79000,
                "$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou"
            ),
        ],
        john: &[john!(
            "bcrypt",
            "$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou"
        )],
    },
    Vector {
        slug: "sunmd5",
        hashcat: &[hc!(
            3300,
            "$md5,rounds=904$4ol8A9yh$$DrANxVf9omze48HtDkwHQ0"
        )],
        john: &[john!(
            "SunMD5",
            "$md5,rounds=904$4ol8A9yh$$DrANxVf9omze48HtDkwHQ0"
        )],
    },
    Vector {
        slug: "mediawiki-b",
        hashcat: &[hc!(3711, "$B$2152187716$8c8b39c3602b194eeeb6cac78eea2742")],
        john: &[john!(
            "MediaWiki",
            "$B$2152187716$8c8b39c3602b194eeeb6cac78eea2742"
        )],
    },
    Vector {
        slug: "md5-two-salts",
        hashcat: &[
            hc!(
                32300,
                "5962d4ada95d6493379cd9c05ce7a376:726620866134417802643053384570:6056291339665060317728572165496183"
            ),
            hc!(31700, "c7a971e405313d0ecc22e37e8b2424a1:2316355934:478467"),
            hc!(
                33000,
                "036a81bc84e01700faf965c3caaa3954:0243402616975530019305541949338903179746132451440267505028190519468680111713847350899833009965414425621884797638402856957040435715380438220464016:0757380776148401126145133134435506200715895167468508855794708942913462135276430452032928239699197100625556660484150983610760766285767453357925167463064045123083116191440783332986105343359475417787249790516137833723344398087127577224833364437305770807742238"
            ),
            hc!(3730, "0e1484eb061b8e9cfd81868bba1dc4a0:229381927:182719643"),
        ],
        john: &[],
    },
    Vector {
        slug: "wpa-pmkid",
        hashcat: &[
            hc!(
                22000,
                "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***"
            ),
            hc_ambiguous!(
                22001,
                "WPA*01*5ce7ebe97a1bbfeb2822ae627b726d5b*27462da350ac*accd10fb464e*686173686361742d6573736964***"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "iscsi-chap",
        hashcat: &[hc!(
            4800,
            "aa4aaa1d52319525023c06a4873f4c51:35343534373533343633383832343736:dc"
        )],
        john: &[],
    },
    Vector {
        slug: "half-md5",
        hashcat: &[hc!(5100, "8743b52063cd8409")],
        john: &[],
    },
    Vector {
        slug: "ike-psk-md5",
        hashcat: &[hc!(
            5300,
            "50503326cac6e4bd892b8257805b5a59a285f464ad3f63dc01bd0335f8341ef52e00be0b8cb205422a3788f021e4e6e8ccbe34784bc85abe42f62545bac64888426a2f1264fa28cf384ff00b14cfa5eff562dda4fad2a31fd7a6715218cff959916deed856feea5bee2e773241c5fbebf202958f0ce0c432955e0f1f6d1259da:688a7bfa8d5819630a970ed6d27018021a15fbb3e2fdcc36ce9b563d8ff95f510c4b3236c014d1cde9c2f1a999b121bc3ab1bc8049c8ac1e8c167a84f53c867492723eb01ab4b38074b38f4297d6fea8f44e01ea828fce33c433430938b1551f60673ce8088e7d2f41e3b49315344046fefee1e3860064331417562761db3ba9:c66606d691eaade4:8bdc88a2cdb4a1cf:c3b13137fae9f66684d98709939e5c3454ee31a98c80a1c76427d805b5dea866eff045515e8fb42dd259b9448caba9d937f4b3b75ec1b092a92232b4c8c1e70a60a52076e907f887b731d0f66e19e09b535238169c74c04a4b393f9b815c54eef4558cd8a22c9018bb4f24ee6db0e32979f9a353361cdba948f9027551ee40b1c96ba81c28aa3e1a0fac105dc469efa83f6d3ee281b945c6fa8b4677bac26dda:53f757c5b08afad6:aa02d9289e1702e5d7ed1e4ebf35ab31c2688e00:aab8580015cf545ac0b7291d15a4f2c79e06defd:944a0df3939f3bd281c9d05fbc0e3d30"
        )],
        john: &[],
    },
    Vector {
        slug: "ike-psk-sha1",
        hashcat: &[hc!(
            5400,
            "266b43c54636c062b6696b71f24b30999c98bd4c3ba57e2de56a7ae50bb17ebcbca1abcd33e9ad466d4df6e6f2a407600f0c5a983f79d493b0a3694080a81143d4bac7a8b7b008ae5364a04688b3cfae44824885ca96ade1e395936567ecad519b502c3a786c72847f79c67b777feb8ba4f747303eb985709e92b3a5634f6513:60f861c6209c9c996ac0dcb49d6f6809faaaf0e8eb8041fe603a918170a801e94ab8ab10c5906d850f4282c0668029fa69dbc8576f7d86633dc2b21f0d79aa06342b02a4d2732841cd3266b84a7eb49ac489b307ba55562a17741142bac7712025f0a8cad59b11f19d9b756ce998176fd6b063df556957b257b3645549a138c2:f4dd079ed2b60e77:f1f8da1f38f76923:fd862602549f6949b33870f186d96cb8926a19d78442c02af823460740be719eba41a79388aeefb072e1ec7cb46b2f0b72e21fb30bd3a6568d2b041af7f9dc0c9cce27ed577e5aabb9ab6c405f1c4b189adbee8c9fb6abf4788b63a3ae05a02c192187b9d7246efe5e46db9b01bf8f4be05f7599ae52bf137743e41d90dceb85bd6ae07397dcc168bbc904adfebb08e6bc67e653edeee97a7e4ab9dab5e63fec:56e3f0d49ea70514:e754055008febe970053d795d26bfe609f42eda8:0c3283efd6396e7a2ecb008e1933fccb694a4ac0:8f79167724f4bdb2d76ee5d5e502b665e3445ea6"
        )],
        john: &[],
    },
    Vector {
        slug: "netntlmv1",
        hashcat: &[
            hc!(
                5500,
                "user::DOMAIN:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c094853920"
            ),
            hc_ambiguous!(
                27000,
                "::5V4T:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c094853920"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "netntlmv2",
        hashcat: &[
            hc!(
                5600,
                "0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700"
            ),
            hc_ambiguous!(
                27100,
                "0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700"
            ),
        ],
        john: &[
            john_fixture!("ntlmv2-opencl", "tests/fixtures/john/ntlmv2-opencl.txt"),
            john!(
                "netntlmv2",
                "0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700"
            ),
        ],
    },
    Vector {
        slug: "cisco-ios4",
        hashcat: &[hc!(5700, "2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI")],
        john: &[],
    },
    Vector {
        slug: "samsung-android",
        hashcat: &[hc!(
            5800,
            "3edde1eb9e6679ccbc1ff3c417e8a475a2d2e279:7724368582277760"
        )],
        john: &[],
    },
    Vector {
        slug: "whirlpool",
        hashcat: &[
            hc!(
                6100,
                "7ca8eaaaa15eaa4c038b4c47b9313e92da827c06940e69947f85bc0fbef3eb8fd254da220ad9e208b6b28f6bb9be31dd760f1fdb26112d83f87d96b416a4d258"
            ),
            hc_ambiguous!(
                40174,
                "21d9e5d0674ea7bfa40f2bdcae869cdccc2a2771481a1c08e084775a1424011a1c42149b2db396bc19ab2844b0cbcf9bf4043dd12bb6a91c12111f585f322dce"
            ),
            hc_ambiguous!(
                40175,
                "e57fc143265bf3a566290cd59f7cd31ffe607e0acffe5a98bc7bb104e3f5bbd1fe047b42d054737a1adf37a626064bf6bba271e2b4dbaeab9e14c6d824a9246b"
            ),
        ],
        john: &[
            john!(
                "whirlpool",
                "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"
            ),
            john!(
                "whirlpool0",
                "b3e1ab6eaf640a34f784593f2074416accd3b8e62c620175fca0997b1ba2347339aa0d79e754c308209ea36811dfa40c1c32f1a2b9004725d987d3635165d3c8"
            ),
            john!(
                "whirlpool1",
                "470f0409abaa446e49667d4ebe12a14387cedbd10dd17b8243cad550a089dc0feea7aa40f6c2aaab71c6ebd076e43c7cfca0ad32567897dcb5969861049a0f5a"
            ),
        ],
    },
    Vector {
        slug: "gost",
        hashcat: &[
            hc!(
                6900,
                "df226c2c6dcb1d995c0299a33a084b201544293c31fc3d279530121d36bbcea9"
            ),
            hc_ambiguous!(
                40088,
                "256f021ad5729ca0a89fcb8377027f2f3a769748c8cdcb469cffab9aa2fac60b"
            ),
        ],
        john: &[john!(
            "gost",
            "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d"
        )],
    },
    Vector {
        slug: "sha384",
        hashcat: &[hc!(
            10800,
            "07371af1ca1fca7c6941d2399f3610f1e392c56c6d73fddffe38f18c430a2817028dae1ef09ac683b62148a2c8757f42"
        )],
        john: &[john!(
            "Raw-SHA384",
            "07371af1ca1fca7c6941d2399f3610f1e392c56c6d73fddffe38f18c430a2817028dae1ef09ac683b62148a2c8757f42"
        )],
    },
    Vector {
        slug: "salted-sha384",
        hashcat: &[
            hc!(
                10810,
                "ca1c843a7a336234baf9db2e10bc38824ce523402fbd7741286b1602bdf6cb869a45289bb9fb706bd404b9f3842ff729:2746460797049820734631508"
            ),
            hc!(
                10820,
                "63f63d7f82d4a4cb6b9ff37a6bc7c5ec39faaf9c9078551f5cbf7960e76ded87b643d37ac53c45bc544325e7ff83a1f2:93362"
            ),
            hc!(
                10830,
                "3516a589d2ed4071bf5e36f22e11212b3ad9050b9094b23067103d51e99dcb25c4dc397dba8034fed11a8184acfbb699:577730514588712"
            ),
            hc!(
                10840,
                "316e93ea8e04de3e5a909c53d36923a31a16c1b9e89b44201d6082f87ca49c5bca53cad65f685207db3ea2ccc7ca40f8:700067651"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "sha384-utf16",
        hashcat: &[hc!(
            10870,
            "48e61d68e93027fae35d405ed16cd01b6f1ae66267833b4a7aa1759e45bab9bba652da2e4c07c155a3d8cf1d81f3a7e8"
        )],
        john: &[],
    },
    Vector {
        slug: "md2",
        hashcat: &[hc_ambiguous!(40084, "742fd7197420380cf5bb80b9c85a117d")],
        john: &[john!("MD2", "$md2$ab4f496bfb2a530b219ff33031fe06b0")],
    },
    Vector {
        slug: "sha0",
        hashcat: &[hc_ambiguous!(
            40085,
            "d288d613d6945bd9acb2dba2fcf4f5d27d40e0f4"
        )],
        john: &[],
    },
    Vector {
        slug: "panama",
        hashcat: &[hc_ambiguous!(
            40100,
            "ec3600d769166760e905fd928fd1172ea4e706eb23aff9dea91e052a6c699b7c"
        )],
        john: &[john!(
            "Panama",
            "049d698307d8541f22870dfa0a551099d3d02bc6d57c610a06a4585ed8d35ff8"
        )],
    },
    Vector {
        slug: "mdc2",
        hashcat: &[hc_ambiguous!(40101, "5da8fead05e8cd9d4d5424957b5bb4d6")],
        john: &[john!("mdc2", "$mdc2$000ed54e093d61679aefbeae05bfe33a")],
    },
    Vector {
        slug: "has-160",
        hashcat: &[hc_ambiguous!(
            40165,
            "f070541c734597e89e371337bd82d7ebec8fe096"
        )],
        john: &[john!("has-160", "307964ef34151d37c8047adec7ab50f4ff89762d")],
    },
    Vector {
        slug: "edon-r-256",
        hashcat: &[hc_ambiguous!(
            40166,
            "31b2db8e815040dd1cc7b632fbe7cca6b9acc8e2045076fe27e9105015d418f0"
        )],
        john: &[],
    },
    Vector {
        slug: "edon-r-512",
        hashcat: &[hc_ambiguous!(
            40167,
            "3f27d20214108d30863c32e73d64b1d51041fe478dbdb3c16e9b4c280472a7c1373efd6bdd81b530217e2f58c5f981ff244b50587fc528fca61023066f4a0e20"
        )],
        john: &[],
    },
    Vector {
        slug: "sha256-md5",
        hashcat: &[hc_ambiguous!(
            20800,
            "74ee1fae245edd6f27bf36efc3604942479fceefbadab5dc5c0b538c196eb0f1"
        )],
        john: &[],
    },
    Vector {
        slug: "md5-sha1-md5-sha1",
        hashcat: &[hc_ambiguous!(20900, "100b3a4fc1dc8d60d9bf40688d8b740a")],
        john: &[],
    },
    Vector {
        slug: "sha256-double",
        hashcat: &[hc_ambiguous!(
            21400,
            "0cc1b58a543f372327aa0281e97ab56e345267ee46feabf7709515debb7ec43c"
        )],
        john: &[],
    },
    Vector {
        slug: "sha1-double-md5",
        hashcat: &[hc_ambiguous!(
            40039,
            "888a2ffcb3854fba0321110c5d0d434ad1aa2880"
        )],
        john: &[],
    },
    Vector {
        slug: "sha224-double",
        hashcat: &[hc_ambiguous!(
            40076,
            "b7d9a0e57e6e94e8b87996b81ffa64b05d237c58fff1d7a4e4fe2a77"
        )],
        john: &[],
    },
    Vector {
        slug: "sha224-sha1",
        hashcat: &[hc_ambiguous!(
            40077,
            "10d302483c927df95abba98d69dcd9608365241d1523a8cc5fcbcedc"
        )],
        john: &[],
    },
    Vector {
        slug: "ntlm-double",
        hashcat: &[hc_ambiguous!(40080, "7f30a0c84b2a806d93c39cea3b760716")],
        john: &[],
    },
    Vector {
        slug: "sha256-double-salt",
        hashcat: &[hc!(
            20710,
            "bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824:7218532375810603"
        )],
        john: &[],
    },
    Vector {
        slug: "sha1-md5",
        hashcat: &[hc!(21100, "aade80a61c6e3cd3cac614f47c1991e0a87dd028:6")],
        john: &[],
    },
    Vector {
        slug: "md5-sha1-md5",
        hashcat: &[hc!(
            21200,
            "e69b7a7fe1bf2ad9ef116f79551ee919:baa038987e582431a6d"
        )],
        john: &[],
    },
    Vector {
        slug: "sha256-sandwich-salt",
        hashcat: &[hc!(
            22300,
            "755a8ce4e0cf0baee41d714aa35c9fca803106608f718f973eab006578285007:11265"
        )],
        john: &[],
    },
    Vector {
        slug: "sha1-nested-salt",
        hashcat: &[hc!(
            24300,
            "94520b02c04e79e08a75a84c2a6e3ed4e3874fe8:ThisIsATestSalt"
        )],
        john: &[],
    },
    Vector {
        slug: "sha256-salt-sha256",
        hashcat: &[hc!(
            40046,
            "bae9edada8358fcebcd811f7d362f46277fb9d488379869fba65d79701d48b8b:869dc2ed80187919"
        )],
        john: &[],
    },
    Vector {
        slug: "sha256-nested-salted",
        hashcat: &[hc!(
            40047,
            "ad66bdc0841d7e08d96c03de271ce14e77de078746b535adbf9d4b6ccbf2a517:7218532375810603"
        )],
        john: &[],
    },
    Vector {
        slug: "md5-salt-sha1-salt",
        hashcat: &[hc!(
            40048,
            "799dc7d9aa4d3f404cc21a4936dbdcde:68617368636174"
        )],
        john: &[],
    },
    Vector {
        slug: "sha256-salt-sha256-bin",
        hashcat: &[hc!(
            40049,
            "5934ea4d670c13a71155faba42056b2525f71bdc9215d31108990c11bf3d98e3:9269771356270099311432765354522635185291064175409115041569"
        )],
        john: &[],
    },
    Vector {
        slug: "md5-simpla",
        hashcat: &[hc!(
            40051,
            "86d173f13213d1e48bce9647bdc306d5:8e86a279d6e182b3c811c559e6b15484"
        )],
        john: &[],
    },
    Vector {
        slug: "sha512-double-salt",
        hashcat: &[hc!(
            40067,
            "25d509824028a999f4ee851b5de404bb316b78ae8e974874376484018f58520e082747a7ce9f769bcaccb5f63878356c780f602e23393f12b650a6931e4b9338:21881837027919828109608"
        )],
        john: &[],
    },
    Vector {
        slug: "sha512-double-bin-salt",
        hashcat: &[hc!(
            40068,
            "c1bade2bd4ebc8db841ac6ab3e0a5035a29619e5b1a6135782b77da5d7cfaccee096f3ddb9ee23b9866378cfc2fb19f2c013fed1b7e1fffd18340a4f39238412:789"
        )],
        john: &[],
    },
    Vector {
        slug: "whirlpool-cubecart",
        hashcat: &[hc!(
            40069,
            "a2c0342a2617026fbaeed01130c826cc3f58242799894b3ecc1abfa811ede03fd712efd14a886af6fa74045502f22c9feb1c45a291cf2d7bbe9bb94c388b6403:deadbeef"
        )],
        john: &[],
    },
    Vector {
        slug: "md5-sandwich-salt",
        hashcat: &[hc!(40071, "866244ca1d318292a6f40b60e03fd29c:72219426709")],
        john: &[],
    },
    Vector {
        slug: "md5-two-nested-salts",
        hashcat: &[hc!(
            21310,
            "dc91b5a658ef4b7d859e90742f340e24:708237:d270e9eea5802e346bcaa9b229f37766"
        )],
        john: &[],
    },
    Vector {
        slug: "md5-triple-two-salts",
        hashcat: &[hc!(
            21900,
            "2c749af6c65cf3e82e5837e3056727f5:59331674906582121215362940957615121466283616005471:17254656838978443692786064919357750120910718779182716907569266"
        )],
        john: &[],
    },
    Vector {
        slug: "sha1-two-salts",
        hashcat: &[hc!(
            19300,
            "630d2e918ab98e5fad9c61c0e4697654c4c16d73:18463812876898603420835420139870031762867:4449516425193605979760642927684590668549584534278112685644182848763890902699756869283142014018311837025441092624864168514500447147373198033271040848851687108629922695275682773136540885737874252666804716579965812709728589952868736177317883550827482248620334"
        )],
        john: &[],
    },
    Vector {
        slug: "authme-sha256",
        hashcat: &[hc!(
            20711,
            "$SHA$7218532375810603$bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824"
        )],
        john: &[],
    },
    Vector {
        slug: "netwitness-sha256",
        hashcat: &[hc!(
            20712,
            "6F48F44C46F5ADC534597687B086278F0AAF7D262ADDB3978562A7D55BBDF467:MDAwMzY1NzYwODI4MQ=="
        )],
        john: &[],
    },
    Vector {
        slug: "sha1-utf16-username-salt",
        hashcat: &[hc!(
            29000,
            "339b5eaa53f28516008e9ca710857d3a4785b6fc:8ca064ff42fcab5a8f0692544b8dd3d3054bd73fe9afaa08c6b6b310538cc9a7:757365726e616d65"
        )],
        john: &[],
    },
    Vector {
        slug: "aix-smd5",
        hashcat: &[hc!(6300, "{smd5}17800721$WkGka7tXcrfpUQS6WOQyw/")],
        john: &[],
    },
    Vector {
        slug: "ssha1-aix",
        hashcat: &[hc!(
            40017,
            "{ssha1}06$5586485655847243$V5f1Ff1y4dr7AWeVSSdv6N52..Y"
        )],
        john: &[],
    },
    Vector {
        slug: "ssha256-aix",
        hashcat: &[hc!(
            40015,
            "{ssha256}06$2715084824104660$1s/s4RZWEcvZ5VuWPXWGUfwSoG07eVSVce8F6ANJ.g4"
        )],
        john: &[],
    },
    Vector {
        slug: "ssha512-aix",
        hashcat: &[hc!(
            40016,
            "{ssha512}06$4653718755856803$O04nVHL7iU9Jguy/B3Yow.veBM52irn.038Y/Ln6AMy/BG8wbU6ozSP8/W9KDZPUbhdsbl1lf8px.vKJS1S/.."
        )],
        john: &[],
    },
    Vector {
        slug: "sha256crypt",
        hashcat: &[hc!(
            7400,
            "$5$7777657035274252$XftMj84MW.New1/ViLY5V4CM4Y7EBvfETaZsCW9vcJ8"
        )],
        john: &[john!(
            "sha256crypt",
            "$5$7777657035274252$XftMj84MW.New1/ViLY5V4CM4Y7EBvfETaZsCW9vcJ8"
        )],
    },
    Vector {
        slug: "citrix-netscaler-sha1",
        hashcat: &[hc!(
            8100,
            "1130725275da09ca13254957f2314a639818d44c37ef6d558"
        )],
        john: &[john!(
            "Citrix_NS10",
            "100000000f1dc96f425971ba590a076fd0f8bccbf25c1ba0c"
        )],
    },
    Vector {
        slug: "wbb3",
        hashcat: &[hc!(
            8400,
            "7f8d1951fe48ae3266980c2979c141f60e4415e5:5037864764153886517871426607441768004150"
        )],
        john: &[],
    },
    Vector {
        slug: "qnx-md5",
        hashcat: &[hc!(
            19000,
            "@m@75f6f129f9c9e77b6b1b78f791ed764a@8741857532330050"
        )],
        john: &[john!(
            "qnx",
            "@m@bde10f1a1119328c64594c52df3165cf@6e1f9a390d50a85c"
        )],
    },
    Vector {
        slug: "qnx-sha256",
        hashcat: &[hc!(
            19100,
            "@s@0b365cab7e17ee1e7e1a90078501cc1aa85888d6da34e2f5b04f5c614b882a93@5498317092471604"
        )],
        john: &[],
    },
    Vector {
        slug: "qnx-sha512",
        hashcat: &[hc!(
            19200,
            "@S@715df9e94c097805dd1e13c6a40f331d02ce589765a2100ec7435e76b978d5efc364ce10870780622cee003c9951bd92ec1020c924b124cfff7e0fa1f73e3672@2257314490293159"
        )],
        john: &[],
    },
    Vector {
        slug: "pbkdf2-hmac-md5",
        hashcat: &[hc!(
            40031,
            "md5:1000:NjAxMDY4MQ==:a00DtIW9hP9voC85fmEA5uVhgdDx67nSPSm9yADHjkI="
        )],
        john: &[],
    },
    Vector {
        slug: "pbkdf2-hmac-sha1",
        hashcat: &[hc!(
            40032,
            "sha1:1000:MTYwNTM4MDU4Mzc4MzA=:aGghFQBtQ8+WVlMk5GEaMw=="
        )],
        john: &[],
    },
    Vector {
        slug: "pbkdf2-hmac-sha256",
        hashcat: &[hc!(
            40024,
            "sha256:1000:NjI3MDM3:vVfavLQL9ZWjg8BUMq6/FB8FtpkIGWYk"
        )],
        john: &[],
    },
    Vector {
        slug: "pbkdf2-hmac-sha512",
        hashcat: &[hc!(40034, "sha512:1000:NzY2:DNWohLbdIWIt4Npk9gpTvA==")],
        john: &[],
    },
    Vector {
        slug: "passlib-pbkdf2-sha512",
        hashcat: &[hc!(
            40042,
            "$pbkdf2-sha512$25000$LyWE0HrP2RsjZCxlDGFMKQ$1vC5Ohk2mCS9b6akqsEfgeb4l74SF8XjH.SljXf3dMLHdlY1GK9ojcCKts6/asR4aPqBmk74nCDddU3tvSCJvw"
        )],
        john: &[],
    },
    Vector {
        slug: "passlib-pbkdf2-sha256",
        hashcat: &[hc!(
            40043,
            "$pbkdf2-sha256$29000$x9h7j/Ge8x6DMEao1VqrdQ$kra3R1wEnY8mPdDWOpTqOTINaAmZvRMcYd8u5OBQP9A"
        )],
        john: &[],
    },
    Vector {
        slug: "passlib-pbkdf2-sha1",
        hashcat: &[hc!(
            40044,
            "$pbkdf2$131000$r5WythYixPgfQ2jt3buXcg$8Kdr.QQEOaZIXNOrrru36I/.6Po"
        )],
        john: &[],
    },
    Vector {
        slug: "django-pbkdf2-sha256",
        hashcat: &[hc!(
            40022,
            "pbkdf2_sha256$10000$1135411628$bFYX62rfJobJ07VwrUMXfuffLfj2RDM2G6/BrTrUWkE="
        )],
        john: &[],
    },
    Vector {
        slug: "atlassian-pbkdf2-sha1",
        hashcat: &[hc!(
            40033,
            "{PKCS5S2}NTczNTY0NDY2NjQyNzU1Mx8gGiRGobaZYwumctGHbn2ZOHB8LkwzH+Z1gkWfy1zD"
        )],
        john: &[],
    },
    Vector {
        slug: "prestashop",
        hashcat: &[hc!(
            40026,
            "f22cade043e7214200206dbffca49fd9:27167508161455764247627144160038845437138252877014827848"
        )],
        john: &[],
    },
    Vector {
        slug: "sha1crypt",
        hashcat: &[hc!(
            40038,
            "$sha1$20000$75552156$HhYMDdaEHiK3eMIzTldOFPnw.s2Q"
        )],
        john: &[john!(
            "sha1crypt",
            "$sha1$20000$75552156$HhYMDdaEHiK3eMIzTldOFPnw.s2Q"
        )],
    },
    Vector {
        slug: "drupal7",
        hashcat: &[hc!(
            40020,
            "$S$C20340258nzjDWpoQthrdNTR02f0pmev0K/5/Nx80WSkOQcPEQRh"
        )],
        john: &[john!(
            "Drupal7",
            "$S$CwkjgAKeSx2imSiN3SyBEg8e0sgE2QOx4a/VIfCHN0BZUNAWCr1X"
        )],
    },
    Vector {
        slug: "cisco-ios8",
        hashcat: &[hc!(
            40021,
            "$8$84486783037343$pYNyVrtyMalQrZLxRi7ZLQS1Fl.jkYCgASUi5P8JNb2"
        )],
        john: &[],
    },
    Vector {
        slug: "macos-pbkdf2-sha512",
        hashcat: &[hc!(
            40018,
            "$ml$1024$2484380731132131624506271467162123576077004878124365203837706482$89a3a979ee186c0c837ca4551f32e951e6564c7ac6798aa35baf4427fbf6bd1d630642c12cfd5c236c7b0104782237db95e895f7c0e372cd81d58f0448daf958"
        )],
        john: &[],
    },
    Vector {
        slug: "pbkdf1-sha1",
        hashcat: &[hc!(
            40070,
            "PBKDF1:sha1:1000:cGVuZ3VpbmtlZXBlcg==:J4BrIhXDUHNQ9lPPrWKn4V7Of9Y="
        )],
        john: &[],
    },
    Vector {
        slug: "web2py-pbkdf2-sha512",
        hashcat: &[hc!(
            40050,
            "pbkdf2(1000,20,sha512)$744943$c5f8cdef76e3327c908d8d96d4abdb3d8caba14c"
        )],
        john: &[],
    },
    Vector {
        slug: "crc32",
        hashcat: &[hc!(11500, "c762de4a:00000000")],
        john: &[john!("CRC32", "$crc32$00000000.fa455f6b")],
    },
    Vector {
        slug: "crc32c",
        hashcat: &[hc!(27900, "5e23d60f:00000000")],
        john: &[],
    },
    Vector {
        slug: "murmurhash",
        hashcat: &[hc!(25700, "b69e7687:05094309")],
        john: &[],
    },
    Vector {
        slug: "murmurhash3",
        hashcat: &[hc!(27800, "23e93f65:00000000")],
        john: &[],
    },
    Vector {
        slug: "crc64jones",
        hashcat: &[hc!(28000, "65c1f848fe38cce6:4260950400318054")],
        john: &[],
    },
    Vector {
        slug: "java-hashcode",
        hashcat: &[hc!(18700, "29937c08")],
        john: &[],
    },
    Vector {
        slug: "siphash",
        hashcat: &[hc!(
            10100,
            "583e6f51e52ba296:2:4:47356410265714355482333327356688"
        )],
        john: &[],
    },
    Vector {
        slug: "salted-sha224",
        hashcat: &[
            hc!(
                40009,
                "0cf361904f4b0234cf4ade8496d8c11c04e5982db967603e82f22b2f:89452466460220844541730694146873525188525677"
            ),
            hc!(
                40010,
                "4258a61d3d0d5a5b6796f0ab02d081e998fe657d55d22091d3b51409:36669207"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "uuid-v3",
        hashcat: &[hc!(
            40004,
            "ab419066-13e0-3b0a-81e2-78d838da75dc:6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        )],
        john: &[],
    },
    Vector {
        slug: "uuid-v5",
        hashcat: &[hc!(
            40005,
            "1cc9c588-793e-5098-a328-1dcf2519d238:6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        )],
        john: &[],
    },
    Vector {
        slug: "modx-evolution",
        hashcat: &[hc!(
            40007,
            "uncrypt>3b406c893a8ee69e02f80c771a420717061499aa:1"
        )],
        john: &[],
    },
    Vector {
        slug: "cisco-ise-sha256",
        hashcat: &[hc!(
            40012,
            "465865d4226c4d9696e601f2c99b25ae2c194ec01806bafc93933331acfc1a60e8bdcca8be9fa245a5fa16029bb52480915746f47d1c539d01da7ec6f37468d1"
        )],
        john: &[],
    },
    Vector {
        slug: "fortigate256",
        hashcat: &[hc!(
            40054,
            "SH2lpcpFXM5QRlWYwY5vL9+5svfYyb+c79qENpxEoB3NtZpVxKwHjuq/9TH88U="
        )],
        john: &[john!(
            "Fortigate256",
            "SH2+n+OiTlautpJQF1NBcMU2H1otOvlAz9g5wzxwHw+4il3Aiixv9oPtKnRgCc="
        )],
    },
    Vector {
        slug: "qnx7-sha512",
        hashcat: &[hc!(
            40041,
            "@S@vm2nBGHes6QkXra0f74XmouSiRzjYD3r/0py+txv0Kr8A4hCPMGFHoZqr41JFiYcJPPOeIheqFseMyLyw/15Pw==@NDY2MDEwNjk3YjBjYzM2MzliMzc3Mzc0ZTNiMTAzNzE="
        )],
        john: &[],
    },
    Vector {
        slug: "umbraco-hmac-sha1",
        hashcat: &[hc!(24800, "8uigXlGMNI7BzwLCJlDbcKR2FP4=")],
        john: &[],
    },
    Vector {
        slug: "dahua-md5",
        hashcat: &[hc!(24900, "GRuHbyVp")],
        john: &[john!("dahua", "$dahua$4WzwxXxM")],
    },
    Vector {
        slug: "besder-md5",
        hashcat: &[hc!(24901, "GRmHbqVh")],
        john: &[],
    },
    Vector {
        slug: "postgres-cram-md5",
        hashcat: &[hc!(
            11100,
            "$postgres$postgres*74402844*4e7fabaaf34d780c4a5822d28ee1c83e"
        )],
        john: &[john!(
            "postgres",
            "$postgres$postgres*74402844*4e7fabaaf34d780c4a5822d28ee1c83e"
        )],
    },
    Vector {
        slug: "mysql-cram-sha1",
        hashcat: &[hc!(
            11200,
            "$mysqlna$2576670568531371763643101056213751754328*5e4be686a3149a12847caa9898247dcc05739601"
        )],
        john: &[john!(
            "mysqlna",
            "$mysqlna$2576670568531371763643101056213751754328*5e4be686a3149a12847caa9898247dcc05739601"
        )],
    },
    Vector {
        slug: "cram-md5-dovecot",
        hashcat: &[hc!(
            16400,
            "{CRAM-MD5}5389b33b9725e5657cb631dc50017ff100000000000000000000000000000000"
        )],
        john: &[],
    },
    Vector {
        slug: "tacacs-plus",
        hashcat: &[hc!(16100, "$tacacs-plus$0$5fde8e68$4e13e8fb33df$c006")],
        john: &[john!(
            "tacacs-plus",
            "$tacacs-plus$0$6d0e1631$db7c01e77499$c006"
        )],
    },
    Vector {
        slug: "pop3-apop",
        hashcat: &[hc!(
            37601,
            "$apop$<1234.1234567890@DESKTOP-RESPONDER>$2a4fe2feddb704ea75cd7c773509dcb0"
        )],
        john: &[],
    },
    Vector {
        slug: "sasl-digest-md5",
        hashcat: &[hc!(
            37600,
            "$sasl$DIGEST-MD5$WORKGROUP$admin$OA9BSXrbuRhWay$YDgMb0MHFhY9LOl9Tg5hH4GD8JHF8MaZ$00000001$auth$ldap/dc01.workgroup.local$ce9c97bcd0f0bf9d00c456514496814f"
        )],
        john: &[],
    },
    Vector {
        slug: "ospf-md5",
        hashcat: &[hc!(
            40001,
            "$netmd5$0201002c0a0a0afe0000000000000002000001106225f41bffffff00000a1201000000280a0a0afe00000000$46ab0f2c7f0a65102bcc25b1c4ea445b"
        )],
        john: &[],
    },
    Vector {
        slug: "mysql-caching-sha2",
        hashcat: &[hc!(
            40006,
            "$mysqlsha2$336a0e5d214b713776503223785a39014c6d3842*1087166c986227f1ab6cfc071e7392b95a869ba94456a7429620614095b01be2"
        )],
        john: &[],
    },
    Vector {
        slug: "coldfusion10",
        hashcat: &[hc!(
            12600,
            "3f3473a071b1fb955544e80c81853ca0f1e4f9ee4ca3bf4d2a8a10b5ef5be1f6:6058321484538505215534207835727413038041028036676832416353152201"
        )],
        john: &[],
    },
    Vector {
        slug: "peoplesoft-ps-token",
        hashcat: &[hc!(
            13500,
            "24eea51b53d02b4c5ff99bcb05a6847fdb2d9308:4f10a0de76e242040c28e9d3dd15c903343489c79765f9118c098c266b9ff505c95bd75bbe406ff3404849eea73930ad17937c0ba6fc3e7bb6d37362941318938b8af96d1292a310b3fd29a67e411ecb10d30247c99183a16951b3859054d4eba9dcd50709c7b21dee836d7ed195cc6b33317aeb557cc56392dc551faa8d5a0fb42212"
        )],
        john: &[],
    },
    Vector {
        slug: "windows-phone-pin",
        hashcat: &[hc!(
            13800,
            "060a4a94cb2263bcefe74705bd0efe7643d09c2bc25fc69f6a32c1b8d5a5d0d9:4647316184156410832507278642444030512402463246148636510356103432440257733102761444262383653100802140838605535187005586063548643765207865344068042278454875021452355870320020868064506248840047414683714173748364871633802572014845467035357710118327480707136422"
        )],
        john: &[],
    },
    Vector {
        slug: "opencart",
        hashcat: &[hc!(
            13900,
            "058c1c3773340c8563421e2b17e60eb7c916787e:827500576"
        )],
        john: &[],
    },
    Vector {
        slug: "md5-double-salt-md5",
        hashcat: &[hc!(30500, "e13bb4b8e5a98db7277df344aa3363cf:28945624531")],
        john: &[],
    },
    Vector {
        slug: "symfony-legacy-sha256",
        hashcat: &[hc!(
            35800,
            "e65e9e4f3cd2f28dd8f18de72a465b3a8cd982ba615fada61842ecea05ca0c9c:3fd6486e7c9d4eb920275412198bb7f8ed7eacd53ba953dd50f1e481952c15b5"
        )],
        john: &[],
    },
    Vector {
        slug: "sha1-cx",
        hashcat: &[hc!(
            14400,
            "fcdc7ec700b887e8eaebf94c2ec52aebb5521223:63038426024388230227"
        )],
        john: &[],
    },
    Vector {
        slug: "skip32",
        hashcat: &[hc!(14900, "7090b6b9:04223875")],
        john: &[],
    },
    Vector {
        slug: "rails-restful-auth",
        hashcat: &[hc!(
            27200,
            "3999d08db95797891ec77f07223ca81bf43e1be2:5dcc47b04c49d3c8e1b9e4ec367fddeed21b7b85"
        )],
        john: &[],
    },
    Vector {
        slug: "murmurhash64a",
        hashcat: &[hc!(34200, "ef3014941bf1102d:837163b2348dfae1")],
        john: &[],
    },
    Vector {
        slug: "des-plaintext",
        hashcat: &[hc!(14000, "53b325182924b356:1412781058343178")],
        john: &[],
    },
    Vector {
        slug: "des3-plaintext",
        hashcat: &[hc!(14100, "4c29eea59d8db1e7:7428288455525516")],
        john: &[],
    },
    Vector {
        slug: "aes128-ecb-nokdf",
        hashcat: &[hc!(
            26401,
            "e7a32f3210455cc044f26117c4612aab:86046627772965328523223752173724"
        )],
        john: &[],
    },
    Vector {
        slug: "aes192-ecb-nokdf",
        hashcat: &[hc!(
            26402,
            "2995e91b798ef51232a91579edb1d176:49869364034411376791729962721320"
        )],
        john: &[],
    },
    Vector {
        slug: "aes256-ecb-nokdf",
        hashcat: &[hc!(
            26403,
            "264a4248c9522cb74d33fe26cb596895:61270210011294880287232432636227"
        )],
        john: &[],
    },
    Vector {
        slug: "krb5pa17",
        hashcat: &[hc!(
            19800,
            "$krb5pa$17$hashcat$HASHCATDOMAIN.COM$a17776abe5383236c58582f515843e029ecbff43706d177651b7b6cdb2713b17597ddb35b1c9c470c281589fd1d51cca125414d19e40e333"
        )],
        john: &[],
    },
    Vector {
        slug: "krb5pa18",
        hashcat: &[hc!(
            19900,
            "$krb5pa$18$hashcat$HASHCATDOMAIN.COM$96c289009b05181bfd32062962740b1b1ce5f74eb12e0266cde74e81094661addab08c0c1a178882c91a0ed89ae4e0e68d2820b9cce69770"
        )],
        john: &[],
    },
    Vector {
        slug: "krb5db17",
        hashcat: &[hc!(
            28800,
            "$krb5db$17$test$TEST.LOCAL$1c41586d6c060071e08186ee214e725e"
        )],
        john: &[],
    },
    Vector {
        slug: "krb5db18",
        hashcat: &[hc!(
            28900,
            "$krb5db$18$test$TEST.LOCAL$266b5a53a6d663c3f69174f3309acada8e467c097c7973699f86286a6cf1a6c7"
        )],
        john: &[],
    },
    Vector {
        slug: "krb5db-old",
        hashcat: &[hc!(38400, "$krb5db$1$test$TEST.LOCAL$7f153708497ae385")],
        john: &[],
    },
    Vector {
        slug: "krb5tgs17",
        hashcat: &[hc!(
            19600,
            "$krb5tgs$17$srv_http$synacktiv.local$849e31b3db1c1f203fa20b85$948690f5875125348286ad3346d27b43eaabc71896b620c16de7ddcdbd561628c650c508856a3f574261948b6db4b48332d30536e978046a423ad4368f9a69b4dc4642dab4e0d475d8299be718fd6f98ac85a771b457b2453e78c9411dfce572b19660fe7a5a8246d9b2a91ea2f14d1986ea0a77ecf9b8330bc8fd9ab540bcf46b74c5aa7005cfccd89ec05f66aeab30c6b2bf8595cf6c9a1b68ad885258850c4b1dd9265f270fb2af52fd76c16246df51ea67efc58a65c345686c84e43642febe908a"
        )],
        john: &[john!(
            "krb5tgs-sha1",
            "$krb5tgs$17$user$realm$ae8434177efd09be5bc2eff8$90b4ce5b266821adc26c64f71958a475cf9348fce65096190be04f8430c4e0d554c86dd7ad29c275f9e8f15d2dab4565a3d6e21e449dc2f88e52ea0402c7170ba74f4af037c5d7f8db6d53018a564ab590fc23aa1134788bcc4a55f69ec13c0a083291a96b41bffb978f5a160b7edc828382d11aacd89b5a1bfa710b0e591b190bff9062eace4d26187777db358e70efd26df9c9312dbeef20b1ee0d823d4e71b8f1d00d91ea017459c27c32dc20e451ea6278be63cdd512ce656357c942b95438228e"
        )],
    },
    Vector {
        slug: "krb5tgs18",
        hashcat: &[hc!(
            19700,
            "$krb5tgs$18$srv_http$synacktiv.local$16ce51f6eba20c8ee534ff8a$57d07b23643a516834795f0c010da8f549b7e65063e5a367ca9240f9b800adad1734df7e7d5dd8307e785de4f40aacf901df41aa6ce695f8619ec579c1fa57ee93661cf402aeef4e3a42e7e3477645d52c09dc72feade03512dffe0df517344f673c63532b790c242cc1d50f4b4b34976cb6e08ab325b3aefb2684262a5ee9faacb14d059754f50553be5bfa5c4c51e833ff2b6ac02c6e5d4c4eb193e27d7dde301bd1ddf480e5e282b8c27ef37b136c8f140b56de105b73adeb1de16232fa1ab5c9f6"
        )],
        john: &[],
    },
    Vector {
        slug: "krb5tgs23",
        hashcat: &[
            hc_ambiguous!(
                35300,
                "$krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$35e8e45658860bc31a859b41a08989265f4ef8afd75652ab4d7a30ef151bf6350d879ae189a8cb769e01fa573c6315232b37e4bcad9105520640a781e5fd85c09615e78267e494f433f067cc6958200a82f70627ce0eebc2ac445729c2a8a0255dc3ede2c4973d2d93ac8c1a56b26444df300cb93045d05ff2326affaa3ae97f5cd866c14b78a459f0933a550e0b6507bf8af27c2391ef69fbdd649dd059a4b9ae2440edd96c82479645ccdb06bae0eead3b7f639178a90cf24d9a"
            ),
            hc!(
                13100,
                "$krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$35e8e45658860bc31a859b41a08989265f4ef8afd75652ab4d7a30ef151bf6350d879ae189a8cb769e01fa573c6315232b37e4bcad9105520640a781e5fd85c09615e78267e494f433f067cc6958200a82f70627ce0eebc2ac445729c2a8a0255dc3ede2c4973d2d93ac8c1a56b26444df300cb93045d05ff2326affaa3ae97f5cd866c14b78a459f0933a550e0b6507bf8af27c2391ef69fbdd649dd059a4b9ae2440edd96c82479645ccdb06bae0eead3b7f639178a90cf24d9a"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "krb5tgs3",
        hashcat: &[hc!(
            38500,
            "$krb5tgs$3$*user$realm$test/spn*$bf121bf846245e8f7ca288e61797866d$dd842b865809244a05fcb67176bfd4e5443389c9f37b2c336aa2fb1ac4ddcc518444a576ae7f94a2cc21eb1349ba843e3cc1b641362838f97a2a06c6e169580ee3f76c8a57b6f15113bb20b650b3dd806864388bfd05c55d8b6c822648b10e08b574b5e3c4383b6103f1556c81cca31cd20af1965df0a2cb7adb9d21521c9c1f2abfdf6a93a1299a5e2eee00d3a202da9d4921f3e370da4b0afe75c26f48d92497ca36b88f5203936222eeb4e87e99efefd0edc0c8bce0e26a88e383f1b7a7f7"
        )],
        john: &[],
    },
    Vector {
        slug: "krb5asrep23",
        hashcat: &[
            hc_ambiguous!(
                35400,
                "$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac"
            ),
            hc!(
                18200,
                "$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "krb5asrep3",
        hashcat: &[hc!(
            38600,
            "$krb5asrep$3$user$realm$a2afda2f7f57adde2d3359f7427b0f7d$73fa8102fd97b2d911b0217306de09f2c3291373695cedb678c14d0d7a0e085754520ae4326daad0e40c26851d711e64a3cd4c83239e8b62aa99c718db38de8d01ccd3069efb1fc1c3cdfa75911a01944d920bd1cdf191469dc47b59140cb727e8732563eb9edaa1d33af55bf2586920050a69f092157a1c6f7cdc4a7e0860255073dc5afe1793c44fccc0377d4b0c701ff2cee8e8868f96ad1f730d51a0cc76aad0834e0a1d15e1e233b79222ca4a9f56041c53f6ba0ad679175119041b30a10762d11f7d1ceea17195dee83bdafe9024e288a2abb94b254a204cb9e2a53e647bb32d8bc89f5e340bb4f6ece082abc1"
        )],
        john: &[],
    },
    Vector {
        slug: "sspr-md5",
        hashcat: &[hc!(
            40057,
            "$sspr$0$100000$NONE$2c8586ef492e3c3dd3795395507dc14f"
        )],
        john: &[],
    },
    Vector {
        slug: "sspr-sha1",
        hashcat: &[hc!(
            40058,
            "$sspr$1$100000$NONE$b3485214dfa55b038a606a183a560dab7db4ecf1"
        )],
        john: &[john!(
            "sspr",
            "$sspr$1$100000$NONE$64840051a425cbc0b4e2d3750d9e0de3e800de18"
        )],
    },
    Vector {
        slug: "sspr-sha1-salt",
        hashcat: &[hc!(
            40059,
            "$sspr$2$100000$CxCpGqosk9PkCBcoRFp6DLjjRhVEJKK8$a33283d71c2ecaf4f3017b0a89feca2fc879221c"
        )],
        john: &[],
    },
    Vector {
        slug: "sspr-sha256-salt",
        hashcat: &[hc!(
            40060,
            "$sspr$3$100000$ODk2NDA5Mjc2NDIwMjMwMjQyMTQ1NzMz$7195873d47c7e3627510862e37fe7cab9bc83b91feecb9864841bf80cff92419"
        )],
        john: &[],
    },
    Vector {
        slug: "adobe-aem-sha256-salt",
        hashcat: &[hc!(
            40061,
            "$sspr$3$1000$f9bbf1381f481427$a1b45fd7eb190cc7f0bf831698cb777207eebbb4b7ea2abd6fff84be539aae62"
        )],
        john: &[],
    },
    Vector {
        slug: "sspr-sha512-salt",
        hashcat: &[hc!(
            40062,
            "$sspr$4$100000$NzYwNjMyNDc2MTQ2OTE4NTUzODAyODE3$0ce2e8b8efa4280e6e003d77cb45d45300dff3960c5c073f68303565fe62fe4ff3ada8cee7d3b87d0457335ab0df73c5c64ee1f71ccf6b8bd43a316ecb42ecd4"
        )],
        john: &[],
    },
    Vector {
        slug: "adobe-aem-sha512-salt",
        hashcat: &[hc!(
            40063,
            "$sspr$4$1000$9ad596c50a5c9acd$d4cdc3c7d227e3cc57a9c9014b1eff1684808ef40191482cd8ae6e9d7b66211a5f04e4b34f494b0513a5f67b9614c5ff16e95e624a60f41b16b90533f305146e"
        )],
        john: &[],
    },
    Vector {
        slug: "sspr-pbkdf2-sha1",
        hashcat: &[hc!(
            40064,
            "$pbkdf2-hmac-sha1$100000$7134180503252384106490944216249411431665011151428170747164626720$990e0c5f62b1384d48cbe3660329b9741c4a8473"
        )],
        john: &[],
    },
    Vector {
        slug: "sspr-pbkdf2-sha256",
        hashcat: &[hc!(
            40065,
            "$pbkdf2-sha256$100000$MDUzMTE4NjQyNDc5NTQxMjAwMjg1OTYxNjAxNDgzNzc$bwYpAyQ2g5PqdnMj8mJ46mkwQbyztw8gEQqnhDHj48c"
        )],
        john: &[],
    },
    Vector {
        slug: "sspr-pbkdf2-sha512",
        hashcat: &[hc!(
            40066,
            "$pbkdf2-hmac-sha512$100000.0211258841559010919749469547425215185689838310218571790549787198.1659e40e64daf84d635a5f1ed2f5708f6735233bed471994bdc0307b3c5f77597f79bdcdd088d1e79357b383809ddfd84379006b49e14f4ff45c449071478777"
        )],
        john: &[],
    },
    Vector {
        slug: "filezilla-server",
        hashcat: &[hc!(
            15000,
            "bfa9fe5a404faff8b0d200385e26b783a163e475869336029d3ebaccaf02b5f16e4949279e8a33b942ab647f8f19a83dbe89a6d39dd6d8f84812de7d2e556767:6422386434050716105781561510557063652302782465168686858312232148"
        )],
        john: &[],
    },
    Vector {
        slug: "citrix-netscaler-pbkdf2-sha256",
        hashcat: &[hc!(
            40075,
            "5567243c55099b6b10a714a350db53beea8be6ac9c247fd40fea7e96d206a9f11fd1c45735556ac2004138640de206d0e1522607ab3c3f92816156d2d7845068e"
        )],
        john: &[],
    },
    Vector {
        slug: "fernet",
        hashcat: &[hc!(
            40083,
            "gAAAAABpVS3xV437a0DY_zbCoSrtML-DrLC6xSi-9CLArB06FXVZNbNmnp-4EfrJ6RplpoNb3VEhyHnDLdYjbtVpfvuqw42KoZ1KKsUoor--DAXjjBOR0TY="
        )],
        john: &[],
    },
    Vector {
        slug: "bcrypt-md5",
        hashcat: &[hc!(
            25600,
            "$2a$05$/VT2Xs2dMd8GJKfrXhjYP.DkTjOVrY12yDN7/6I8ZV0q/1lEohLru"
        )],
        john: &[],
    },
    Vector {
        slug: "bcrypt-sha1",
        hashcat: &[hc!(
            25800,
            "$2a$05$Uo385Fa0g86uUXHwZxB90.qMMdRFExaXePGka4WGFv.86I45AEjmO"
        )],
        john: &[],
    },
    Vector {
        slug: "bcrypt-sha512",
        hashcat: &[hc!(
            28400,
            "$2a$12$KhivLhCuLhSyMBOxLxCyLu78x4z2X/EJdZNfS3Gy36fvRt56P2jbS"
        )],
        john: &[],
    },
    Vector {
        slug: "phpass-md5",
        hashcat: &[hc!(40079, "$H$9ZtU3uM7Twc8X53ImNRhaec4b3QHJ91")],
        john: &[],
    },
    Vector {
        slug: "cisco-ios9",
        hashcat: &[hc!(
            9300,
            "$9$87023684531115$phio0TBQwaO7KZ8toQFyGFyDvyOzidaypRWN0uKX0hU"
        )],
        john: &[],
    },
    Vector {
        slug: "bsdi-crypt",
        hashcat: &[hc!(12400, "_GW..8841inaTltazRsQ")],
        john: &[john!("bsdicrypt", "_J9..CCCCXBrJUJV154M")],
    },
    Vector {
        slug: "radmin2",
        hashcat: &[hc!(9900, "22527bee5c29ce95373c4e0f359f079b")],
        john: &[john!("RAdmin", "$radmin2$B137F09CF92F465CABCA06AB1B283C1F")],
    },
    Vector {
        slug: "fortigate",
        hashcat: &[hc!(7000, "AK1FCIhM0IUIQVFJgcDFwLCMi7GppdwtRzMyDpFOFxdpH8=")],
        john: &[john!(
            "Fortigate",
            "AK1wTiFOMv7mZOTvQNmKQBAY98hZZjSRLxAY8vZp8NlDWU="
        )],
    },
    Vector {
        slug: "sybase-ase",
        hashcat: &[hc!(
            8000,
            "0xc0071808773188715731b69bd4e310b4129913aaf657356c5bdf3c46f249ed42477b5c74af6eaac4d15a"
        )],
        john: &[john!(
            "SybaseASE",
            "0xc0074f9cc8c0d55d9803b0c0816e127f2a56ee080230af5b4ce3da1f3d9fcc5449fcfcf3fb9595eb8ea6"
        )],
    },
    Vector {
        slug: "citrix-netscaler-sha512",
        hashcat: &[hc!(
            22200,
            "2f9282ade42ce148175dc3b4d8b5916dae5211eee49886c3f7cc768f6b9f2eb982a5ac2f2672a0223999bfd15349093278adf12f6276e8b61dacf5572b3f93d0b4fa886ce"
        )],
        john: &[],
    },
    Vector {
        slug: "bitshares",
        hashcat: &[hc!(
            21000,
            "caec04bdf7c17f763a9ec7439f7c9abda112f1bfc9b1bb684fef9b6142636979b9896cfc236896d821a69a961a143dd19c96d59777258201f1bbe5ecc2a2ecf5"
        )],
        john: &[],
    },
    Vector {
        slug: "rails-restful-authentication",
        hashcat: &[hc!(
            19500,
            "d7d5ea3e09391da412b653ae6c8d7431ec273ea2:238769868762:8962783556527653675"
        )],
        john: &[],
    },
    Vector {
        slug: "tripcode",
        hashcat: &[hc!(16000, "pfaRCwDe0U")],
        john: &[john!("tripcode", "Rk7VUsDT2U")],
    },
    Vector {
        slug: "openedge-progress",
        hashcat: &[hc!(26200, "lebVZteiEsdpkncc")],
        john: &[],
    },
    Vector {
        slug: "teamspeak3",
        hashcat: &[hc!(
            28300,
            "$teamspeak$3$E0aV0IQ29EDyxRfkFoQflUGJ6zo=$mRgDUkNpd0IwUEcTJQBmE0NHYwdDEhFzQ0VgMRcFJUIRYnaHBwNXRZJwk2ZUaURzdXkVYiUROERmI0hYYGFYCDiIJCeIU3N5EhRVcZFnSIRCJlkUFkY4YFMDcheYeTl4RYZEdpKGJYhxAIQJEYGYEA=="
        )],
        john: &[],
    },
    Vector {
        slug: "aes-crypt-sha256",
        hashcat: &[hc!(
            22400,
            "$aescrypt$1*efc648908ca7ec727f37f3316dfd885c*eff5c87a35545406a57b56de57bd0554*3a66401271aec08cbd10cf2070332214093a33f36bd0dced4a4bb09fab817184*6a3c49fea0cafb19190dc4bdadb787e73b1df244c51780beef912598bd3bdf7e"
        )],
        john: &[],
    },
    Vector {
        slug: "jwt",
        hashcat: &[hc!(
            16500,
            "eyJhbGciOiJIUzI1NiJ9.eyIzNDM2MzQyMCI6NTc2ODc1NDd9.f1nXZ3V_Hrr6ee-AFCTLaHRnrkiKmio2t3JqwL32guY"
        )],
        john: &[],
    },
    Vector {
        slug: "mojolicious",
        hashcat: &[hc!(
            16501,
            "mojolicious=eyJiYXIiOiJhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmMiLCJleHBpcmVzIjoxNzU1MDIxNjM4LCJmb29vIjoxfVpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo---078935cd386250a467f9d7bfe379d6f0175679545460660c3ca090eb4c69ddbf"
        )],
        john: &[],
    },
    Vector {
        slug: "ansible-vault",
        hashcat: &[hc!(
            16900,
            "$ansible$0*0*6b761adc6faeb0cc0bf197d3d4a4a7d3f1682e4b169cae8fa6b459b3214ed41e*426d313c5809d4a80a4b9bc7d4823070*d8bad190c7fbc7c3cb1c60a27abfb0ff59d6fb73178681c7454d94a0f56a4360"
        )],
        john: &[john!(
            "ansible",
            "$ansible$0*0*f623a48ba49f7abf7c1920bc1e2ab2607cda2b5786da2560b8178a6095e5dfd2*ab55de42e4f131f109f1a086f2e8e22f*6767c60857ce1d7aa20226d76ec1abf77837c623bb7e879147ab888ef15a0dbb"
        )],
    },
    Vector {
        slug: "knx-ip-secure",
        hashcat: &[hc!(
            25900,
            "$knx-ip-secure-device-authentication-code$*3033*fa7c0d787a9467c209f0a6e7cf16069ed704f3959dce19e45d7935c0a91bce41*f927640d9bbe9a4b0b74dd3289ad41ec"
        )],
        john: &[],
    },
    Vector {
        slug: "metamask",
        hashcat: &[
            hc!(
                26600,
                "$metamask$jfGI3TXguhb8GPnKSXFrMzRk2NCEc131Gt5G3kZr5+s=$h+BoIf2CQ5BEjaIOShFE7g==$R95fzGt4UQ0uwrcrVYnIi4UcSlWn9wlmer+//526ZDwYAp50K82F1u1oacYcdjjhuEvbZnWk/uBG00UkgLLlO3WbINljqmu2QWdDEwjTgo/qWR6MU9d/82rxNiONHQE8UrZ8SV+htVr6XIB0ze3aCV0E+fwI93EeP79ZeDxuOEhuHoiYT0bHWMv5nA48AdluG4DbOo7SrDAWBVCBsEdXsOfYsS3/TIh0a/iFCMX4uhxY2824JwcWp4H36SFWyBYMZCJ3/U4DYFbbjWZtGRthoJlIik5BJq4FLu3Y1jEgza0AWlAvu4MKTEqrYSpUIghfxf1a1f+kPvxsHNq0as0kRwCXu09DObbdsiggbmeoBkxMZiFq0d9ar/3Gon0r3hfc3c124Wlivzbzu1JcZ3wURhLSsUS7b5cfG86aXHJkxmQDA5urBz6lw3bsIvlEUB2ErkQy/zD+cPwCG1Rs/WKt7KNh45lppCUkHccbf+xlpdc8OfUwj01Xp7BdH8LMR7Vx1C4hZCvSdtURVl0VaAMxHDX0MjRkwmqS"
            ),
            hc!(
                26610,
                "$metamask-short$jfGI3TXguhb8GPnKSXFrMzRk2NCEc131Gt5G3kZr5+s=$h+BoIf2CQ5BEjaIOShFE7g==$R95fzGt4UQ0uwrcrVYnIi4UcSlWn9wlmer+//526ZDwYAp50K82F1u1oacYcdjjhuEvbZnWk/uBG00UkgLLlOw=="
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "office2016-sheetprotection",
        hashcat: &[hc!(
            25300,
            "$office$2016$0$100000$876MLoKTq42+/DLp415iZQ==$TNDvpvYyvlSUy97UOLKNhXynhUDDA7H8kLql0ISH5SxcP6hbthdjaTo4Z3/MU0dcR2SAd+AduYb3TB5CLZ8+ow=="
        )],
        john: &[],
    },
    Vector {
        slug: "haval",
        hashcat: &[
            hc_ambiguous!(40102, "7bdb3946de69fa2bbd719b97f4472b4c"),
            hc_ambiguous!(40103, "6e2f70e6b9f2dd69cc6b85f6e4098292"),
            hc_ambiguous!(40104, "c339c70717f3448624ed14bf5e4c7784"),
            hc_ambiguous!(40105, "7e7e7fe1c80992a5183138e3948e4424c4121e6a"),
            hc_ambiguous!(40106, "0a51a5fd18e4e288ae1a9234634af9df1b2a5b44"),
            hc_ambiguous!(40107, "5d91ae221d22b2a9a4eba549fd6b3743ea2ca8d5"),
            hc_ambiguous!(40108, "5d97366a5be117a571a6e0541397c2e3d051aab557a224b0"),
            hc_ambiguous!(40109, "31fd78faba008a0dab71adc7d2acb60c43c34cb5ccc4f84c"),
            hc_ambiguous!(40110, "2b0836388e3b8fbc0b2a675ac3668c6fe14e2957cc3f3084"),
            hc_ambiguous!(
                40111,
                "fa9f54ea58a54f14bc9592e27b8aea42f21e3851a3d724be32e5813d"
            ),
            hc_ambiguous!(
                40112,
                "62c10f8cdb079d349e5d6af1c78c22e84beb332ba750a6c257c6177d"
            ),
            hc_ambiguous!(
                40113,
                "ce7053168ec92d0bb83e6039ada7477fef6eecfc3116d93278c0f36a"
            ),
            hc_ambiguous!(
                40114,
                "9ddb8d41435015df7caf22cbe436f512f90008a119fb7836c79af30a15e61e37"
            ),
            hc_ambiguous!(
                40115,
                "b5f791bf79336c8d34efceb2adf89550261640a122b05c3620740967c64e84aa"
            ),
            hc_ambiguous!(
                40116,
                "72f72ddb75c084e6bfe4b939299c55f3d1c1d79f5ec5a9cc3470e0fa56914e9a"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "blake",
        hashcat: &[
            hc_ambiguous!(
                40117,
                "b97223695a40301e703fde4f93c7e376635f5545b36302dff81e7f44",
            ),
            hc_ambiguous!(
                40118,
                "5cc8cc69c778c46c5a27790a887addda9b7b155e12adfbba7e97c5c1a6eac3dd",
            ),
            hc_ambiguous!(
                40119,
                "665ce5461d27a7a3d7b907b5d7822ed08ef5be964d4e46a550abf63fe08b0bfa0ac52357c3ac3903492d38dcb882e531",
            ),
            hc_ambiguous!(
                40120,
                "dbe858c23dc30b73d4df036696ce3189dbf971070bddebdd76004c9fbc0bf010d18aa1448212b098b569ef0b08ceedfe50f0899b4162d7c2115be3f7a725713c",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "bmw",
        hashcat: &[
            hc_ambiguous!(
                40121,
                "e307f60003a3440b5a324e3cbff297d752ccf07ec8474062f7030b1e",
            ),
            hc_ambiguous!(
                40122,
                "94a9c07402d39d630c9d301d3ab3aa8a7d55493ab8417412d103a1212b0c5170",
            ),
            hc_ambiguous!(
                40123,
                "7dc6a952dc1b116958198cf1d1ca9e972549a5558464e6ffe51b18f237d08ab43487e5a76288647cb18bb1c49cfe7f04",
            ),
            hc_ambiguous!(
                40124,
                "1eaf35f8c9ccb48d6305f10df3f220bdffb416fc5b7335630a27f77f251f54e20933d8bcc784703ce2eafa1856df8879664d8d2a18f22ecb3cd40646b3c6c006",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "cubehash",
        hashcat: &[
            hc_ambiguous!(
                40125,
                "4b87a448b4ec677c4748cf8d00efac7662933807c37e3f837b5f9c57",
            ),
            hc_ambiguous!(
                40126,
                "83197263f83cd8665bd7aa75f3df2a569559a79a8eefe3057d30259b55334dc7",
            ),
            hc_ambiguous!(
                40127,
                "312a0146534d4ad452d696d8a44fb2d3fb4739cc83eb217a8a04620cfeac43a4c83ccdbd9a8c0cbe2a22aeb884dbc878",
            ),
            hc_ambiguous!(
                40128,
                "8884ea07f9b0a33433c734caaa28db1eb662958e0f7594f7199a336467ffe99711c6d0951c2f0ce717bdc9f757d979b360c4199b984a55a30147cc4cd3fb029b",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "echo",
        hashcat: &[
            hc_ambiguous!(
                40129,
                "dda4e7ebdab515a590e23a0160debb6467ddb124a3a4620f7511673d",
            ),
            hc_ambiguous!(
                40130,
                "4d8ab56039659b602c114b58688a8151f5f78b016b882e95b4c8ba0198d1c6c3",
            ),
            hc_ambiguous!(
                40131,
                "313332f8ddf5fbb4bbf34485cfc74c179ecb3fc0e8df1c82efdb4092859632bd2542e61f87a6a187c4f591226a6ccdd2",
            ),
            hc_ambiguous!(
                40132,
                "94d8804c8eb3de22edd238e80a74d6b91284853121fae4a78dc8c0f658e2a202d8eab1d266bc5fa99e81feef96c3d71e84be1e30b213354d52f1b9f0f22d4eb9",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "fugue",
        hashcat: &[
            hc_ambiguous!(
                40133,
                "0b1aaf18cd6cd949867b99aa28e7f19d368b064269e753e8c5ee01c6",
            ),
            hc_ambiguous!(
                40134,
                "e545a4d7a9252cccd07152377af7326b262f43ce0a83eb447cbb82713b307e78",
            ),
            hc_ambiguous!(
                40135,
                "adde0faf0065af5c2b5c41b177142870e4add47b54651f09bdf940c1a654c771f2c7908e486e5cb5b8cd2488a0f2ebeb",
            ),
            hc_ambiguous!(
                40136,
                "920e968668a8a3aacff1c855449e7db1572fcbaa5d16a1ae7973a5868c95bddeae9551e6fc7d98760f23d320f614d175fd0e52068654bca17ca27080c68e9180",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "groestl",
        hashcat: &[
            hc_ambiguous!(
                40137,
                "088233a104bb48b9fbc22e96267488207f0520c102a5bbc3fbc5caa9",
            ),
            hc_ambiguous!(
                40138,
                "fd032bc81a0ffed5201add8209a80c4f8d06c2b96a17ae5e1452e1a78ff3a31a",
            ),
            hc_ambiguous!(
                40139,
                "1a66a7e00890353567076161c13f20a180ebda13b5bc9185cdbaeab28ba07c818b860e71fa1a9344c7978bf5ccbbf757",
            ),
            hc_ambiguous!(
                40140,
                "a579375673904bf1cd42a7776744e7ff596e4896830aa441867795b4bf372d0a7567003dba016ae6f5f838eafc940f87367897c1578f3c31d274877cf5174ec2",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "hamsi",
        hashcat: &[
            hc_ambiguous!(
                40141,
                "56b7c2cd4d31621bb5350f7b915e3a534582285a7bd25845950449d5",
            ),
            hc_ambiguous!(
                40142,
                "23992c5687d75482dc8ccd8873f51fa597da826f777941e0ae19c11582592305",
            ),
            hc_ambiguous!(
                40143,
                "0b7fb3ab0059dab2664f896182e48b1b6b711bf87bc737aa4539b24a15078d8309b74f33112bec9b57b1ff6391c455b3",
            ),
            hc_ambiguous!(
                40144,
                "6086c74b28820775e4ab101a521ced7680985b43abe586d97096beaf87e89a5ebc0d4923decd9449c5226299e8f10961aff44747d088d98a47c662a137b543bf",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "jh",
        hashcat: &[
            hc_ambiguous!(
                40145,
                "69ff0662d2eb9ca2819fd714e14cad1ae1a3e8dffd6f56ac61e3db7f",
            ),
            hc_ambiguous!(
                40146,
                "d9a369b52c209dd119397326b8a16b0aca7dad7ada830bcba2a9e8739f1337f0",
            ),
            hc_ambiguous!(
                40147,
                "f3f78e8b52b7c24d49938d91ad406bae1b7879662f0acf95bf8bb93710bdf603f594e90292fdb135f130ad71206e0a42",
            ),
            hc_ambiguous!(
                40148,
                "824904b6ebd86ba610043d2e69f7e0755de4178a21a56960c39a26ec1b8046c48b2363b92c5de090ab4100c80703a3fc81cb75711057369541ed529b46770ad5",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "keccak",
        hashcat: &[
            hc!(
                17700,
                "e1dfad9bafeae6ef15f5bbb16cf4c26f09f5f1e7870581962fc84636"
            ),
            hc!(
                17800,
                "203f88777f18bb4ee1226627b547808f38d90d3e106262b5de9ca943b57137b6"
            ),
            hc!(
                17900,
                "5804b7ada5806ba79540100e9a7ef493654ff2a21d94d4f2ce4bf69abda5d94bf03701fe9525a15dfdc625bfbd769701"
            ),
            hc!(
                18000,
                "2fbf5c9080f0a704de2e915ba8fdae6ab00bbc026b2c1c8fa07da1239381c6b7f4dfd399bf9652500da723694a4c719587dd0219cb30eabe61210a8ae4dc0b03"
            ),
        ],
        john: &[
            john!(
                "Raw-Keccak-256",
                "203f88777f18bb4ee1226627b547808f38d90d3e106262b5de9ca943b57137b6"
            ),
            john!(
                "Raw-Keccak",
                "2fbf5c9080f0a704de2e915ba8fdae6ab00bbc026b2c1c8fa07da1239381c6b7f4dfd399bf9652500da723694a4c719587dd0219cb30eabe61210a8ae4dc0b03"
            ),
        ],
    },
    Vector {
        slug: "luffa",
        hashcat: &[
            hc_ambiguous!(
                40149,
                "22f54680de2d223b759198c33907627fd2f77aabf6888d37532b3000",
            ),
            hc_ambiguous!(
                40150,
                "22f54680de2d223b759198c33907627fd2f77aabf6888d37532b300073c6d069",
            ),
            hc_ambiguous!(
                40151,
                "8dd83061ff0d2fa32a84c98a360b3f1a509e5186fa64895e812decd9112cff72cfb450f8ef51c8264d3ef3307284b4d6",
            ),
            hc_ambiguous!(
                40152,
                "a2d33bd8e84794c6bf3fefe2019c6af5ccf25a19b96e1a0ca83260812bf1f56a882d3e554710668b79ab886b3463245994ab70bc59765f285a0bbfc714745725",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "shabal",
        hashcat: &[
            hc_ambiguous!(
                40153,
                "3262dad883ed99f43a344fb2c5045253ce935fe36bb461826e27f09f",
            ),
            hc_ambiguous!(
                40154,
                "69f72ed7674889359266a38a602f900505944cde9b9341e42018eb797a69cfdf",
            ),
            hc_ambiguous!(
                40155,
                "c795ef512476e7dd3e9df347196ceadf0e5c34122ee092468941fa2ee96c904332e1d2764c74789b4f3bfe9edc8f5559",
            ),
            hc_ambiguous!(
                40156,
                "d3d3b8e1030607bea0b49558e5e4a583a0365a611d615823895766b0449580228edf9c8c396cb0bb62c5ee8b589431640d9fc6e1f546d9921b37f2651e807ae8",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "sha3",
        hashcat: &[
            hc!(
                17300,
                "412ef78534ba6ab0e9b1607d3e9767a25c1ea9d5e83176b4c2817a6c"
            ),
            hc!(
                17400,
                "d60fcf6585da4e17224f58858970f0ed5ab042c3916b76b0b828e62eaf636cbd"
            ),
            hc!(
                17500,
                "983ba28532cc6320d04f20fa485bcedb38bddb666eca5f1e5aa279ff1c6244fe5f83cf4bbf05b95ff378dd2353617221"
            ),
            hc!(
                17600,
                "7c2dc1d743735d4e069f3bda85b1b7e9172033dfdd8cd599ca094ef8570f3930c3f2c0b7afc8d6152ce4eaad6057a2ff22e71934b3a3dd0fb55a7fc84a53144e"
            ),
        ],
        john: &[john!(
            "Raw-SHA3",
            "7c2dc1d743735d4e069f3bda85b1b7e9172033dfdd8cd599ca094ef8570f3930c3f2c0b7afc8d6152ce4eaad6057a2ff22e71934b3a3dd0fb55a7fc84a53144e"
        )],
    },
    Vector {
        slug: "shavite3",
        hashcat: &[
            hc_ambiguous!(
                40157,
                "dcd131d53b576e0615fd3c68e8d7bf32e4a70669e41b727db7f218ca",
            ),
            hc_ambiguous!(
                40158,
                "4822be4d566dc19f8c8cd67290eeeeeebd7579ba84a1a4a3fa0d58840a113b44",
            ),
            hc_ambiguous!(
                40159,
                "80d57b047711a509e9444c769e65c258e2feacdab7c4970cbb3e66f96a726c307f135e86022d270e26c8b92a6f186cca",
            ),
            hc_ambiguous!(
                40160,
                "6fc6c372cbbc8dfddab17b65ada3818795282ae5da4162ce4b2724c3b67636a494c15972792eb155106cbb2cc53d559c7fdd0f5937a3935ac55fbf25080acfc9",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "simd",
        hashcat: &[
            hc_ambiguous!(
                40161,
                "2f74b6bf688efcf84af322aaae9d520c14c73a7c2f23a950990b61b6",
            ),
            hc_ambiguous!(
                40162,
                "7cb7c2409260124fa0b3738b0dc42183d57fc92abf36e077bcb553bf493d9a12",
            ),
            hc_ambiguous!(
                40163,
                "6f6c2f83b43a3fe173ba9b58aaccee8e5e3fc2e4f191514c485acf79db9932edba23034f69530eb91a059bda05545ef9",
            ),
            hc_ambiguous!(
                40164,
                "fc4623e13134947b85f567426734c80f65d2c7cfd9ff410c4a26058731aed3d1efd3709d8a31ec1e10b4c38f587aa43740ab52ec6dae8dd8ead0818e808ef87f",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "skein-512",
        hashcat: &[
            hc_ambiguous!(
                40096,
                "24a3df2fc779538c1c8f2372b9b87f9176922086fefd099bf9efca6f",
            ),
            hc_ambiguous!(
                40097,
                "45e91567c3263a5fb2bcb4a4e403c3b776c087be7176335b2b4d97d3ef47614c",
            ),
            hc_ambiguous!(
                40098,
                "ae07ebdbdc899f2e0fdd8ec11378ed673ed407eb4d947b334fc8ff4ae0da0b4b0505e43a5efe143cb33167bf3bac0e1e",
            ),
            hc_ambiguous!(
                40099,
                "67a6caf6e02968509ea3893d65eda0d8ffcaf22c6c5466357d3fd1e34c9a9e8c2b349b6ba6f8b2c2ee672f30c2ee982e5da7ee20509125830af88ff57169a742",
            ),
        ],
        john: &[john!(
            "skein-512",
            "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"
        )],
    },
    Vector {
        slug: "tiger",
        hashcat: &[
            hc_ambiguous!(40090, "6e2d24e09a70a02bdd9c4885ea199b06"),
            hc_ambiguous!(40091, "6e2d24e09a70a02bdd9c4885ea199b0649821304"),
            hc_ambiguous!(40089, "6e2d24e09a70a02bdd9c4885ea199b064982130432331b44"),
            hc_ambiguous!(40092, "6ff6a5dc0f02836902a17fe15816fad45d6d39de1d14b240"),
            hc_ambiguous!(40093, "4f5e0dc524eaf4c41fe58b74aa23d7e74db94153073c09cb"),
        ],
        john: &[],
    },
    Vector {
        slug: "snefru",
        hashcat: &[
            hc_ambiguous!(40094, "ba1d02bbc8eb20ace9162b1653da8483"),
            hc_ambiguous!(
                40095,
                "7f224f9a530d90acae8c051c87e9f2dfd60232c6529aee3aec16e0578d625f7e",
            ),
        ],
        john: &[
            john!("Snefru-128", "53b8a9b1c9ed00174d88d705fb7bae30"),
            john!(
                "Snefru-256",
                "4170e04e900e6221562ceb5ff6ea27fa9b9b0d9587add44a4379a02619c5a106"
            ),
        ],
    },
    Vector {
        slug: "md6",
        hashcat: &[
            hc!(
                34600,
                "539a8b63639c94b80e746611c476a684e7cc95235187b2f8b81a188d6dfbf64c"
            ),
            hc_ambiguous!(40168, "387369565c845fffaa4e8c56d79f245d"),
            hc_ambiguous!(
                40170,
                "06bb86c04bb969f9057a034f0024b1b7a25f8378938d61e594f9a5b4dfb9fc122c8641eaf75d7b7c07de63cb7870822b8793c0e10b8177da56700bf2131eba75",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "radiogatun",
        hashcat: &[
            hc_ambiguous!(40171, "d013f6fde4161f6260784ac0940ab1d0"),
            hc_ambiguous!(
                40172,
                "f972538913e4a99b318236833101e312c4922d83b40c8301ab3d81e0c82460a7",
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "hmac",
        hashcat: &[
            hc!(50, "e28e4e37e972a945e464b5226053bac0:40"),
            hc!(60, "7f51edecfa6fb401a0b5e63d33fc8c0e:84143"),
            hc!(150, "02b256705348a28b1d6c0f063907979f7e0c82f8:10323"),
            hc!(160, "8d7cb4d4a27a438059bb83a34d1e6cc439669168:2134817"),
            hc!(
                40013,
                "4f5edca01734e03dd7e735362625a76e6bcb61b2:52355614946067"
            ),
            hc!(
                40014,
                "34d8e55a2ae1e9549a291326ce2f0a8dcdc75c5c:08523202563542341"
            ),
            hc!(
                1450,
                "b435ffbacea34d5eb0dbc4d69a92f0152f2cf4cd364d34c2ece322ca22d8b334:21217"
            ),
            hc!(
                1460,
                "8b9472281c36c3a693703de0e0f1ffab8fc0ecdd3bc5ead04c76dd74ef431e49:70108387805"
            ),
            hc!(
                40027,
                "0f71c7c82700c9094ca95eee3d804cc283b538bec49428a9ef8da7b34effb3ba:08151337"
            ),
            hc!(
                40028,
                "d5c6b874338a492ac57ddc6871afc3c70dcfd264185a69d84cf839a07ef92b2c:08151337"
            ),
            hc!(
                40072,
                "0d541ae24d30aff2627c4d1a910f766088a64809edb46a05d29649a9b944da6c:1234"
            ),
            hc!(
                40073,
                "e740440e7bd65056a90f1aa4eb00e00308a9f1788866b4eacbd46cfc8032301d4e5b3a9d179be044:95454599772294521162217"
            ),
            hc!(
                40074,
                "345136b13b3a6e52901e2a414efa0cf5fca2fecf8b03279656d3b0f42c30df3006c5ad186494996b:2436077107013929602"
            ),
            hc!(
                1750,
                "138c00f17a1a0363f274817c91118f019aff09f937bfdaea844280a0c0e7811267cc4735d967d8640eed1218268c1c4a76fec8f7aa551491b353829f3a654270:885142"
            ),
            hc!(
                1760,
                "7d02921299935179d509e6dd4f3d0f2944e3451ea9de3af16baead6a7297e5653577d2473a0fff743d9fe78a89bd49296114319989dc7e7870fc7f62bc96accb:114"
            ),
            hc!(
                40029,
                "be4555415af4a05078dcf260bb3c0a35948135df3dbf93f7c8b80574ceb0d71ea4312127f839b7707bf39ccc932d9e7cb799671183455889e8dde3738dfab5b6:08151337"
            ),
            hc!(
                40030,
                "bebf6831b3f9f958acb345a88cb98f30cb0374cff13e6012818487c8dc8d5857f23bca2caed280195ad558b8ce393503e632e901e8d1eb2ccb349a544ac195fd:08151337"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "streebog",
        hashcat: &[
            hc!(
                11700,
                "57e9e50caec93d72e9498c211d6dc4f4d328248b48ecf46ba7abfa874f666e36"
            ),
            hc!(
                11800,
                "5d5bdba48c8f89ee6c0a0e11023540424283e84902de08013aeeb626e819950bb32842903593a1d2e8f71897ff7fe72e17ac9ba8ce1d1d2f7e9c4359ea63bdc3"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "ripemd",
        hashcat: &[
            hc_ambiguous!(
                33600,
                "8339009b816d4e4c2a6be3c6e1daac6aca69a7670ecdc583adfca0db17cc8f08ce35d6c759b038ab"
            ),
            hc_ambiguous!(40086, "c79c5eefc7c8e629c12aa936f1bda9a9"),
            hc_ambiguous!(40173, "540a38d3ed9357f8f331867815733fae"),
            hc!(6000, "012cb9b334ec1aeb71a9c8ce85586082467f7eb6"),
            hc_ambiguous!(
                40087,
                "33d5166e2930db590e82d3a855564acc526568c39679d778844ebf9b5be75738"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "racf",
        hashcat: &[hc!(8500, "$racf$*8481*6095E8FCA59F8E3E")],
        john: &[john!("RACF", "$racf$*AAAAAAA*CA2E330B2FD1820E")],
    },
    Vector {
        slug: "as400-des",
        hashcat: &[hc!(8501, "$as400$des$*OPEN3*EC76FC0DEF5B0A83")],
        john: &[john!("as400-des", "$as400des$AAAAAAA*CA2E330B2FD1820E")],
    },
    Vector {
        slug: "scrypt",
        hashcat: &[
            hc!(
                8900,
                "SCRYPT:16384:8:1:OTEyNzU0ODg=:Cc8SPjRH1hFQhuIPCdF51uNGtJ2aOY/isuoMlMUsJ8c="
            ),
            hc!(
                70100,
                "SCRYPT:16384:8:1:OTEyNzU0ODg=:Cc8SPjRH1hFQhuIPCdF51uNGtJ2aOY/isuoMlMUsJ8c="
            ),
            hc!(
                70200,
                "SCRYPT:16384:8:1:OTEyNzU0ODg=:Cc8SPjRH1hFQhuIPCdF51uNGtJ2aOY/isuoMlMUsJ8c="
            ),
        ],
        john: &[john!(
            "scrypt",
            "$ScryptKDF.pm$16384*8*1*VHRuaXZOZ05INWJs*JjrOzA8pdPhLvLh8sY64fLLaAjFUwYCXMmS16NXcn0A="
        )],
    },
    Vector {
        slug: "racf-kdfaes",
        hashcat: &[hc!(
            14200,
            "$racf-kdfaes$*USER*E7D7E66D000180000008003200100010*00112233445566778899AABBCCDDEEFF*5390653DEC0316FB5AD56053208056A6"
        )],
        john: &[],
    },
    Vector {
        slug: "linux-cryptoapi",
        hashcat: &[hc!(
            14500,
            "$cryptoapi$9$2$03000000000000000000000000000000$00000000000000000000000000000000$d1d20e91a8f2e18881dc79369d8af761"
        )],
        john: &[],
    },
    Vector {
        slug: "apple-secure-notes",
        hashcat: &[hc!(
            16200,
            "$ASN$*1*20000*80771171105233481004850004085037*d04b17af7f6b184346aad3efefe8bec0987ee73418291a41"
        )],
        john: &[john!(
            "notes",
            "$ASN$*4*20000*caff9d98b629cad13d54f5f3cbae2b85*79270514692c7a9d971a1ab6f6d22ba42c0514c29408c998"
        )],
    },
    Vector {
        slug: "electrum",
        hashcat: &[
            hc!(
                16600,
                "$electrum$1*44358283104603165383613672586868*c43a6632d9f59364f74c395a03d8c2ea"
            ),
            hc!(
                21700,
                "$electrum$4*03eae309d8bda5dcbddaae8145469193152763894b7260a6c4ba181b3ac2ed5653*8c594086a64dc87a9c1f8a69f646e31e8d3182c3c722def4427aa20684776ac26092c6f60bf2762e27adfa93fe1e952dcb8d6362224b9a371953aa3a2edb596ce5eb4c0879c4353f2cc515ec6c9e7a6defa26c5df346d18a62e9d40fcc606bc8c34322bf2212f77770a683788db0baf4cb43595c2a27fe5ff8bdcb1fd915bcd725149d8ee8f14c71635fecb04da5dde97584f4581ceb7d907dceed80ae5daa8352dda20b25fd6001e99a96b7cf839a36cd3f5656304e6998c18e03dd2fb720cb41386c52910c9cb83272c3d50f3a6ff362ab8389b0c21c75133c971df0a75b331796371b060b32fe1673f4a041d7ae08bbdeffb45d706eaf65f99573c07972701c97766b4d7a8a03bba0f885eb3845dfd9152286e1de1f93e25ce04c54712509166dda80a84c2d34652f68e6c01e662f8b1cc7c15103a4502c29332a4fdbdda470c875809e15aab3f2fcb061ee96992ad7e8ab9da88203e35f47d6e88b07a13b0e70ef76de3be20dc06facbddc1e47206b16b44573f57396265116b4d243e77d1c98bc2b28aa3ec0f8d959764a54ecdd03d8360ff2823577fe2183e618aac15b30c1d20986841e3d83c0bfabcedb7c27ddc436eb7113db927e0beae7522b04566631a090b214660152a4f4a90e19356e66ee7309a0671b2e7bfde82667538d193fc7e397442052c6c611b6bf0a04f629a1dc7fa9eb44bfad1bfc6a0bce9f0564c3b483737e447720b7fd038c9a961a25e9594b76bf8c8071c83fcacd689c7469f698ee4aee4d4f626a73e21ce4967e705e4d83e1145b4260330367d8341c84723a1b02567ffbab26aac3afd1079887b4391f05d09780fc65f8b4f68cd51391c06593919d7eafd0775f83045b8f5c2e59cef902ff500654ea29b7623c7594ab2cc0e05ffe3f10abc46c9c5dac824673c307dcbff5bc5f3774141ff99f6a34ec4dd8a58d154a1c72636a2422b8fafdef399dec350d2b91947448582d52291f2261d264d29399ae3c92dc61769a49224af9e7c98d74190f93eb49a44db7587c1a2afb5e1a4bec5cdeb8ad2aac9728d5ae95600c52e9f063c11cdb32b7c1d8435ce76fcf1fa562bd38f14bf6c303c70fb373d951b8a691ab793f12c0f3336d6191378bccaed32923bba81868148f029e3d5712a2fb9f610997549710716db37f7400690c8dfbed12ff0a683d8e4d0079b380e2fd856eeafb8c6eedfac8fb54dacd6bd8a96e9f8d23ea87252c1a7c2b53efc6e6aa1f0cc30fbaaf68ee7d46666afc15856669cd9baebf9397ff9f322cce5285e68a985f3b6aadce5e8f14e9f9dd16764bc4e9f62168aa265d8634ab706ed40b0809023f141c36717bd6ccef9ec6aa6bfd2d00bda9375c2fee9ebba49590a166*1b0997cf64bb2c2ff88cb87bcacd9729d404bd46db18117c20d94e67c946fedc"
            ),
            hc!(
                21800,
                "$electrum$5*02170fee7c35f1ef3b229edc90fbd0793b688a0d6f41137a97aab2343d315cce16*94cf72d8f5d774932b414a3344984859e43721268d2eb35fa531de5a2fc7024b463c730a54f4f46229dd9fede5034b19ac415c2916e9c16b02094f845795df0c397ff76d597886b1f9e014ad1a8f64a3f617d9900aa645b3ba86f16ce542251fc22c41d93fa6bc118be96d9582917e19d2a299743331804cfc7ce2c035367b4cbcfb70adfb1e10a0f2795769f2165d8fd13daa8b45eeac495b5b63e91a87f63b42e483f84a881e49adecacf6519cb564694b42dd9fe80fcbc6cdb63cf5ae33f35255266f5c2524dd93d3cc15eba0f2ccdc3c109cc2d7e8f711b8b440f168caf8b005e8bcdfe694148e94a04d2a738f09349a96600bd8e8edae793b26ebae231022f24e96cb158db141ac40400a9e9ef099e673cfe017281537c57f82fb45c62bdb64462235a6eefb594961d5eb2c46537958e4d04250804c6e9f343ab7a0db07af6b8a9d1a6c5cfcd311b8fb8383ac9ed9d98d427d526c2f517fc97473bd87cb59899bd0e8fb8c57fa0f7e0d53daa57c972cf92764af4b1725a5fb8f504b663ec519731929b3caaa793d8ee74293eee27d0e208a60e26290bc546e6fa9ed865076e13febfea249729218c1b5752e912055fbf993fbac5df2cca2b37c5e0f9c30789858ceeb3c482a8db123966775aeed2eee2fc34efb160d164929f51589bff748ca773f38978bff3508d5a7591fb2d2795df983504a788071f469d78c88fd7899cabbc5804f458653d0206b82771a59522e1fa794d7de1536c51a437f5d6df5efd6654678e5794ca429b5752e1103340ed80786f1e9da7f5b39af628b2212e4d88cd36b8a7136d50a6b6e275ab406ba7c57cc70d77d01c4c16e9363901164fa92dc9e9b99219d5376f24862e775968605001e71b000e2c7123b4b43f3ca40db17efd729388782e46e64d43ccb947db4eb1473ff1a3836b74fe312cd1a33b73b8b8d80c087088932277773c329f2f66a01d6b3fc1e651c56959ebbed7b14a21b977f3acdedf1a0d98d519a74b50c39b3052d840106da4145345d86ec0461cddafacc2a4f0dd646457ad05bf04dcbcc80516a5c5ed14d2d639a70e77b686f19cbfb63f546d81ae19cc8ba35cce3f3b5b9602df25b678e14411fecec87b8347f5047513df415c6b1a3d39871a6bcb0f67d9cf8311596deae45fd1d84a04fd58f1fd55c5156b7309af09094c99a53674809cb87a45f95a2d69f9997a38085519cb4e056f9efd56672a2c1fe927d5ea8eec25b8aff6e56f9a2310f1a481daf407b8adf16201da267c59973920fd21bb087b88123ef98709839d6a3ee34efb8ccd5c15ed0e46cff3172682769531164b66c8689c35a26299dd26d09233d1f64f9667474141cf9c6a6de7f2bc52c3bb44cfe679ff4b912c06df406283836b3581773cb76d375304f46239da5996594a8d03b14c02f1b35a432dc44a96331242ae31174*33a7ee59d6d17ed1ee99dc0a71771227e6f3734b17ba36eb589bdced56244135"
            ),
        ],
        john: &[
            john_fixture!(
                "electrum-modern-opencl",
                "tests/fixtures/john/electrum-modern-opencl.txt"
            ),
            john!(
                "electrum",
                "$electrum$1*d64ac297de09893a03bc540b346d5e97*0af493539c512e3ded466b4879b8a47b"
            ),
        ],
    },
    Vector {
        slug: "telegram",
        hashcat: &[
            hc!(
                22301,
                "$telegram$0*518c001aeb3b4ae96c6173be4cebe60a85f67b1e087b045935849e2f815b5e41*25184098058621950709328221838128"
            ),
            hc!(
                22600,
                "$telegram$1*4000*913a7e42143b4eed0fb532dacfa04e3a0eae036ae66dd02de76323046c575531*cde5f7a3bda3812b4a3cd4df1269c6be18ca7536981522c251cab531c274776804634cdca5313dc8beb9895f903a40d874cd50dbb82e5e4d8f264820f3f2e2111a5831e1a2f16b1a75b2264c4b4485dfe0f789071130160af205f9f96aef378ee05602de2562f8c3b136a75ea01f54f4598af93f9e7f98eb66a5fd3dabaa864708fe0e84b59b77686974060f1533e3acc5367bc493915b5614603cf5601cfa0a6b8eae4c4bd24948176dd7ff470bc0863f35fdfce31a667c70e37743f662bc9c5ec86baff3ebb6bf7de96bcdfaca18baf9617a979424f792ef6e65e346ea2cbc1d53377f47c3fc681d7eda8169e6e20cd6a22dd94bf24933b8ffc4878216fa9edc7c72a073446a14b63e12b223f840217a7eac51b6afcc15bfa12afd3e85d3bd"
            ),
            hc!(
                24500,
                "$telegram$2*100000*77461dcb457ce9539f8e4235d33bd12455b4a38446e63b52ecdf2e7b65af4476*f705dda3247df6d690dfc7f44d8c666979737cae9505d961130071bcc18eeadaef0320ac6985e4a116834c0761e55314464aae56dadb8f80ab8886c16f72f8b95adca08b56a60c4303d84210f75cfd78a3e1a197c84a747988ce2e1b247397b61041823bdb33932714ba16ca7279e6c36b75d3f994479a469b50a7b2c7299a4d7aadb775fb030d3bb55ca77b7ce8ac2f5cf5eb7bdbcc10821b8953a4734b448060246e5bb93f130d6d3f2e28b9e04f2a064820be562274c040cd849f1473d45141559fc45da4c54abeaf5ca40d2d57f8f8e33bdb232c7279872f758b3fb452713b5d91c855383f7cec8376649a53b83951cf8edd519a99e91b8a6cb90153088e35d9fed332c7253771740f49f9dc40c7da50352656395bbfeae63e10f754d24a"
            ),
        ],
        john: &[john!(
            "telegram",
            "$telegram$1*4000*e693c27ff92fe83a5a247cce198a8d6a0f3a89ffedc6bcddbc39586bb1bcb50b*d6fb7ebda06a23a9c42fc57c39e2c3128da4ee1ff394f17c2fc4290229e13d1c9e45c42ef1aee64903e5904c28cffd49498358fee96eb01888f2251715b7a5e71fa130918f46da5a2117e742ad7727700e924411138bb8d4359662da0ebd4f4357d96d1aa62955e44d4acf2e2ac6e0ce057f48fe24209090fd35eeac8a905aca649cafb2aade1ef7a96a7ab44a22bd7961e79a9291b7fea8749dd415f2fcd73d0293cdb533554f396625f669315c2400ebf6f1f30e08063e88b59b2d5832a197b165cdc6b0dc9d5bfa6d5e278a79fa101e10a98c6662cc3d623aa64daada76f340a657c2cbaddfa46e35c60ecb49e8f1f57bc170b8064b70aa2b22bb326915a8121922e06e7839e62075ee045b8c82751defcba0e8fb75c32f8bbbdb8b673258"
        )],
    },
    Vector {
        slug: "multibit",
        hashcat: &[hc!(
            22500,
            "$multibit$1*e5912fe5c84af3d5*5f0391c219e8ef62c06505b1f6232858f5bcaa739c2b471d45dd0bd8345334de"
        )],
        john: &[john!(
            "multibit",
            "$multibit$1*0908a1bd44147709*c82b6d0409c1e46a4660ea6d4fa9ae12e4e234c98a71a51ced105c7e66a57ca3"
        )],
    },
    Vector {
        slug: "sqlcipher",
        hashcat: &[hc!(
            24600,
            "SQLCIPHER*1*64000*25548249195677404156261816261456*85b5e156e1cf1e0be5e9f4217186817b*33435c230bbc7989bbd027630e3f47cd"
        )],
        john: &[],
    },
    Vector {
        slug: "vmware-vmx",
        hashcat: &[hc!(
            27400,
            "$vmx$0$10000$264bbab02fdf7c1a793651120bec3723$cbb368564d8dfb99f509d4922f4693413f3816af713f0e76bc2409ff9336935d"
        )],
        john: &[],
    },
    Vector {
        slug: "aws-sigv4",
        hashcat: &[hc!(
            28700,
            "$AWS-Sig-v4$0$20220221T000000Z$us-east-1$s3$421ab6e4af9f49fa30fa9c253fcfeb2ce91668e139e6b23303c5f75b04f8a3c4$3755ed2bc1b2346e003ccaa7d02ae8b73c72bcbe9f452ccf066c78504d786bbb"
        )],
        john: &[],
    },
    Vector {
        slug: "radmin3",
        hashcat: &[hc!(
            29200,
            "$radmin3$75007300650072006e0061006d006500*c63bf695069d564844c4849e7df6d41f1fbc5f3a7d8fe27c5f20545a238398fa*0062fb848c21d606baa0a91d7177daceb69ad2f6d090c2f1b3a654cfb417be66f739ae952f5c7c5170743459daf854a22684787b24f8725337b3c3bd1e0f2a6285768ceccca77f26c579d42a66372df7782b2eefccb028a0efb51a4257dd0804d05e0a83f611f2a0f10ffe920568cc7af1ec426f450ec99ade1f2a4905fd319f8c190c2db0b0e24627d635bc2b4a2c4c9ae956b1e02784c9ce958eb9883c60ba8ea2731dd0e515f492c44f39324e4027587c1330f14216e17f212eaec949273797ae74497782ee8b6f640dd2d124c59db8c37724c8a5a63bad005f8e491b459ff1b92f861ab6d99a2548cb8902b0840c7f20a108ede6bf9a60093053781216fe"
        )],
        john: &[],
    },
    Vector {
        slug: "wpa-pmkid-legacy",
        hashcat: &[
            hc_ambiguous!(
                16800,
                "2582a8281bf9d4308d6f5731d0e61c61:4604ba734d4e:89acf0e761f4:ed487162465a774bfba60eb603a39f3a"
            ),
            hc_ambiguous!(
                16801,
                "2582a8281bf9d4308d6f5731d0e61c61:4604ba734d4e:89acf0e761f4"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "mysql-a",
        hashcat: &[hc!(
            7401,
            "$mysql$A$005*F9CC98CE08892924F50A213B6BC571A2C11778C5*625479393559393965414D45316477456B484F41316E64484742577A2E3162785353526B7554584647562F"
        )],
        john: &[],
    },
    Vector {
        slug: "nsec3",
        hashcat: &[hc!(
            8300,
            "pi6a89u8tca930h8mvolklmesefc5gmn:.fnmlbsik.net:35537886:1"
        )],
        john: &[],
    },
    Vector {
        slug: "ethereum-pbkdf2",
        hashcat: &[hc!(
            15600,
            "$ethereum$p*1024*38353131353831333338313138363430*a8b4dfe92687dbc0afeb5dae7863f18964241e96b264f09959903c8c924583fc*0a9252861d1e235994ce33dbca91c98231764d8ecb4950015a8ae20d6415b986"
        )],
        john: &[john!(
            "ethereum",
            "$ethereum$p*262144*ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd*5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46*517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
        )],
    },
    Vector {
        slug: "ethereum-scrypt",
        hashcat: &[hc!(
            15700,
            "$ethereum$s*262144*8*1*3134313837333434333838303231333633373433323633373534333136363537*73da7f80ec3bd4f2a128c3a815cfb4d576ecb1a9b47024c902e62ea926f7795b*910e0f8dc1f7ba41959e1089bb769f3e919109591913cc33ba03953d7a905efd"
        )],
        john: &[],
    },
    Vector {
        slug: "solarwinds",
        hashcat: &[
            hc!(
                21500,
                "$solarwinds$0$admin$fj4EBQewCQUZ7IYHl0qL8uj9kQSBb3m7N4u0crkKK0Uj9rbbAnSrBZMXO7oWx9KqL3sCzwncvPZ9hyDV9QCFTg=="
            ),
            hc!(
                21501,
                "$solarwinds$1$3pHkk55NTYpAeV3EJjcAww==$N4Ii2PxXX/bTZZwslQLIKrp0wvfZ5aN9hpyiR896ozJMJTPO1Q7BK1Eht8Vhl4kXq/42Vn2zp3qYeAkRuqsuEw=="
            ),
        ],
        john: &[john!(
            "solarwinds",
            "$solarwinds$0$admin$/+PA4Zck3arkLA7iwWIugnAEoq4ocRsYjF7lzgQWvJc+pepPz2a5z/L1Pz3c366Y/CasJIa7enKFDPJCWNiKRg=="
        )],
    },
    Vector {
        slug: "snmpv3",
        hashcat: &[
            hc!(
                25000,
                "$SNMPv3$0$45889431$30818f0201033011020409242fc0020300ffe304010102010304383036041180001f88808106d566db57fd600000000002011002020118040a6d61747269785f4d4435040c0000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a226020411f319300201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$1b37c3ea872731f922959e90"
            ),
            hc!(
                25100,
                "$SNMPv3$1$45889431$30818f0201033011020409242fc0020300ffe304010102010304383036041180001f88808106d566db57fd600000000002011002020118040a6d61747269785f4d4435040c0000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a226020411f319300201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$1b37c3ea872731f922959e90"
            ),
            hc!(
                25200,
                "$SNMPv3$2$45889431$30818f02010330110204371780f3020300ffe304010102010304383036041180001f88808106d566db57fd600000000002011002020118040a6d61747269785f534841040c0000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a2260204073557d50201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$81f14f1930589f26f6755f6b"
            ),
            hc!(
                26700,
                "$SNMPv3$3$45889431$308197020103301102047aa1a79e020300ffe30401010201030440303e041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d3232340410000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a2260204272f76620201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$2f7a3891dd2e27d3f567e4d6d0257962"
            ),
            hc!(
                26800,
                "$SNMPv3$4$45889431$30819f020103301102047fc51818020300ffe304010102010304483046041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d32353604180000000000000000000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a22602040efec2600201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$36d655bfeb59e933845db47d719b68ac7bc59ec087eb89a0"
            ),
            hc!(
                26900,
                "$SNMPv3$5$45889431$3081a70201033011020455c0c85c020300ffe30401010201030450304e041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d333834042000000000000000000000000000000000000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a226020411b3c3590201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$89424907553231aaa27055f4b3b0a97c626ed4cdc4b660d903765b607af792a5"
            ),
            hc!(
                27300,
                "$SNMPv3$6$45889431$3081b702010330110204367c80d4020300ffe30401010201030460305e041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d35313204300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a22602046ea3546f0201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$9e4681768d5dee9e2d0ca7380dfa19f0a0f805c550142b889af548f5506c2c3587df980707600b58d97ed1beaa9feaf9"
            ),
        ],
        john: &[john!(
            "SNMP",
            "$SNMPv3$1$3$3081b10201033011020430f6f3d5020300ffe304010702010304373035040d80001f888059dc486145a2632202010802020ab90405706970706f040c00000000000000000000000004080000000103d5321a0460826ecf6443956d4c364bfc6f6ffc8ee0df000ffd0955af12d2c0f3c60fadea417d2bb80c0b2c1fa7a46ce44f9f16e15ee830a49881f60ecfa757d2f04000eb39a94058121d88ca20eeef4e6bf06784c67c15f144915d9bc2c6a0461da92a4abe$80001f888059dc486145a26322$19395e67894fda182414849f"
        )],
    },
    Vector {
        slug: "bitcoin-wif",
        hashcat: &[
            hc_ambiguous!(30901, "14Fqy5AGRehazZ4NLzxFWy2E4BiNFdH9Ut"),
            hc_ambiguous!(30902, "12sLRz1TKPZurKCwVqeT5FkW3Y7usipPbZ"),
            hc_ambiguous!(30903, "bc1q926ca6n7wz7gm2gfd8xc5p0vu687ngvnknpx74"),
            hc_ambiguous!(30904, "bc1qq6samcuksd2f6rsc48eu3lkq87zp33vfud0p0t"),
            hc_ambiguous!(30905, "3JqAMRQN3Gd6i8yV3Kw7v55RmFxW7iW2Aq"),
            hc_ambiguous!(30906, "3PmD8zdrFD8KVgLrguVDCP2RJB4Rh35G9Z"),
            hc_ambiguous!(28501, "1Jv6EonXm9x4Dw4QjEPAhGfmzFxTL7b3Zj"),
            hc_ambiguous!(28502, "1L9nr4GX4Zmd7gDL1UT75QPUqxSgNTvdHb"),
            hc_ambiguous!(28503, "bc1qxd76a5zamfyw0g2d2rxkdh0zt9m0uzmxmwjf0q"),
            hc_ambiguous!(28504, "bc1qv8e65p73gmp4w3z6fqnyu8t6ct69vetsda3snd"),
            hc_ambiguous!(28505, "3H1YvmSdrjEfj9LvtiKJ8XiYq5htJRuejA"),
            hc_ambiguous!(28506, "3LovFVx5zBRvusVcj7pf3JxV9V46kjKhKu"),
        ],
        john: &[],
    },
    Vector {
        slug: "virtualbox",
        hashcat: &[
            hc!(
                27500,
                "$vbox$0$260000$fcc37189521686699a43e49514b91f159306be108b98895666583cd15c3e206b$8$288c3957db47e7c3dff2f7932121eb3395d21ab76b9cf3de2dc660310a25e7ad$20000$8847cd90f8acef74bae41155392908780eebb1d16452aa09b2f7b6cd7d8a4096$9f4d615b484f95c73944a98f392a3ce04f93403e8bb6257e6b6c854273d3a08a"
            ),
            hc!(
                27600,
                "$vbox$0$160000$54aff69fca91c20b3b15618c6732c4a2f953dd88690cd4cc731569b6b80b5572$16$cfb003087e0c618afa9ad7e44adcd97517f039e0424dedb46db8affbb73cd064019abae19ee5e4f5b05b626e6bc5d7da65c61a5f94d7bcac521c388276e5358b$20000$2e5729055136168eea79cb3f1765450a35ab7540125f2ca2a46924a99fd0524d$b28d1db1cabe99ca989a405c33a27beeb9c0683b8b4b54b0e0d85f712f64d89c"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "truecrypt",
        hashcat: &[
            hc_ambiguous!(
                29311,
                "$truecrypt$87914967f14737a67fb460f27b8aeb81de2b41bf2740b3dd78784e02763951daa47c7ca235e75c22ec8d959d6b67f7eedefad61e6a0d038079d3721a8e7215e4$15671e8c7b3dbed6453a114e6db89a52be9a9c1698a9c698f1e37f80d7afaf0efba82b6e5f5df32bd289b95343c6775e2c7f025ef1d8bfae84042a92546e15b635b5fade3aef6ee52a7a5ab018d33ea98bc115dfc62af606187fbab8cbda6e8417402c722ca8c2b07e6ca6a33bf94b2ce2a819a9f8cfaa5af70e3af6e5350d3a306f036f13ff5ba97d5728d5f6413b482c74f528211ae77b6c169215c5487d5a3ce23736b16996b86c71b12d120df28ef322f5143d9a258d0ae7aaa8c193a6dcb5bf18e3c57b5474d24b843f8dd4e83a74109396ddb4f0c50d3657a7eacc8828568e51202de48cd2dfe5acbe3d8840ade1ce44b716d5c0008f2b21b9981353cb12b8af2592a5ab744ae83623349f551acf371c81f86d17a8422654989f078179b2386e2aa8375853a1802cd8bc5d41ce45795f78b80e69fcfa3d14cf9127c3a33fa2dc76ad73960fb7bce15dd489e0b6eca7beed3733887cd5e6f3939a015d4d449185060b2f3bbad46e46d417b8f0830e91edd5ebc17cd5a99316792a36afd83fa1edc55da25518c8e7ff61e201976fa2c5fc9969e05cbee0dce7a0ef876b7340bbe8937c9d9c8248f0e0eae705fe7e1d2da48902f4f3e27d2cf532b7021e18"
            ),
            hc_ambiguous!(
                29312,
                "$truecrypt$d6e1644acd373e6fdb8ccaaeab0c400d22eaa0b02e2a6649e065ad50f91e2f81fc5e1600d1cdf3b4ee72a7326a9a28d336ec65adf2d54661e1a609dd9941279f$d64a9c513dfb0192734fc1e1014cdd0a399e89a0860c4077463c18609f5218254edd998adb11a02271723d1aa094550df385dd8e080cb42ed1349f69c0a6bad4b37e6dab1effbe0095471a8d640679422fe1533a21f10cb6d15e5ee8cde78e677acf3d09d008e9fbf57f09c1c57f19e51ff54631e0e2adc2ee2832425c1ec718d96a17df7e55aceffb7b23a1872f32795d4491c739e21b01e19a1b7dfcb22709c9d9302154462664a668ea635664df65804bf680ff07026d6f5b225762a3a270df832d47e7feb6277a228454a3ba9b5bbade23ecaec0eaf31ad1dbac31754c970a212bd44c9278bc6076f096a2eed602e04a70c6f7fa94ef4e75299692e5dcc6f1a7e6032b9b765e9e61faeed3f9efacc0a15b1817e74d48ec11a13d15811c7e2c4d12f36d35a04131d02f14184fc15bc20e79115dc7c980b681a19a225964469787df481b68a8f722f2bd3115dbbcb3c8ac1b07d742f78f30635dea29dfb1db83e89fc85a30b0379fc8aa69a4ea94c99052685d38c9559a1246284cdc32c5110eb8c6741352cd42e09e6389d4765c58aa84d51867cf86fba69d29eac1cd7fac2f36603d2fb2af146c5d4c2bedb4f6c6d0f387f0a8d635e33384df60f8d2415b"
            ),
            hc_ambiguous!(
                29313,
                "$truecrypt$3916e924d246e5ceb17b140211fff57b67150b3dee53fa475261d465b0ee3e56ee820e6ba3958d84c61508f028b2a112e9005877784e07deddcf310d01ba8171$0b620533790456d20d17c8fda84f9d93bbfe41509b931a417b82d68ed9b0bc9641b79a5bf8f71bcdbba979dfb7566a5b8ccc221f80722c1ce7ec81be4a8c880b1b057e681c187504eabf4eea32f7b81383defd4616618a99852d1678a6520883c8f3564e6dcf874150a060b9a44748d97f95b223b089ac847e31fb5a2db3656d7b57decff65e2c5c9af5bdece7a1845caa9df805fc1f7e56bf545d854beec27a9640bf1697c195e5f95b82c20d76c5a56ff4283219caa5a618e8caace9d0fcde0df6ee6e043ccbc78fd06a602cc638f7ae4675063b840ee08ffa9e143553bffd20126fa30f95e013aabf103f12c3ceeb284c80dc335fe2e78580d6ddfa80511aba9db7c93838cae0db40b9dbeccbf9d160032d334a9c35156721c746b51131baf6855fdfc1edee3099b8e4abc619e1c60e3ce68615e1eb42bd8d338046f7c854a60defe395e0d7168786a3035c9735cd42433dd0c46dcf8b5cb2c28905df80476561e55d6310b25f74d78b651ccd3484332c59a6ad490e29ea267db5ce4a47c9dcde39f420ba0755ea7e5583a3a562925acaa125d5056795b98135825232aa543a460137cc84235b85dd44d65e01e6eb1ade1b970f3ffe2b9762f5a7f261037e"
            ),
            hc_ambiguous!(
                29321,
                "$truecrypt$5ebff6b4050aaa3374f9946166a9c4134dd3ec0df1176da2fb103909d20e8b3c9b95cbbd6d1a7ad05411a1443ad6254e059e924d78bab6a0463e71cf7c3109b7$ef4e837bf6d7a548dd8333c451b59d1132098f44c6ff19c6cb921b1de3bd0aa675e0478a05f90204d46a5d6ff598bfa40370ac8795928a6d2e0f1347696e3cfa329738170fe54298981d84f40c63d1a338c5db62679338e849124a28a79a8e505bb89a4673f0457b2737a00b908116310281b5b2eb66c6fda5599196b313d51ef26201335d715c18f6b128454a5601671e619bdcce8e54acb47d498c4161614a05063bff5497a4a3d99bff1fce2a163727af2fe9ae7512461b9dcebf3a4f1031d6235d8ce09b734294d0cedc04eafc6295f212b1b080e7b9745580d0dd18e99cfd95afef982762d5aabeaa2d3a928dcf36322cc06b07fd719c88e0b9a2625a94a77502d4bd40a85ba138cbd0cf9561aa395dc552801f68cce16e5484a672aa5b78665dc531ab1e3e728185929dc443b7f4c8a5cb687c6589bb3f4ddc2a8639d959b839b0813d50e7711b761622c3693a92e540e4f932c6c89bf4e1bff1d69151848c3d01b2f6aba52b58e5b393f6cd58ff0d2e040b1205b042b5a28d5b12cb0cc95fa32f1bcdebd4c82d889a5d87c45dcfd34e80b19bf7be35696e0fa0cbd9338b314de24c1ee7bbc0a3b6824f86af2aa5d127d21444985ff566e921431938f6"
            ),
            hc_ambiguous!(
                29322,
                "$truecrypt$9f207bec0eded18a1b2e324d4f05d2f33f0bd1aeb43db65d33242fa48ac960fad4c14d04c553e06ad47e7e394d16e0a6544d35fb0b2415bd060bc5f537e42a58$b1681e991e2ec0b5773f6e8e5766e5fcc7335b19dd068d1f20260085ecda8eba366ff1521997c5654630ef09ba421b871a3dc66aa0dd5eba8a3bc7052398a7ad779506d86cbf687e76cd9dc50969e222820d2f905c0550995a9c068725bb6c8b04358c965ab77221fdfd829e57ce54cac6e2fa62db15043d720b72fa8962dd718a0b42c34577af9cb4a5ed04c1ae17b7af470c0d8b77987dc9e2d2593a52458c4acb83b628b1488371de85f78a2e25aeaebc18d20a8c3007d08949e93b80087707afd1fe4e07a0afee4244e5270f768e234b86852aa1556c53ffc0d6f60661369a484d55d063119e71e70af1ec775908466cac7b12bc22e1a9525c2bfa9f83f7901c8e0a1d56387ef65040b750656b0b75791738b5b7e453f24167eae56c057c94e1e4cf1a0d08894225f11b45bc31827cad1dfe62e148549385953aa16a0410dba231aace3a7b9fd9b1c2b930f01193377b59736d8a8959ca5b449655f79a4dbec0da566083f90caa2490b01a10c0a86dd4aaa719bdc1e4233db17217f03509cc20dab7246730e3f964944990690b6dcc84936e1dd487bd154ceefe58a838a0488cc93b854a112ea67f6802d2f409915e648ee5cf5fdc3c12e41acbfab7caa9"
            ),
            hc_ambiguous!(
                29323,
                "$truecrypt$721a7f40d2b88de8e11f1a203b04ffa97a1f5671623c6783f984cc7c55e04665f95a7f3fd52f402898aaaed68d048cc4c4fabf81c26832b589687dad082f3e4e$0f23c7caba28118f21a4cbb8f32b25914ff4022e7c4c8cdd45411801c7c6bde4033badbdcb82f96c77b42025d13fa71415b3278138100ea58ee4476c81ce66f78e89c59ac22cf454684ea7e8c3900374662f23c9491891b60ed7ce8231a7ac5710ee87b51a3f7bd9566a60dc6e7e701c41f3810d7977314b321e8194349909f2ca458a976851d854eaeb934c8df2b5e063d416d3d7c464e28173a0bbba88ec75cf8fe68f21067739b2473bd804fd710de1e4d3ae9451b374edcfd8e3cd613b23aeae272e0923007482dac26a7532ab09af8aad57cd7f1c451bc260cc912d5830cb0d5332f792519e009ed5450171434e5f0f2ba9e003676933a86d83c766419fac98a7ee232eeb593d1686528fab576d5f393d82f9602bcd65975153df205b6d1bc50dacad2ea5bb184696f978efd2b1c1656bf87e03a28a536c48320c430d407ff6c2fc6e7d4ae7b115e79fd0a88df08eca4743178c7c216f35035596a90b0f0fe9c173c7d0e3d76c33a8fce1f5b9b37674bd12e93fb714c9cbba6768c101b5db8f8fd137144453f00dccc7b66911a0a8d87b198807f30be6619400331c5746d481df7ad47a1f867c07f7b8cd296a0c5e03a121c1a7a60b4f768bea49799d2f"
            ),
            hc_ambiguous!(
                29331,
                "$truecrypt$cf53d4153414b63285e701e52c2d99e148c6ccc4508132f82cb41862d0a0ac9ea16274285ac261c339c1508eec9fea54c33e382458662913678f2a88a84959a6$78e238973985ec670d50252677430587ee28b72bfa5edfb2f79c40b734ba8a54a3662642a6ab067e75f41154688ad4adb5d6decd891462dd537188195a51e06fa5baf22b69d0f472cfeeae77ab9a90091731863af1d8b5b380da179fa7d5227ef031732b1ae06e0fe34c0b28b7a64eac34e5a08e09d7001394b3afc804ac69bf819cdd2d383fe96a721f7c683628da8e529d84bdaa68d702573d8f7ef26f75d1bd5c91efa88cb33b1e9c006b87981c55ed3b8063ab7068f8e99b128bc56ea3e883efa55d6f340b2681e50405d91f5f6d76cdbeac404944164d329d3ee01311de0bc6547310f126b5a4c0e9fb74825f91faefa60b7ac828819d4544c1872ff5041e61d5cf093553f427358b2181046376d7b876e1bccf0774d5d251b7c922c214bb5c70c715165d028e1dca73e7adeca3396d77f6e597a10dd4c58f37fdbbdc1d04cd8890ba4c5025776a88a349bb925add13193becf1ca10fe32536db0c0b06a1ef799fb692e304b3716ca5a8a80859c4012ca3e06701b46b5a32f4d10e285a0cdaf6c24e0d98139e7f306e52503c9b503aa28f1fbbb236284907068074fcb3e267e3c4aab2bd3b79b24a7a08106bb55850fa2bb8e2f6d9919a6743cb822c164"
            ),
            hc_ambiguous!(
                29332,
                "$truecrypt$e9e503972b72dee996b0bfced2df003a54b42399e3586520cf1f69475ba32aff564e40e604a505af95ce15220f558ae815e94ce4953882a8299ee3fffb12e9bd$62bf8e2c41c0a8337ce20d45715440cc83e394200d351c5b04be5b70fa11b8467320a091a1d703c88cc7b26fd114795c04a973b3266ba97f55d4b4e4771bb1b4a6aabc9d57e03f0ae7c8a77dfc3d37078efba45031e7d63bb514726e2f2dc6da8cce167a17e36b32c326a5bcaa2c4b445f6e10e1f899a9adcc2a698769f900b7909f7aec52fc9862d75286ffda67933f9c52e5c681d590ad0329b85f8db0f6bb6daa3b2d55b62c65da37e3e7fcb99954e0abe20c39724e8fb2c7f839ec67d35f151dfd8c4dd4bc8dc4393fab291efa08cc0099277d219a0ba4c6272af3684d8043ed3f502b98e196dc7aa0291627613179199976f28eff08649acf70aa0c0dc5896ed13eb18ea28fdd6c460a9c7cfedeab5ac80a3c195226cfca094a7590fa2ae5ed2133ba09b5466b2049b6291f8dcf345e5718a4c0ef3f9c8d8e07d0e5dddd07452b533fbf243ef063fb6d26759ae725d8ca430f8cf17b86665d23bdff1c9dbdfe601b88e87cb7c89f23abc4a8bb1f0b7375cc29b1d81c950ffe92e16e2080e1d6270bbb3ba753322d2b623caed87213e552c33e699d4010f0f61df2b7f460d7cd82e70a711388f1c0b591d424259d3de8b3628daf62c6c5b71864eb0e7d31"
            ),
            hc_ambiguous!(
                29333,
                "$truecrypt$de7d6725cc4c910a7e96307df69d41335e64d17b4425ca5bf1730f27820f92df9f20f3e855d8566eb5255927153f987348789666c8e563e366a09e68a8126b11$c25ac817b2706dde5cec3946e64332b21b41b928985c1a637559ead5b4fecac74ff0d625ef6d8be93dea3eaca05394f23ee9e079d3504a77b4c0b22d3cfcafa9c670966bfa3a5f30539250d97267a9e56b5a1437b1fd2ce58f4ab78b52ba61d01c28d7a6b726d92c8819711c70f820690cf2b9bbef75f196ba87fb5f72a29e213096a8be3b6e6d0ff3dc22563dc9e7d95be68ad169c233289fccfdc2f5528c658cb178b4e78d54e96cb452859b01dd756ca0245bdd586fb450e84988071428c80af0a6dc5f16dea8094da3acb51ac5d2a710414256b2423e0333584437ea9a65a07f06bd241103a478d137e9a274a78a19d3ca121f1bc10e4c9e5fc277d23107db1fb447f71ba0f92b20e3ead77cffaca25f772182705a75e500d9aab3996bfda042f4bdfe35a3a477e355c76a711ad0f64848d6144073ce6ec4152c87973fc3e69626523463812061c51f51fc08487e8a4dbae1ca7965c11f222c607688b3384c5c29d4fe91d14d2cc940a6a9d94486d1823261928d88f56fe00e206d7a31734de0217afd38afa3d2cf3499c2dcff13332a369c4b1f39867f6dfc83ec32d19b931b082f07acac7e70bdd537e8432245c11662d89ec3cc97e582de5d2cc6bde7"
            ),
            hc_ambiguous!(
                29341,
                "$truecrypt$2b5da9924119fde5270f712ba3c3e4974460416e8465f222149499908c2fca0a4753b581f26625d11c4d3f49bdeb1c95bc3e17629d7e19ffb66175e5feab90a4$fd670194f95d578266f3f54e61b82dc00efc2bb4438e19c3f6d7a92825a7625d88ec6286ab4e1761749edc83dad4340fd167544f09913fd6b03775013ff232fc4dad6f726ef82ad4bd1c5227a7796d7db35a912beeda5b0cdd798bc34d3ac24403c87dc672a983687dd64f920c991840a56105a6311797eed9976014909700366420673f6455242c71151ac75903a353538ec24b4feb967e2b46886395cf3e934e83a6a58ef2c0180273a0c33ba2bd870b1d84afb03d5558dc17bc7fb586404ad9a7e506ed859540110c6ad73f0f1d2be47829bc666e1838ec3f1dc1f610206241ce07fbf2542ecef9348b37aa460815794ca582709697cbf0c90c3dae4cb9dd97b29d3c7d82bd8d0c81d708e74c7007468c6c55a40fd4f803a4f5a75818d7da0d1ef333b8622e7de516fa62a6fa2b8d6d5d23653dfcedffec771456ee204e5c85ee88defbe195462fbe8ce0e2a5a455dab66478b877ec37dfa66f19ab5201c56cd707ba7bee1b10360965d3868c1fdf91dda124b1b0994fee75848083d19369735905bd2864b496c6e35ecf96f6dd4728570a45746bcf8d7d0ec0b9b0b112b28fdc53efcfa7d0558c132cd683a742d62b34304d9f991029c8aedc3d8767da8c"
            ),
            hc_ambiguous!(
                29342,
                "$truecrypt$debcc3e74a7b2acb4c7eaa4ac86fd6431da1d9579f4f76f0b31f07b3d36e65099daca9e4ae569114b3cb6e64d707b6206a2ab6b31ab0c17b356da3719d0e2fa4$058f0349763970855d4c83b02a967bb2969f1b6f3e4fdbce37c6df203efbe87bfdb5ffd8fe376e9ad61862a8f659ef0db39e06ed34c4f80aa856df2219ac6a37ebb0244445db7e412b773f4e28846c5e65129cd4f4ce76979c083f08a7c4e2be30469b8363eaf8579baa870cdcb2bdca6b60e64559cb0def242576b80722bf36eb6d94640d2937b49edf9c9af67f0172f27319448425f86831c35ae35e764b9e69fcc47a42ba7a565d682366023291b1b4cbcd1b7ba6fba75c214e5849a9ba26197f7f010f01301dcbffaa7311f2ab32c2810470d3fe873334ca578adbfd04c5a39cbd53b09755e4d868dbf8a44d76cc91031f4710b8a985c70738b443572b4745ed10e6120852870b0fdb258f0a804d679eec85b5290235c9c526165b961f17ff0fe32d9f597c8f2ab9b84f3d22fef71fec67987e687590de6ab11b33f1b06f23c38ead94c3de419061b6568612c27517b0a3395e401a2c6058fc5f41f0e084e8f2157b6486624314b1f341f74cfdec9deaed7abf89ccf97b47441493e5086f1351f42a5c0929f6431753baadcd2fb347b8835d08250743bb45aaf1c6bb30eed98e911a273074b7e8ebad2174b527b1b84e1961967bf358711346482d9db1c7"
            ),
            hc_ambiguous!(
                29343,
                "$truecrypt$5e6628907291b0b74a4f43a23fb0693acb71c4379c3a3cc0eafbab40036bbdadfede179e04484aca0f5b6ecf7c7e8abe61d6836be6590838b8f9027da93ba77d$076b9a557c958159c5dcddfb70823b7e324bd99b40a8f39410f6afd279df3493b58b9ffce41b65f3afd2fc467f4553a946b85e6ffc74b91c9c38c689d98419339a84d3c6d116274e34482d546407006ee04af03b594998127b2a9716ca4278b1f3050d015af10a9bb11db0465373f3a786c148bb20473377d8e97264b1c4d7ec4179829ce929573b26e5987b59da8591e2dc8e3934830dd0b5ac521c8637e9bb31e4bc084d53bc6a8dc6875e857a4c8c32a577eed3c6cea5beef514160982be2c7d7e2f4d65efa3f4a0e11ac1860ff3160e7cd968e18019abfd0395080a9f8e860c627fc32c63c8b7ef46b203c63cf0f12c05ea65b1f83a5f1fc6ad6cc200a9527151c2b8016a38f1e87be9c960088eaaa98a01d9db8cdacaae26c446a846042a6c0248b666eea7a1be44dc3fc35ce100c3a3eb377e898deb097cfba9246685d7ec8527cdc5e1983c154169178e3d86cd4017606ccc42d25cbdea0aca2b1ac422372cfbb1ad2b7d465449a2c1fbbae35c8e7fdaadd683a7dc991b76aaba08b8706916924407392a2aef458c2e833290dc1ff116f3f49f918e6a133b60728ac7c464e4f3521784cf32866be32877534bb014312c4301d1740781221a5e8758ea4"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "veracrypt",
        hashcat: &[
            hc_ambiguous!(
                29411,
                "$veracrypt$531aca1fa6db5118506320114cb11a9f00dade61720533fc12982b28ec71a1a3856ac6ee44b4acc207c8230352208d5f0dc37bf755bd98830279d6befcb6001c$df025f816a0aa1baf3b9b51be00fadb451ffbe9bdfc381115eeceeef778e29a8761f853b7c99e0ea9ec452ba77677f888ea40a39cf65db74d87147690684e273313dea15ff2039797e112006e5f80f2c5baf2c11eb62cb63cfb45883f8885fc7cd5bdb74ef57ec4fe3cec5c2025364582380366169d9419ac41b6f6e878429239e52538f9698e73700b920e7b58c56a4563f5aa512e334ddc56909ac2a0ad4146833f050edd78b7954e6549d0fa2e3b26ed2a769a6c029bfa4de62d49575acce078ef035e366ec13b6092cb205e481bc822f87972bfbe4a3915fad620c4b8645e96bcc468d5804208ae251a560068a09455657f4539dc7e80637fa85fbce058ffee421a98d85b2ae1118d9bd4f24e1e810627cc9893b7166e199dc91fd7f79740530a472df0948f285293478042b28cd2caef086a6ce9d5f656f97adde7d68924ef477fdf2a0c0b107671a1f94b2906d8fb58114836982e4e130e6944df8b42288512376553a1fa6526f9e46dc19b99bb568b30269d9f5d7db2d70a9aa85371b0ac71a6f6f564aaef26a0508c16bf03934973504a5188de37b18a689a020bc37a54d2863879e12902b43bc71c057fa47cbaac1e0100696af365e8226daeba346"
            ),
            hc_ambiguous!(
                29412,
                "$veracrypt$531aca1fa6db5118506320114cb11a9f00dade61720533fc12982b28ec71a1a3856ac6ee44b4acc207c8230352208d5f0dc37bf755bd98830279d6befcb6001c$df025f816a0aa1baf3b9b51be00fadb451ffbe9bdfc381115eeceeef778e29a8761f853b7c99e0ea9ec452ba77677f888ea40a39cf65db74d87147690684e273313dea15ff2039797e112006e5f80f2c5baf2c11eb62cb63cfb45883f8885fc7cd5bdb74ef57ec4fe3cec5c2025364582380366169d9419ac41b6f6e878429239e52538f9698e73700b920e7b58c56a4563f5aa512e334ddc56909ac2a0ad4146833f050edd78b7954e6549d0fa2e3b26ed2a769a6c029bfa4de62d49575acce078ef035e366ec13b6092cb205e481bc822f87972bfbe4a3915fad620c4b8645e96bcc468d5804208ae251a560068a09455657f4539dc7e80637fa85fbce058ffee421a98d85b2ae1118d9bd4f24e1e810627cc9893b7166e199dc91fd7f79740530a472df0948f285293478042b28cd2caef086a6ce9d5f656f97adde7d68924ef477fdf2a0c0b107671a1f94b2906d8fb58114836982e4e130e6944df8b42288512376553a1fa6526f9e46dc19b99bb568b30269d9f5d7db2d70a9aa85371b0ac71a6f6f564aaef26a0508c16bf03934973504a5188de37b18a689a020bc37a54d2863879e12902b43bc71c057fa47cbaac1e0100696af365e8226daeba346"
            ),
            hc_ambiguous!(
                29413,
                "$veracrypt$531aca1fa6db5118506320114cb11a9f00dade61720533fc12982b28ec71a1a3856ac6ee44b4acc207c8230352208d5f0dc37bf755bd98830279d6befcb6001c$df025f816a0aa1baf3b9b51be00fadb451ffbe9bdfc381115eeceeef778e29a8761f853b7c99e0ea9ec452ba77677f888ea40a39cf65db74d87147690684e273313dea15ff2039797e112006e5f80f2c5baf2c11eb62cb63cfb45883f8885fc7cd5bdb74ef57ec4fe3cec5c2025364582380366169d9419ac41b6f6e878429239e52538f9698e73700b920e7b58c56a4563f5aa512e334ddc56909ac2a0ad4146833f050edd78b7954e6549d0fa2e3b26ed2a769a6c029bfa4de62d49575acce078ef035e366ec13b6092cb205e481bc822f87972bfbe4a3915fad620c4b8645e96bcc468d5804208ae251a560068a09455657f4539dc7e80637fa85fbce058ffee421a98d85b2ae1118d9bd4f24e1e810627cc9893b7166e199dc91fd7f79740530a472df0948f285293478042b28cd2caef086a6ce9d5f656f97adde7d68924ef477fdf2a0c0b107671a1f94b2906d8fb58114836982e4e130e6944df8b42288512376553a1fa6526f9e46dc19b99bb568b30269d9f5d7db2d70a9aa85371b0ac71a6f6f564aaef26a0508c16bf03934973504a5188de37b18a689a020bc37a54d2863879e12902b43bc71c057fa47cbaac1e0100696af365e8226daeba346"
            ),
            hc_ambiguous!(
                29421,
                "$veracrypt$2be25b279d8d2694e0ad1e5049902e717f1bdf741bbd678bf307d510741b649d78c54dca46fb2c92723afd9a40769b295e66d445ec232af5bddf91481ee41256$e56b77839e8bf55265077bab405901218ac7933f74073f1208f1de72aace5da4e07d5f83ca580c0216d36c200b54570a1d58e9d8e5c98a597dec23b74a465aeac572a99af70e1a1e20fd29c7c296099e4eed5b715cb470617ea4f20140b62ec4694af67d9158deac3ce846718e10518875ce8cea0286a487a295979e67159d06e871789bf5535b75c809b340f8627e18679e3dab839a1c9823ea14a07d5cc4251b777dddb408da147c70e7cc788a01c27b0ba4f4700d3248f59fa8217874ae4958ea4518522b44f7191ec19459faef7678422adecd58777487ef54a5305ff2caaa545dcb82f7e7a3eb30bd9f7ebab542d0964a367f9c710cf26bbd704e841d591428da3486db31c57f91c6167bf99e31839363cb93bc60d755031f96f2d2c964e1d85b7eaa104985ef801a21d99352c025d7415d5b2f1aa37dc513345d0ff6a1bca92ad7b8c265f322d04f2992895de32636c9b03318cf7154632d547debc1c5e0c8f8730a045efcf3d16ff956cf803716eee22168bc5a5ab72ddb5087436722cb0f59a5b7b03bc557ffb50e8757d1a5639e2bcddd8060de4ee5535fb614b4fc159c6a39040dcbe83889b9c6fac1c9364a7bea930d916ea23fafa0fde07ef609"
            ),
            hc_ambiguous!(
                29422,
                "$veracrypt$37e6db10454a5d74c1e75eca0bc8a70e67ac032357e4bd6a4315c0174cf9780f92210dfc0a3e977969f2890828d446aecc317dc40fb3162915998cc703e49257$a950a1603342913900052011a7fa85fb0b1fd4489f17237ac1a8bbfd644e871ab95a4019f14b2b938d627646b9958b530dd0739760024ad323d36962b60ba92908e55a876fc392ac2dce6a2410bcdd30a01cba90427f02ccb96e222ab1381266a6f626aa00b0f59e743c1a77433cbb28648f04c91853bdf9b8b29917b2341bf7deb013131ad228ea0c7f9435985318431dae59faff46db3726341b97a956da4ad11766124cd06644c1ba1083b36d3f380f20c272e460b958841fc23be1820ad2e0e6db66eaf4ea171035add0ab543ce8e853e3119ceb9d7f32c0948b81604b81075bcb33efe747fec300a7c68ec383d28d560cccce713c0acf51d74c0db718ba93a9e720b657dda2409adf1ce35aa7e1c0d7ed3df98dd0b6d455a355ce02bda8bea8afc0a8341ac78214efd4372b4430270009ec65badf186e5f0d815dcf597b4703af95e3bfc03313125d2a88b9bb3788b6bbc3c7212713cd584a226b155a2e6872b33730af6fba29aa3dccdb0ec35b5d6e3d981faf39c8dd35fdcff502d14736bc6a47af6e4d7f3518f8ef5e0a4e5d521589a761757f86e2bef471d9867e9b532903c479e4966dcc99189fcdfa3d676f50ccd33fb7cc0aa3e85542ff2648c9"
            ),
            hc_ambiguous!(
                29423,
                "$veracrypt$d44f26d1742260f88023d825729cc5a64cf8475d887632a2fb4a84af27af138cfadc4bcbb122f6ba68339ae8427d1f72c0c4aeef041291492ae0a7d8677d8da4$3227ae2a26d9a433076b44458b14f52766cf0e4baeb473a789180660d62e42bbea7c042379a5a74e259463e1c18381fa13aee27141264be381de71c12f8f704913f211c45fda0295e963d90fc35272e907858c0522601f6e7a73b43ff222663f149a485fc6c464e5f3b7cc0b6508f30621385365ca8a4e0bff4061f64f5fbdb11f70f19d77e56fa6ff015ad76ecaaccd759d30da05d2a6fbf00ac9673ac3c23efd339313c2a99511e928f976bf9b2664d97685498d5931af2d453edc6fb1129e324eaba64264711fbe21d0d202b3659106e8100634f09c38cd15b1b3acba79d7f31d31fe23c166392e300db09f10550c83187566dc0fdf768b872555851b34e3c15ad7e7438a72e6126c895cf1204987df4b42cb7bc2fe03c5777867d269378c6e496df2a1a3457b907f7143a139d800868ad95e2901723c6ebb991054b4e991c67fe4c17702d9829d9dc1fe8bf4a956460721c858e31dbcbe56850a4ed31558c6ee89ba2cba2ef4bde77fed11848f9f92e0add54964a683c3686dbab4695ebc42554da922a08c6fff32cac936ea447e771aa74a689eb269ffef677294ef297600dfd73bbbb734d2968e38a98b4a8a77ff0eec8246d93b542e3521a3eb636101"
            ),
            hc_ambiguous!(
                29431,
                "$veracrypt$48f79476aa0aa8327a8a9056e61450f4e2883c9e9669142f2e2f022c2f85303b897d088dea03d64329f6c402a56fed05b3919715929090a25c8ae84c67dbdb36$4ebfa3e9ccc0b391c130a4c3dd6495a1d6eb5d2eab72f8009096f7475ecb736bb3225b6da144e1596d859dad159fae5a739beea88ea074771e9d0b2d7c48ae302606a60d7cff6db54f3e460c548c06a4f47dc1ac203a8c8349fbff6a652219a63f27bc76327543e22be4f8dab8e4f90a4283fbf1552119fe24114ce8869eb20ce87dd72300f7aad3f7b4a26a355f16517725449151cf0373dbd0b281f6ac753485a14a5361cc75d40928e241a6b4684658801774843238048cf8c7f2fd88950abac040e12b0c41fdcaca3702907e951ec11c061a91b3050a4855abe6f3b50b4bd0b17c4be1f5b50b873eadc2d8446cd72c4fcac576bbce3acea769f740c5322ee8c927ffd4dd11c8a9e66f06e58df2e5d4d85c13b44c412bab839c9512b7a0acdd97b37dcccc4b70854eda0f36de12d62dd10cc13bc6154103d083bf6540bc78e5d0aad5d063cc74dad4cbe6e060febda2a9fd79c238f99dcb0766ff4addcfd0c03e619c765f65b1c75d5d22c6536958bcda78077ff44b64c4da741bf50154df310d4e0724238a777b524237b9478277e400ad8146dc3ca1da83e3d2f1c5115a4b7fcdc71dd7d56ba86a2f9b721c9a4137aabb07c3c5fedcf5342c4fae4898c9"
            ),
            hc_ambiguous!(
                29432,
                "$veracrypt$1b721942019ebe8cedddbed7744a0702c0e053281a467e0ed69bf875c7406407d72eb8f2aea21270e41898c0a2c14382f86e04c15e7bc019d1d9dd813eabee0a$e5173e3cb1d927859d3e6de1006335a5184ae12b4c8dc2db2b1cd785063152a776f4dc5cacc1856a919b880d704b7450f5a0e0c9521bc9b4d67213c36a50e6664a1cbcea33f997b858e654111c7e9fca74f361528e85a28880381ec2600e3c1cd508c3833dd21cc91978185cba53caefd7b3c82d219d49f0b41e536d32e8d3ce194ad7923ca742213e19dcebdbd9687979d5a594654a5c611e8b829c4019e90a3cfb14e5fd7f8ed91e0fc79eed182399f02a3e3e202d4becaa6730e1f05f99ce06ce16dba7777ccddac72e85f2d3be5ecc9c808ac273f10ceb71cad666166abc327c4061a5f47424a5b6d9d093782f34b49924342a2e8cea663446ed4232a9a415ee2dfde988fa827b06d7438fec20ad0689543c3ee4602ce3ec3806fc7d668ef7e34330edd1e077b329a7627fa3ae5c89308258a17ecefbee114c80c2ab06f8271f14de8f2d13d1d6e5a119b71a6bae88ab151f76cdb2442284bc481d0df7e2163c3acfe763d3968195450d275af9034a00184a30cefed163e636626bffe6a35df3472508a49cb2b9b4c4a95d11c5d17e4e0539e9f13112125515778bcd1c2813c62a02673663062ad60583ec6a02c8a572865829e5b8c767b285728bea4907"
            ),
            hc_ambiguous!(
                29433,
                "$veracrypt$5eb128daef63eff7e6db6aa10a8858f89964f47844acca68df82ebb2e73866fa75e3b7a53f9d2ff1ecdd1f4dc90e9c0fdf51f60d11b1992cd2971b4889edfc89$20bbf346fd7693f675b617cb9e4e9a43e6f445021068fc13453b130f2eb1d753ee83ecc61dabec293e88b62110cf6a8fab670e171f6aba2226550b54893263f5fa086b3cc41dd3db2eae07b585e5162c7a0d9723a426d408d83266c4d6018dc1b8b456d28a224033a30bfe62b1e58c2ddf596e07f7ff31849a6f5cfcc1c977b82d8484c270d44ededb0afdb781295e92968fc8cc69766af0ce1e72f02d6b4e124ba4b1af71519dcaade857bb3f371f93a350da6e65ee46c2ac782f134c75c10fe9d653fccc08c614dc362871911af8b83bdfc479f770dfe4b3c86b5d895842c53852fe4912738f848bf7c3e10b8189d25faceab9ef30b6fa0284edaa471752ac2b65335179b8d605417709f64fded7d94383618a921660d4cdb190bbb3769a8e56d2cd1ee07078ebc3b68ebeb016893f7099018e40cb326e32b29a62806eaf1a3fd382f4f876bf721eadfc019c5545813e81fd7168995f743663b136762b07910a63b6eec5b728a4ad07a689cceecb14c2802f334401a0a4fd2ec49e2da7f3cb24d6181f01ceed93ee73dedc3378133c83c9a71155c86785ff20dd5a64323d2fd4bf076bab3c17a1bb45edf81c30a7bd7dbbb097ece0dca83fff9138d56ae668"
            ),
            hc_ambiguous!(
                29441,
                "$veracrypt$528c2997054ce1d22cbc5233463df8119a0318ab94aa715e6e686c898f36690b443221a18f578fb893e0db1e4b875cc711eab542e70e13b55d6aa26134e1a8d3$4f5ae6caaea7390a5e2f50130e85f9e551216dd0895f4fb0bcdec219246c249236771e1f2a1f447054d363c398ab367ed7f9574eb0611211e742f429cd53b56fcdb42d2eb183c134847dc6efc7c8293d6481aa53406f0446398591956f79ca3ce76e80208fd409d0f6f14c68312fc119ab4292972338b1457c73585ae2fc863bf202f141495de50253799cbc27010fba6de6b0a36888d12f4e3964aaaf43a830097aee7d40c5e79e5e80e7b0228a67a95bb4969dd8afa0d51d6fff340f82e824547c708b5aa59274009d7d847c53a8019e73c068c6e96a4c3c6c27d0e9f4a8c3a9c52c964eebc00128e9a539f4f569606c92bfc2d4662494a1a6aca239d73399645c86bd66b8985b5bf217b29eeba0507a388aeec85fe94f6b42a1b805ecb90a08b2c8081fe51e76bc1d97f73ae10c72a9b2db694304e04807820c088f91bb97d4585493f3e6cc392a7e56a64a66b8e11b51898b4f956d1b5fe8cf55772fd6f8c0f2a2bb2d9fef05ab2bb90f251ff2e6aa0dfffeac9e045be2ec44ebc8dd4d260748e308205475dcc2cef369e869bfc1e6d7335620c694f524260770838c768346d83af7b467cdc80814d8f55a535dbac35fc278d0d1f6101db95019cee097bb"
            ),
            hc_ambiguous!(
                29442,
                "$veracrypt$a3c0fa44ec59bf7a3eed64bf70b8a60623664503eeb972eb51fa25ee921d813f8e45d3e1ab1c0088a62482bb78c6e07308d2308d3d66831505b0cb02fe214fba$c8a51cf9be2ada3c46045afa7df810f2e7b57792150de63b111a9aa78d70e25d832b3d6901aa455b32da240ff68380d66da27f4f7ccc5fadc6b3ff68e27b6d5c48e6512865e3b9fbe2a64a55454cfc333d7850603ecf8e1cf19abaaf8c1581a6fa14c5091ebe70e6338081d72d6a95b542764f3865946edc8e626e166cc2e0f6260032f8decdd98f9a82aa2b065a41e9b42ce8c33d3f935706431d19888bd5b2bd4d34d9bceb8596b15994f247169ee7f8cd34b6955362b60f37a4167c7b63bab8af65e7c592e9ba4535c255b4b3d93b302aa017ea335af20f9d9696f1eb37770ca87b0245d29887cc4611a3a43d11170219c509814eb1fc122a189c08394f22309dd48a996cbfc70cf67f76b6b19e46407a12ef001b2c360501dbd63d1c9f85132204709204992078318920b32aac917bb98d8eeefb60abef47571404d069a6df7881f8e7815c18789f23561d7d33f47e1aa97fb4a60bac0332b0e742a9b0498e5641401567615fd6dbd0fcfff07aebce0d543f2c498486f15f38dcf1dd55d7144d3fc51bf1f491798b183a84f3f49a72944c8054cdab915e19dc376ae3fa681d4afcd7b13f425e96340a696a4f11929b2e769ba207c5bf2c2976a3834c499d"
            ),
            hc_ambiguous!(
                29443,
                "$veracrypt$1a8c0135fa94567aa866740cb27c5b9763c95be3ac0b7b5c744a36e48c08ae38d6d06ae5db926c64d05295cef134fb4d8eaa96a7b5673a1439f55c8ab829390e$a945babc464e63f3aa33dcfed72c1bcf4051af13da96a2601a060d8c8be0343a7a4f0394b2bdd419b019bd10c3d39f0b6d9afd833816ee9ee5a8afada52db174a85ee029c46b706f8f96e937bb71569b65c2339a3ac8d831733888717fe08029013931ebed1fe932ceb16e52a5d54204e181057584d06991b8e9b16ba557d38f00e7c2be5ea864473e5e35d00a58b7ef8888c78d52ac1933011ca6c447bd16751024186657d1e314540e2c847115b70a51a23e61426ae09e646d715f807eed85e5c14ab2130da0ba86ddc40d3cdce035b454fceb969094d8d1b66e69f34e24d642dc244a81d163c395837d4cd9e2d581f4bb470ad4e5a2037068947f14676796f4adf208621c3db4629b3fec9a24edebfc37f97ea657295a2efbdd18fc44a0cc04f429d4da374db3ba2f3fc7dece70b64ac2c2a94ce5334b20b4251534f9ff3f60b1b252019d2617379bba68a4bc621cbd070881301beb0300bee243d113347d2f0a52fa79fb9fb349eba0056678618c006287e9730a0af32daa17841d88b99e25a9afcedd292a0592565f0ba533f1022ed4d6e51e64b98bab390fee3646133a0e02a5724bb14203fd50006e4be86544b62a9cb64188fbbf4ccd90a32022aa7c"
            ),
            hc_ambiguous!(
                29451,
                "$veracrypt$b8a19a544414e540172595aef79e6616f504799b40a407edfb69d40534e93f0bdb3187876f0b7a21739b3a9bb02bd4752eac4d2021e65a2a9413cc389964fad4$6e2cd37f337eb3fe3c75909fe9911609d084fb8c09543f949e738fc2fcfa4825ca5f1e08678e711142553f95b19ba720fa6c8ae5d325be0b36b93c1b2683b0944d2ad4e858c1d83f21a302ef721b9a570233219b9fcf95919fef9ca353af32d7ceb0b3058986c4ed9580b8058325403d45048e43d9e94a1e8fbaa0658f82f81940ea821e1bd526829ee6478a32da4095ab9e7c04dac3b6cc08f99348467a5bf068ba54d0aededdf6005c18ee37e21ee8d980cabe470be49d332661761934f5c07126001c290002587ba4b49982fefaac41b62f7e74ce943bb40a2d78094f734d1bc2aa3dedff43ee2a7b8f3525743c76194637da9ebc2794bac14601e03aa98e9118023a184970b6b8f84f546af88b81e2fde836e286b57cbcbdd7d39334860571a5cc612b77f0c51c741854abeb320bf961aea99b88798199bf826970f2b1b8027499955f68e15328080289d8cf0569057e1ed887f956ce72b14dd13a1f61134e1195d13c68d9c298ae0183107e3a93dd13ee0730f1fabe3935ee70f4c6a1923abb3e0d0c8ecf45260c1444e7e73386acf29d3239d0160e097e6193099e10cc98f61bfda49df6b0635e73a9ccc7bdcc543306b40dd12b91023f61b21418af91"
            ),
            hc_ambiguous!(
                29452,
                "$veracrypt$1c3197f32dc5b72b4d60474a7a43afefb0d2e856a8fc4957c3fb1188b62cb0ca002f585c125bb33c5a5e85a665afae9fce15cb127c2fd9b5ee074a48fd95b3a5$8364dfd645968187d546443ba234f5cc40e78c4bdcd1e0c6d0a1208dd892442bc1dfe2a45bc4821e843bb6d9f4adf742c48c432daf0d4a51d42cafdfca281f0fab0caabde8005405840383bbfd8dbf227384891ffa501531549e0b9562c2dd77f0e6552d253acb20cbee9a75d17ec283a46006ee89cd53e3b538e054952ae6db7aac9f2f190590e697a2a8e22d080e88c32f4d27b5afe100647da2a5c80cfcb69e5a3db67cb2fcd86d89c1c53fab1bf3a287bb9002d092e75eb1fe6269a1603545dbf97b9d7fcc9485b6400f7b0abaccc31642cefd83f037e7314c6990c51af24ae894cc1c49a09d18f3ad91b3ef37ae5414fef280ec776d9c0bf84b2eb312c8cb0046bedf6f29b4aab30cdb34333f613000a39bf650341cbf33bdd47ba7bd9be8108a1254390b045d82b208d21aa45de7ca399f8e91845b9ffb47d9e6eeb506965622a2e842ec6897277388cbb6ca2a50117e228e84bebd98f9aba40f38dc3bce3b576cb08596836e50ef276ee3a76b8ce76735fd172e9bae284aa83e2677dac56e4624e66604a90e2e3ae704c64a0f27b51ce9e472891bbc212b4a6055e4482b2e6963507f9ffb477224372289fcfee5764a5f4bc7307a509e7c37c69b4857"
            ),
            hc_ambiguous!(
                29453,
                "$veracrypt$f421bdc1087b8319c12d84a680ceab0102e8e41c9ccffe76dbe0215dcfcb7b543f3e1bbedd099e88646823dae5bad8468b72436961ea8e0449a6b92b8bda7b9b$a1fe215e997ec3be2ee5eb3b4d47c41d50998df2f883404fb66270f72b5ce666e7d5ca7847c4a8b2762723da1ad088b0ad75c4fd2ccbbfa4e3adf091b6af4f44f5484ce0c89a5b0db0cbe99b3a9d43d7ff6c4ddbc9636cacfedb26b59340c6eb3e8c587db41fc01f10da2974af96531b2bee5f0b9818c3b86a3cac4ba20e08c49be84af65eb40d51626161f4eef187bf5776a89e791f3f5cbcfaa510df201fb2bf35ff03e81d0572af9abbed3cac82681925a3d1954440a6037df78f7a1e63bea81c852571a21fb550f9fe114b82bf7b94290e362cef233186f17396488c0f259c83c50ac4f8cc27d3a134ddc98f14c2fe0dd6e7d6f5eec63848314dc5984979eeb79df326f80ee0e7f671072117903cb72bbbce4f750fca3f008dadf532241e05913704df6ca03edb9641775c3b6e3e328fd078c6d70298512118312cab8316bb6ddc0b860952c621b2bb4cec1b3c7da9b1cb4c494fec382fe85aefdc56570b54845a14651535d261db519be0e860a4e20c30c86cff6f9de6e16b68d09a0e9593d271df2740950e65f1fb16e3fee034183e540e2a3b0f76156f06946b5d1bfc62fe0cab3daa14603a8d21eb03a4d266e965b010c265c9a0e093084d262a8c03"
            ),
            hc_ambiguous!(
                29461,
                "$veracrypt$c8a5f07efc320ecd797ac2c5b911b0f7ee688f859890dd3fa39b4808eb3113219e2bf1517f46a20feba286a3f3e997c80361132262bc0dacb6e9f7088bec9f56$89a0b989ad9d4cc847170422ecd3384c9ee5ccf813fa8fe8ba4d2e6a993c99032337032b83471e9e0aa2531d85481c6d66f3a0d24688e1a17b5e81b3f68736ed05279ac05bcb83bea0c813d807e8c5547f11774c93a0e9de280c1ac5b5f170c0a4b5234f7d0d35a8ec7ec69454607cd35be24428a7be1799beed0ccd6a2af49b920446ebb0cb0bebda4a86c386fcffbb61cb93894ad74819a288c6e5b2e12111011e9f149d165b91f79897f71a96bc17c2b7a5e184147a90e9289d143b597ea98797c560e91b454461d03182f1a6c0bfd2b332829f30f0f18c8253d3194aac7996d4c401a3c1de7b266962a7dd8bc0b071a357121f00bafda835584a119f8fa23306545c413856ad3b2784b8de8ce9377f180baeb0f41590eb603110ff0a82f67349711d6f1b5d707f9c655318af88530962b9127fcf3c73b4d26319a9760cd795cd5ecba203dade9e1c79af14a9e06b9b56ce0af024e6ac582bd3ced1051fb865b55b4b6eaa65789a0c31c04cc4f2fc7b458fda188907f16810f4ce6e12a264cdcb264f1c26533758b92f585a3bbc2cac84731d74e9603d1c43b321ca36b01e5724e0e5558bcba56b57c8d59ded93c12d2664350cf6a048bcfc5d62aa85c590"
            ),
            hc_ambiguous!(
                29462,
                "$veracrypt$6bb6eef1af55eb2b2849e1fc9c90c08f705010efa6443581111216b3e145201374bb8e626e4d94a4ce7ecabb11aa57610063fceed38ca9873b0e1194bd12121d$2f6b8a71994c5982049c4517ca7178a55b68cee773e06532b46d68810ede1b18783d7bca98bebf1778d14ecc18e0791190402c6a82bf3ec93e715e65997812363cc6e6bcad4f751fce16f37bbc1d6ac1d0a24c5685e85501a7c46d1cd5b04c55c605357906e5957b99230e2e9834a206e6ff48270ddf3c08c39e5c8390b2a7b7e6064719dbac29ef7513ea78c0edf420eb7ac6db684e890c5fcacfb230996f335f48f4472eaa33f3abe59943a8e3bc27ff4c24fd42015fdacd5e2eaf448049b4aa5ef1c038ca853871fc7f2573aace0874cdd1f3e01140803c1ad036b801cc1a54d619064b9b31e70e7e2601fd7b40f67814320c56721e86ddb3c62ec8cb9680ca7d2504b9decf360e32497ace8171dd9602f01db3be1541f659643e1bdc5139815acdf4debf0186707569c9b57c0fd0031ce03a5091d7937bca8f37015fa35af5f44968176164c0b9194f895a2346dacc51f5e3e7be5682ea7860c4b4302a0f22edecc7ccaebb1c824c5ca4ed4c5e674e742a1d55a7d3e732e40f0107ffad1e3876ec909fac58f1ee21ac99de2c8c29272b1df9dd7f724ff497925898506c4f6e2ae81e285239e5260b119af959338340876b5b8fdd6fede67ae37d3c750265"
            ),
            hc_ambiguous!(
                29463,
                "$veracrypt$f95b222552195378a228d932f7df38ca459b6d812899be43944ba2e9bf47967ba35da17bf69cc3f424521983989a66fd3c7865af6dd8ac2aeb82e10c92cae66f$62c89b7053d2ba18ee5adcebcf426cc7720f029f7ea5409b3b7182593afbee99f6a3828887d9da6438fafd766589c35c210de60b013d9f816f9a1c8e7e76159347611c3dba00f433aa419dcb9eaf59af6886fccd7d12ae09c2b3d7a8a6102c511e8a34b4c39df8b1938dd5fe037d7087cf2a33b5410df9a6d83d218819b32bc13999c2dd7e96eb740902699ffe5fbaa47270cf1a7e3488198495059e1520ad4ad8beec0c63827286c300555a30febfe29a359d7e364c0b52613d9cff9348152f6871b6210681ab8cfdf24b96c4793c546083197d6e5377a59d7fcab9aa679fddf550ac1ab04249d0d679e8a39ddcca26f9b8b21f7f8b71d64a0ad3d9e3ed9e2e41abd6a9b4ff4d4a7ab29c27882487909fb1118a91de8e2e2d0dea7501a63b7553fd4ff26a5f64964031c9aa3fabbc09e3f58b09ce42bbf3f05afe0f9ea18331c7ba1a887afe307fedc2be93568fe80def12e97d5e129c373814a560573ee6350f59b329352e28137aa31688c499ae1c20b25c91506c520cae56c969790204de1ba46773197fb6a72fd4742712375e89cb5ee41f3ec8b64f3322ba389c947e671b0414e981fe582898af8a5bab09e094f03cb4cab047e7547313a7d1ddba7b70"
            ),
            hc_ambiguous!(
                29471,
                "$veracrypt$444ec71554f0a2989b34bd8a5750ae7b5ed8b1ccdead29120fc030bd5186f312a7fa18ab4f4389d7798e43c073afd1e71dda2052db38dec04a700e8d6b488802$ead0cf95d6e6cecc8eaf6464baf94a64acbbd1a86f826333115b6380bda18cf936150efd6ffc2a344bb78b0b4875781a8c5079772429ef50ddf148f35895496d2e39f32ffaf68a007b070b0beaad316c4b3adf43c0c58ad24430a34abf168ed455b64958ca5465cae0684adadc00f7b9c13fc7671b4520892d23aebff49ea92bc15e804cc650dc3bbd5b8f5122051636f0c576977d4b64ba355bf6e6a8e042fc5165f2a8affa51aa12ff718cee4c543976bf565997b4b57c74e79584e317f4bdb3920f2937c4251af87f432bb8ce78dcb30675246f0303db4aaea913c93be5a26d16dbf8d4d20773aa2a4608d2151491ca6593b51965baeaf9b58f78905df522bf88976fe9436a916c8de38d5a6ca7ca7f436e7982a36335a404298304322ebe194bb34e91e8f7ee7c6541679bb0ce9d80bf4431d1c475b1a785e943e57f8e27a4e665940389b6da2771bd27d943955185379f83ca6a124ec55b2b63d4ef2e2ad6ee27de25f959708f3a64facfe07f06e29459a14f02699751d530f258d0c744a759c188de4f9423f2bd21d3d999ea28df4f3a93a2c47a7e788fe43ccbfbe267277b048002da1ef8c1e7b26690230285675a3a8fdc0f2acf46a4cb24141b3ad1"
            ),
            hc_ambiguous!(
                29472,
                "$veracrypt$0f5da0b17c60edcd392058752ec29c389b140b54cd1f94de43dccea703b1fd37936e75a500b7f9d4e94e7f214c4696c051be9697792a856ebf9c0f5a598cf8ba$5621e49c7505eba3b4738acdc860b6ed648f52e5b673ae06bb04616de438a090ab19abea11c30984ead06859de9b7aec8e436c40816f67a56cb53d5f125e58c42225315a4bf494da8128f0df924bcf6ad4b91c9efc5cb0be67cb0cd753c392388d780f57aba39197513a191cc684e9ebee41bc901dd99e9a625141cf98e55e8f74d838baea3bf8f411b85c14eff8cddd1720c2539eef7a38a72c4ed9745a05476b6a16bcda2a5391c94b6f499e3bea64ff412d03d060741e938ed3dc905d8bd6dbb2420e9277251ebe3421be389ea8b02782baeb258b9ec7e0732b3817ee6da58209871aee4e16d57a132c6215782364570238157d8a7fdcd29f54ab2295f68d027dc9f2e0c951afad7500cafe3219e6530699918ac55f4fa1141bc3596155b05bae2fdc8b0a5438edeb5bb0cfac592565b20645be90b406a1fd59846957e7539fd8423bfd4c7ae7d608aacb084ae887baa1a83b14afff8d2063565086c66e293234a8667af39642b90a38c3a5bd4fa8a787c60f73882535c9b34cb7b243465dcc32aff29cee0e741ff059c6acd8ddcbdb3cfafecdcd0f45c84dd871be4fbffd5ac2ab9e01898009adcf7d932c37d6568ad875e4d6ea15db29a1e8ba5a4e86bd"
            ),
            hc_ambiguous!(
                29473,
                "$veracrypt$18d2e8314961850f8fc26d2bc6f896db9c4eee301b5fa7295615166552b2422042c6cf6212187ec9c0234908e7934009c23ceed0c4858a7a4deecbc59b50a303$afdc7d583cde1b0c06f0bf56162ef1d6d8df8f194aadcbe395780b3d1d7127faf39910eb10f4805abdd1c3ef7a66972603124a475e2b9224699e60a9e12f4096597f20c5fb0528f590d7bd317e41dc6a2128cf5e58a99803a28c213feb8286350b1d7ab56d43bb52e511f3c860e5002472a4454a549509c8ce0c34f17ece23d5b61aa7c63389c8ca44ed10c2caae03e7ed30b3ef98565926d7e4f3a2a9abf03b278083bed7aaadd78d5bffb7cd45ffae92990c06d9e9f375a77a94226035d1f90e177c46a04dab416dfb7ed7c4ed9ee7e84580bed65c5fee9f4b1545b9a7cf6af533870d393eced609aebe308ec1eee3729da09eb7df7a8d1282b15c4a1b8266a456c06b4ea20c209c549d5d6b58a861f8e15cca3b6cef114accbf470ec76d717f6d7d416d7a32f064ab560c1167f9ef4e93310fbd927b088bffbb0cf5d5c2e271c9cad4c604e489e9983a990b23e1a2f973682fdfe38df385474f73ecdc9bce701d01d627192d3051240f4b96bbdcf2346b275e05aa75add4acb97b286cc00e830fee95d0f86a8b1e315ccb6f3f8642180392b3baac01ed2c97c200489b5e5ca4dcb0a6417e622b6196482a10e640b2b6b08e3f62acac3d45dfc6b88c666205"
            ),
            hc_ambiguous!(
                29481,
                "$veracrypt$2bfe4a72e13388a9ce074bbe0711a48d62f123df85b09e0350771edc4a0e4f397038a49b900275c9158145a96b52f95e92f927b3f963c7eadb71a07518d64323$1041c457d2794d0aa505f794153b52b24441271185d386833fbabf0e880c51b544f583d0db2ab6a926ddd3cdd0b68a61d7f5fe3f0ac6aa06ca676a868f373d35073605cf9d521ff55862b5005213a881a7b9025afc3409fa34dc86496620835df072fecd5b501f15e08113835c510d9f0bfd09d2ef1ac0e7bd01f0523d74a54fe984eb497cb960cce5bb154e024dc0c6c61a61e20a45a8f8ef319c63ca9646fbe00930302a5910891a1bc84bd936c926ca535b3b40c9e0ab255363b24a28bb8216d3d32244a725774e6ebbd73d6d3f2a2adcbc28d5341679cbb747efd56db1a09ce80b24640583ffc6f7ca5bd60d59114afcc78601184ba8feadb8d472f86c32bebf70e8158aa56f9db3b3200ef432aa7b370aa4ba408ef11b70d6806f1a21aaa3b629fa06f71dac0ae3e0ce95c7e5b550fc8c46017e151cbbcdf64b3b62b1b846a08925a217227286acfdad35b28407d589bec9578c2a4e9a4320f4a78e1e590fdf53c0a20fe0a1bb6c7d693abcd0e991c449e569477980d4b8972d21e4abc917d897e48ca427c954c3a3e0c8465ef40de51ffc9188047c043224c4a18638f1d91cd88c36623a1d880f18fd0d6ca0b3bbfa7d5d795acfb63576e2c2d83772e8"
            ),
            hc_ambiguous!(
                29482,
                "$veracrypt$af7a64c7c81f608527552532cc7049b0d369e2ce20202d7a41ffb94300cbc9c7ce2130247f49ace4c1512fc3d1b4289ca965e8eb065b35faee5b8479a4e43c4a$269f4ee7f6d20f22fe61b2570d46df07b4307f44ba6926f3b44524f0a47be2a0d677d225e2c50ff618b2e5078a19f0613a856bb3145d765cc4c1726aef27b5f03648dcf421b040e7b4fde3193ad9f8a0ae6d91c079610f826e3d556776753d8ca11320632c16a2e49a4eec6e8371681b39be2d7bb826d81dea19eb1dda2e6c71c520a2ad9128b3209a7caf10c196a16ac6f4267ffea8e7be7ddb856976438e0e997773dab75e3dfe0c047f82e4ed0b6e107261b891c4b161fa3c29017428afaaabee5c2dc727fa23b4195265716d92d06e7b828535a77521113077e6f219d7ca721eb5dab66524a530ca3ceba52e3703ec3f435ad1dfee092b090174f4acd1546107db5b403a0ba4fa90c0b4ec19af92a54ebedfd28783dcd83c78499bd33baf3ed10af229ff29634110e2970b6c04232dc95120a365947688abe011f0c8de0e651d9bd112ce0bdf80c4e37c77b962d92f1418272e7484df5217f5f2f3ba1e9b965773ed2727c5d03938516dd789236479b5ff340335c92260b1ad82a313ffa568f912fac799f93b857aaff7b4d76cb525f120a0a9efc376d39c8e27866eff689be01f5adf693ae63ad4b2a77ca96ea985ab7931457f4d8d1afaeb7e423dd752"
            ),
            hc_ambiguous!(
                29483,
                "$veracrypt$0c9d7444e9e64a833e857163787b2f6349224bdb4bbf788ce25156c870514226674725be3eebc3f2a2c2ee8adbf8bb3ec1405a333e8e091cec0c5aa77fa9b650$48ca01d954912bf3a3b1c38c00297a33ea0e014156ce08d9526150c085e5e2776a1faeb272c6e9539f466f4f93ffe6497c77d3aed54ffcdf1a3e6171cffac7b2ad96bd9e7cc553058894058def68beea05891b0ce734b6a166b8a5f24b4052fc7014b424bd6c33c9d710fb409cdf1a6c7567c1ba6a3010b03f9bda8aa2ef6733542d198a316da0c83106a6c31043f11ac191169db3db994493168ea996737355ccff84f27f6792b3dc87025d3594edb9e759ba3885980df17bc8c751ce3aba0df67aa7997906348729e81c4893cc654dc6b1da3ff7c588a327f45b8acff976d0593cc607dad48a25468d7c3ebc6dd49aa32fc526dd513852cdec4b36f3683b4998800afa25bb968c242d4c66b9b0c77b20d7bd40ffb403e9e087990d59c94ee7d36e9ebfa35a310bab963c253596e6bc89f67d5307823851c526ac789d0628a3eb81f2cdfd7d7612d8be1dade1b17f30aa2bb5d02eb8534caca0c334a269085939a5041c4ad112d325b1bfe3e9851bfdcad80bbc05ecbddc3f2ac09e2ad7182daf6ca5ccc510a100514f5d2dce1ff5046e0c8e7edf0bdc27f8fcdf4e9b3bce786c24bfa28dacee65ee8c913fc18eee5df61b8a43224f3a9c4e1b5de7b600d9e0"
            ),
            hc_ambiguous!(
                29491,
                "$veracrypt$38473cf835ddc41e67a7a73bce5dded37054e381f617e77d5bc148cd4765be050a9a0ace60d18cb84bb636e0e433052017045f2b629af411736c0f611d09c402$18fb2a90f247ffd8d4cc68f90094892b203c3b3c7131a88973b50515ff4743584f2e8f58572746d4ad92d40edffe4399a23507b497a2041f31f40bab43405c439dd31ea703bd4806e987a53c5211a13ea266a9a3a17327d93bb56f90f6f01775e021d798862f84ec35c793620ecd6fa4f25ab531b0468caae08f4692274b150f9356e2714761bf76649c982a5c6913c638ddb0d26896a69f00fb1c672dd64c157626d350863dc815cd0620561b4a748331ac9884525a3b3f04682b459b7bf522dcc4126350152d574dc5b853fe916ae757a487725a4607bacaf21a0edf4b54d37c5557412b0ec2854289690638d38b34ffa5fe3dcf709da3eca0dbb42695b42fa2e0fdfb8e53f4a666ee2e7ea07f235fa371a1651cd0579898e45213d93eb5dd6fcc52847c8c778df4299d192cc89fccc70e19bab316bc011d175c05d4ba596e829155108c3c8b0a42779189316249e4bc13b10da2a00ab5c4d47339de291a1dd0d2b0fe990af69ec3f10b11a808e351acfda53221b32fc3c698d8def54c4021b27c4f4e177f288f79e42731c6f6136e8d226ea5158f1b0077cc52309c0cd907dbe8510aa332546f83de861e67ffabf272be7c459490ee47927aafb02ec925a2"
            ),
            hc_ambiguous!(
                29492,
                "$veracrypt$302d94ef690d9c1638b2bb0d48ee19f5f43d115d625d9ac0e73aad15b586c284ed93359f358f9362b9a01813ac7bdb96cb81a4c8b474e1a14d8d05d20c2c2546$b9a3426ff9a9bb188d8c18df961a5ee4097a0e9dde1fa8e853aaf98679b93673a36d5e7133367f1622a0606bdfab033285dc9c3209c89d82d458ce711afa98e7231e2e7c2bffebd10d45ffc446de4d1f10058ea5726017ac483ef8d84af0a3e2081c95f522c27ace1b3e5fb58a421c75b00da9985e9b94b178e60f60bfa983d9f312baaa9c0b74ec8ffed7d03632624d2b278668fc60113d2a06a374479a6df24886c6eaddcd623bc8c3ed110bcba3e8400853eb6e9fa38c0d1169f70145975d7322140c7e28dc92a36e721633c12b7cd6d5bb4ff61d7b4bf268dca0ffd8f8681b248e2e46b3614f9ea940a57214de34c5b7baa8136b5b21c824c46871625d6f4208e7bc84611cb39610d247470f9e5c6c395986ef114ede9cacb1db692b467c4f402843c65da7727120dcdc7b0d9c3312143d0db7c7d707ce8b3310cd6d294215fab0c75fd2750518f636d951abe96212d2e5c7ae5e6419543441b0f9f7806c89498945d95d3a1309eeae55e870d41fb39f6753472bbae459d303b678c8f93ac5f092576c5988a5f930fe5497656f615c61d3943c8ea7867f875fb63a3ffe86884112a681a7992ffa35883747c33aa8da25b4bdc7f7b9ed9f8dcd8029a99fda"
            ),
            hc_ambiguous!(
                29493,
                "$veracrypt$04c394cd1c02605128eebb85cce6595ba631ad607646f7491103a16dceb56a71336ade3ba847b7468aa027e5db3ff2bcf2c30b31d91ebe10494d3ae9f50da11c$c17b477a485a3ec8e5940cc93819e3a0e66c0cb47561c4132cbe2d453ccfe31b77e2ae8bed494878a0a32739bc5c851e44d48674dbac10a7c8ecf2bb9149f50bcd13edac46fc67952fee16b39ae52517aa24727dca458543191c002f1ebd5c0f47f0b5c0f7087ea0e78c7c428c9b29ce1b90344b96acbe94afcba43c0cc2c0155e6ac7253b11bacea070572f82ad764029592b7f0bbdd199e66f535bc8c3cfe7a020095344b4b0028845101a14def80e860f025fde2defc34fa344345781df781c64b2be3b7b7e9ccc0e8e1127f57284f3ac8ff15e64c3aecb42aaacd528e4166ccb3ae5c90d421c96509a94ca51a2898ba50aa149e1c1990ca0abc31c6e8bf76bdc34da96e8e09cf96fd0946b660c2b5a0ce32d9c8a4903d0c377e3f857ca19ba231b671294f3daa0dd99ba02ed64306730e386cf87b6b5f9f1d1fef1617f9c6ce7abfa712d939671c028731a996bb4c990ba6d758be8935b4385e6b883c8f91e372279878bee77a69b478070bcc2ec19572f580ce404b2a683b499e3317d34515eb46d6119331df18e746fe0447bc2863e01f291d2beccc4832cdc1f7caa4540dab35cab6e096657e221b54c32846d60e4ab0110ae9f97f73b83c17c191b0e"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "diskcryptor",
        hashcat: &[
            hc_ambiguous!(
                20011,
                "$diskcryptor$0*37f6252cf81f8049f68deb41de5becfb46851909e5d4f41f8f5da4c4dc830992c5e29905fa6e0cb755e42c6cfc0509a751a2a4f01fb884968c9fd18bc9007c1ee7e67d1b7cf0e23ba82235517b93db8ebcc96943eb90d782a210e38205af60388475386996c82a1d1dc6a9581057c264577b78f261870ec9cfb3c10a989c2cc8abb97ea18dc09b54d1723ebf74a0c6f9d1b1d6a633559d885d633243eb2108fa51b13aded97671c2281126ff74aae7f6ab9efa3f8a04cef5bcf6fad9d2f1d52275bdb5c12e402baad1f42390af081bea192d2f392bccd57eedfc6fb82b66839d02f6468eb32834980580121466873d8694195628ab46195a6eb06c8d06f9ec9d6093d91d440ae35d890a6f4d92d2cda4254dace1be9bdbaf979c011b28425cfb26803b66a85ee46f5b8bfe72ba16052775bbe28e22306d708143da0c1b5f20887967d1f26bd85112213d303035e0187cd2386db8d02dd2d30171c5276b69529d0de9851812a6ab726b27eb2a539a578fd53a98b64e65be8c0b98db42e266d755f9247706aa503d70d6e9ed3d2b0c81a653ca87dda4c94687e177380738ffe50fe43a08132aa8a898b482df6dd59cd3c3738c36f4d316d648667ae65841eeda636ce16e74668b635d261912d58d96e34843a61004a1b5b8ca4c3221ff8bdde75af488d32089b62dbb5b23aec9d8b6366746b8ed71868e691faf05fd288751f79875a474bf2c2f27d543b2f411aad3432776a1201c4e0e026f081d04b907e231cf59280689708357ab9a96734e104a59f6a9b9853f2702229408f7e1de9fa09e682b3f10ca1398bdadbc4586a0ca6cd75c51bd3793039bc1017ac14722f0007032b78d931e06a80c298b90f820c14f8fe597caf3212bac02da64b5a7517a5a33d32fb4debb9f4f7880d749ede9e60bbe9bb60c5ca344aa08ec60d5b1356ee78d7935efdf72da581dff8fb88f166b75d732a60ea3d4a5899d053bc93ca2d61e6c874ea5845de27f0fc1f93689de6233157912ca1174fc4652c70a49aa0fd47a76eca905619706c0d5b8a5331dbb01b18ca782b06c07656856049ebc3df24975a18ccf666583d8534cc4da34336d5bacb878674c19772b97d95c6bbf5b2f4e23f5b3f223990cd5ad6e639cf790253c524a518cd38036856b00c76a195983783c21f30f92acbd822a20f8201216273a03436eb73b7aeda816ef7c7b767f1449700e88979ad690b52e95f9e00cb5b8dac58503cb2be74f9f1c7a0f469095275c08c4cd11e38d249b083ffb46fee84a4e3caceec00ac54bcc62bf504674a39e01b5f081e513d6c54f305c4f76ed9d8be9dd3f6c143ab81f55c7928f3fea3ea1fb0852b3cc2180d0809b1b38e403acf4d03a507b3f940260af48e1e40cb77c54f386e72d56b2637464a1c49f30460dab6109f1c0d9a50dd64eaeb0a43974095e972149c1b06be3b3420cb445d68280678c4fd42616933828d1f69e3dd5ad231b0f9424a0d4a03b2b078468d8a3e8d72cff262d55d1cbf12925e6b510dfe0afdee35bfd6563b9d72a7c6e0106921dc7913d2573439c9d3999aff7bf0fb4cb8c4269c97315ab0eff22077b5e3107c6779136a4ebc5be5d0ba3dafa2d91423ecc78541088b27cfe0782262aba458acc6a4bb73831591d663ab9081a9bda29036127cc29c29f47edb32c813ba126b85fe5458a215deb017221bd5888db5b3bf7e2096692579d38f9d615b5b0b1415deac13937d5359de70b28ed3817669a955c0852a2bf1dc602c6d37a29d576dc5d748e678d35812d8cef3faba407de7e294034d7a34bd9dc3cf4df3b32fad4b9c0ebd253673df0f1e53c17a2e6159f73bd24e3ab0acbb89e12832816e1fc87103e7bcb1bbab395810066c3bc79a5f580d9645c20977e76f01b9f2f1fcbfecdd19e21030cf91dd460ecd19befdcbee3c6ea8a55a92b5cd2f51efb650d3d585a8da91d50cb27877d7317b1a28f93d30597b5b98acbdf71d544771b5fed1bf3a2e0271c950baad47112038662107873f4b8d422cf07a14686925eff4d37c37debbc5d625e2be713095b30dbc62ab572f2c072551871ccc4175a84657dbe12c7d08077a1169fd1ef258de6bf32ea872c7d6d2401ab6fd1d8fe0fa426c84700d231bee87124a5cbd91fab435de01e7025792c2e5e78342b3d04dc9798bb00fe8e66cb3861762b1c3de99c3c7bd1f4275e13b0d37d5ace24624e0c5ae7c3151835eec2f9864cabbba2d801981587c164e63d61844452dbaaeefa7332241d1d55a25722b475bcfe0b6fd31cb505d042708cd1e11f15bb1c8f5b9b3216ebbfb65a6a80c8a5d0ea85e08e9cc858efa532740501fa075c4dfe5823fc0e478f24d2acba43a86bf832f0cf88d762eb0174bcb6c9bbdcc8168cd4a68948e4c7a4320aa12fbd8e76e228d03cd07d7e625838689d9ecbb4c049dbaafc95999979035b93799fd75cd2c1669d05500fad4f5c2c8a328ac8473aba545f469f2f1b03fe2667c1aabc26f1930cf913deb1c7154473178a6ebada4bccfc70d0ad7aa38cc112146ae7921efdda088d5cb897e084886845a4fa0871b1d6fad873a6263431f0569b133f25c30ccd85921abb1cccf364072af20eb6e08f4521e4a2c83f2707250d1b81c7397b37182bcc6cd0e918a474855c21806638ebd1af67445dc073938a9d35fd58076eff2919cd36b5c6fc0e3ae4ce60720fcbacf8093109d9241d646f87e157a31b7738970279b58488b1e4cd07792ebc8e87ba6b43870fab867cfbc55ddc1e6c4ab1a7c3a1cfc1d9a4d09f1fea3633d5f3462b8d78716111ed7aa7b505ee96fff24b4bd3918e952a7d13021325ba543ff0cdb90cb74621ec74fd9a6e6add2b1ea21115c39f083c3534cb3e946db992128984fddd4d85e8cf6c39"
            ),
            hc_ambiguous!(
                20012,
                "$diskcryptor$0*37f6252cf81f8049f68deb41de5becfb46851909e5d4f41f8f5da4c4dc830992c5e29905fa6e0cb755e42c6cfc0509a751a2a4f01fb884968c9fd18bc9007c1ee7e67d1b7cf0e23ba82235517b93db8ebcc96943eb90d782a210e38205af60388475386996c82a1d1dc6a9581057c264577b78f261870ec9cfb3c10a989c2cc8abb97ea18dc09b54d1723ebf74a0c6f9d1b1d6a633559d885d633243eb2108fa51b13aded97671c2281126ff74aae7f6ab9efa3f8a04cef5bcf6fad9d2f1d52275bdb5c12e402baad1f42390af081bea192d2f392bccd57eedfc6fb82b66839d02f6468eb32834980580121466873d8694195628ab46195a6eb06c8d06f9ec9d6093d91d440ae35d890a6f4d92d2cda4254dace1be9bdbaf979c011b28425cfb26803b66a85ee46f5b8bfe72ba16052775bbe28e22306d708143da0c1b5f20887967d1f26bd85112213d303035e0187cd2386db8d02dd2d30171c5276b69529d0de9851812a6ab726b27eb2a539a578fd53a98b64e65be8c0b98db42e266d755f9247706aa503d70d6e9ed3d2b0c81a653ca87dda4c94687e177380738ffe50fe43a08132aa8a898b482df6dd59cd3c3738c36f4d316d648667ae65841eeda636ce16e74668b635d261912d58d96e34843a61004a1b5b8ca4c3221ff8bdde75af488d32089b62dbb5b23aec9d8b6366746b8ed71868e691faf05fd288751f79875a474bf2c2f27d543b2f411aad3432776a1201c4e0e026f081d04b907e231cf59280689708357ab9a96734e104a59f6a9b9853f2702229408f7e1de9fa09e682b3f10ca1398bdadbc4586a0ca6cd75c51bd3793039bc1017ac14722f0007032b78d931e06a80c298b90f820c14f8fe597caf3212bac02da64b5a7517a5a33d32fb4debb9f4f7880d749ede9e60bbe9bb60c5ca344aa08ec60d5b1356ee78d7935efdf72da581dff8fb88f166b75d732a60ea3d4a5899d053bc93ca2d61e6c874ea5845de27f0fc1f93689de6233157912ca1174fc4652c70a49aa0fd47a76eca905619706c0d5b8a5331dbb01b18ca782b06c07656856049ebc3df24975a18ccf666583d8534cc4da34336d5bacb878674c19772b97d95c6bbf5b2f4e23f5b3f223990cd5ad6e639cf790253c524a518cd38036856b00c76a195983783c21f30f92acbd822a20f8201216273a03436eb73b7aeda816ef7c7b767f1449700e88979ad690b52e95f9e00cb5b8dac58503cb2be74f9f1c7a0f469095275c08c4cd11e38d249b083ffb46fee84a4e3caceec00ac54bcc62bf504674a39e01b5f081e513d6c54f305c4f76ed9d8be9dd3f6c143ab81f55c7928f3fea3ea1fb0852b3cc2180d0809b1b38e403acf4d03a507b3f940260af48e1e40cb77c54f386e72d56b2637464a1c49f30460dab6109f1c0d9a50dd64eaeb0a43974095e972149c1b06be3b3420cb445d68280678c4fd42616933828d1f69e3dd5ad231b0f9424a0d4a03b2b078468d8a3e8d72cff262d55d1cbf12925e6b510dfe0afdee35bfd6563b9d72a7c6e0106921dc7913d2573439c9d3999aff7bf0fb4cb8c4269c97315ab0eff22077b5e3107c6779136a4ebc5be5d0ba3dafa2d91423ecc78541088b27cfe0782262aba458acc6a4bb73831591d663ab9081a9bda29036127cc29c29f47edb32c813ba126b85fe5458a215deb017221bd5888db5b3bf7e2096692579d38f9d615b5b0b1415deac13937d5359de70b28ed3817669a955c0852a2bf1dc602c6d37a29d576dc5d748e678d35812d8cef3faba407de7e294034d7a34bd9dc3cf4df3b32fad4b9c0ebd253673df0f1e53c17a2e6159f73bd24e3ab0acbb89e12832816e1fc87103e7bcb1bbab395810066c3bc79a5f580d9645c20977e76f01b9f2f1fcbfecdd19e21030cf91dd460ecd19befdcbee3c6ea8a55a92b5cd2f51efb650d3d585a8da91d50cb27877d7317b1a28f93d30597b5b98acbdf71d544771b5fed1bf3a2e0271c950baad47112038662107873f4b8d422cf07a14686925eff4d37c37debbc5d625e2be713095b30dbc62ab572f2c072551871ccc4175a84657dbe12c7d08077a1169fd1ef258de6bf32ea872c7d6d2401ab6fd1d8fe0fa426c84700d231bee87124a5cbd91fab435de01e7025792c2e5e78342b3d04dc9798bb00fe8e66cb3861762b1c3de99c3c7bd1f4275e13b0d37d5ace24624e0c5ae7c3151835eec2f9864cabbba2d801981587c164e63d61844452dbaaeefa7332241d1d55a25722b475bcfe0b6fd31cb505d042708cd1e11f15bb1c8f5b9b3216ebbfb65a6a80c8a5d0ea85e08e9cc858efa532740501fa075c4dfe5823fc0e478f24d2acba43a86bf832f0cf88d762eb0174bcb6c9bbdcc8168cd4a68948e4c7a4320aa12fbd8e76e228d03cd07d7e625838689d9ecbb4c049dbaafc95999979035b93799fd75cd2c1669d05500fad4f5c2c8a328ac8473aba545f469f2f1b03fe2667c1aabc26f1930cf913deb1c7154473178a6ebada4bccfc70d0ad7aa38cc112146ae7921efdda088d5cb897e084886845a4fa0871b1d6fad873a6263431f0569b133f25c30ccd85921abb1cccf364072af20eb6e08f4521e4a2c83f2707250d1b81c7397b37182bcc6cd0e918a474855c21806638ebd1af67445dc073938a9d35fd58076eff2919cd36b5c6fc0e3ae4ce60720fcbacf8093109d9241d646f87e157a31b7738970279b58488b1e4cd07792ebc8e87ba6b43870fab867cfbc55ddc1e6c4ab1a7c3a1cfc1d9a4d09f1fea3633d5f3462b8d78716111ed7aa7b505ee96fff24b4bd3918e952a7d13021325ba543ff0cdb90cb74621ec74fd9a6e6add2b1ea21115c39f083c3534cb3e946db992128984fddd4d85e8cf6c39"
            ),
            hc_ambiguous!(
                20013,
                "$diskcryptor$0*37f6252cf81f8049f68deb41de5becfb46851909e5d4f41f8f5da4c4dc830992c5e29905fa6e0cb755e42c6cfc0509a751a2a4f01fb884968c9fd18bc9007c1ee7e67d1b7cf0e23ba82235517b93db8ebcc96943eb90d782a210e38205af60388475386996c82a1d1dc6a9581057c264577b78f261870ec9cfb3c10a989c2cc8abb97ea18dc09b54d1723ebf74a0c6f9d1b1d6a633559d885d633243eb2108fa51b13aded97671c2281126ff74aae7f6ab9efa3f8a04cef5bcf6fad9d2f1d52275bdb5c12e402baad1f42390af081bea192d2f392bccd57eedfc6fb82b66839d02f6468eb32834980580121466873d8694195628ab46195a6eb06c8d06f9ec9d6093d91d440ae35d890a6f4d92d2cda4254dace1be9bdbaf979c011b28425cfb26803b66a85ee46f5b8bfe72ba16052775bbe28e22306d708143da0c1b5f20887967d1f26bd85112213d303035e0187cd2386db8d02dd2d30171c5276b69529d0de9851812a6ab726b27eb2a539a578fd53a98b64e65be8c0b98db42e266d755f9247706aa503d70d6e9ed3d2b0c81a653ca87dda4c94687e177380738ffe50fe43a08132aa8a898b482df6dd59cd3c3738c36f4d316d648667ae65841eeda636ce16e74668b635d261912d58d96e34843a61004a1b5b8ca4c3221ff8bdde75af488d32089b62dbb5b23aec9d8b6366746b8ed71868e691faf05fd288751f79875a474bf2c2f27d543b2f411aad3432776a1201c4e0e026f081d04b907e231cf59280689708357ab9a96734e104a59f6a9b9853f2702229408f7e1de9fa09e682b3f10ca1398bdadbc4586a0ca6cd75c51bd3793039bc1017ac14722f0007032b78d931e06a80c298b90f820c14f8fe597caf3212bac02da64b5a7517a5a33d32fb4debb9f4f7880d749ede9e60bbe9bb60c5ca344aa08ec60d5b1356ee78d7935efdf72da581dff8fb88f166b75d732a60ea3d4a5899d053bc93ca2d61e6c874ea5845de27f0fc1f93689de6233157912ca1174fc4652c70a49aa0fd47a76eca905619706c0d5b8a5331dbb01b18ca782b06c07656856049ebc3df24975a18ccf666583d8534cc4da34336d5bacb878674c19772b97d95c6bbf5b2f4e23f5b3f223990cd5ad6e639cf790253c524a518cd38036856b00c76a195983783c21f30f92acbd822a20f8201216273a03436eb73b7aeda816ef7c7b767f1449700e88979ad690b52e95f9e00cb5b8dac58503cb2be74f9f1c7a0f469095275c08c4cd11e38d249b083ffb46fee84a4e3caceec00ac54bcc62bf504674a39e01b5f081e513d6c54f305c4f76ed9d8be9dd3f6c143ab81f55c7928f3fea3ea1fb0852b3cc2180d0809b1b38e403acf4d03a507b3f940260af48e1e40cb77c54f386e72d56b2637464a1c49f30460dab6109f1c0d9a50dd64eaeb0a43974095e972149c1b06be3b3420cb445d68280678c4fd42616933828d1f69e3dd5ad231b0f9424a0d4a03b2b078468d8a3e8d72cff262d55d1cbf12925e6b510dfe0afdee35bfd6563b9d72a7c6e0106921dc7913d2573439c9d3999aff7bf0fb4cb8c4269c97315ab0eff22077b5e3107c6779136a4ebc5be5d0ba3dafa2d91423ecc78541088b27cfe0782262aba458acc6a4bb73831591d663ab9081a9bda29036127cc29c29f47edb32c813ba126b85fe5458a215deb017221bd5888db5b3bf7e2096692579d38f9d615b5b0b1415deac13937d5359de70b28ed3817669a955c0852a2bf1dc602c6d37a29d576dc5d748e678d35812d8cef3faba407de7e294034d7a34bd9dc3cf4df3b32fad4b9c0ebd253673df0f1e53c17a2e6159f73bd24e3ab0acbb89e12832816e1fc87103e7bcb1bbab395810066c3bc79a5f580d9645c20977e76f01b9f2f1fcbfecdd19e21030cf91dd460ecd19befdcbee3c6ea8a55a92b5cd2f51efb650d3d585a8da91d50cb27877d7317b1a28f93d30597b5b98acbdf71d544771b5fed1bf3a2e0271c950baad47112038662107873f4b8d422cf07a14686925eff4d37c37debbc5d625e2be713095b30dbc62ab572f2c072551871ccc4175a84657dbe12c7d08077a1169fd1ef258de6bf32ea872c7d6d2401ab6fd1d8fe0fa426c84700d231bee87124a5cbd91fab435de01e7025792c2e5e78342b3d04dc9798bb00fe8e66cb3861762b1c3de99c3c7bd1f4275e13b0d37d5ace24624e0c5ae7c3151835eec2f9864cabbba2d801981587c164e63d61844452dbaaeefa7332241d1d55a25722b475bcfe0b6fd31cb505d042708cd1e11f15bb1c8f5b9b3216ebbfb65a6a80c8a5d0ea85e08e9cc858efa532740501fa075c4dfe5823fc0e478f24d2acba43a86bf832f0cf88d762eb0174bcb6c9bbdcc8168cd4a68948e4c7a4320aa12fbd8e76e228d03cd07d7e625838689d9ecbb4c049dbaafc95999979035b93799fd75cd2c1669d05500fad4f5c2c8a328ac8473aba545f469f2f1b03fe2667c1aabc26f1930cf913deb1c7154473178a6ebada4bccfc70d0ad7aa38cc112146ae7921efdda088d5cb897e084886845a4fa0871b1d6fad873a6263431f0569b133f25c30ccd85921abb1cccf364072af20eb6e08f4521e4a2c83f2707250d1b81c7397b37182bcc6cd0e918a474855c21806638ebd1af67445dc073938a9d35fd58076eff2919cd36b5c6fc0e3ae4ce60720fcbacf8093109d9241d646f87e157a31b7738970279b58488b1e4cd07792ebc8e87ba6b43870fab867cfbc55ddc1e6c4ab1a7c3a1cfc1d9a4d09f1fea3633d5f3462b8d78716111ed7aa7b505ee96fff24b4bd3918e952a7d13021325ba543ff0cdb90cb74621ec74fd9a6e6add2b1ea21115c39f083c3534cb3e946db992128984fddd4d85e8cf6c39"
            ),
        ],
        john: &[
            john_fixture!(
                "diskcryptor-aes-opencl",
                "tests/fixtures/john/diskcryptor-aes-opencl.txt"
            ),
            john!(
                "diskcryptor",
                "$diskcryptor$0*e710cb6585ba412d9b4ce8587b8faa311d9a7d8f3dea46232b83b98ac6fd17d6026173cf1096355bf33768b5a9856486af0e9300f92dee6067228662f53598d250a789cb449617f44c05411b4fdb018ba3d11cdc328efd06c3123b1fa8dc52273480d905e4fd7023a8cbe807a52245c877f963feb5b80363680d94cdfb2d8e1cd019e16734890f856441ca1f38a7809699c871454a487f6262a9b732db35c76e902f732a9505597b3df8e00653cf77662072341420e6482d28d12db5e97c9e5b66a7bce4d2c6b1ffe5105e9461deb9fdda805a502dd78fcc5044514e8f4a1552753082d9294abc4cd4873d365d317e4a720cdaef3182d9fa963e50a888e9451824108f6ae837f2cdd25223426a817c23d913205b7e373ee8403b87c830ec95f5dd501662ae9b6228cd692fa4632a5a25ccec970359e18cf85b93f64de226d20aa7ed19f99f665c9ab5a19412669653e6e0db855fef9f0623b68680567373d20ce64031c95b6f9b897fc8905ee1571f0b18aab078048d39502e8644515f8e4dfdaba368b7c1ca0403e7827292b7319a0dfcc1b8f090cc782474f68e117b573259466860577c6459e5cccdf8e5e49ab38b87c29e87cb3d113896ed13ba0ad4d8e51d39d3bde3ef3f78d8e85b86ae52b16c27f9701f7bebb01c49e067452b711d6311550b6927014ef56ed5fa29ff6ada6586942997c1384dc3c5331418bcd676d7ddea7ee1c27aabcf49e9c56fb74ad42b6f43f1193e59c9b807e27c562251a483fcf480653b21d2769f48d15f31b1432c0079c78fedbbf98e4d43c43c1a6ce6cb85ff2776c227cd4291e8cf8e05bb1d9a6e0164913cd0336ed01dc5ffab1463f18cdb82723dfd6d038987d6067f3d341fb5ea087ecde8ddd4dd74b52a617a26658f07ca778b161ef25c45bacc60125ac9fd2117345126faf83937173d196e9b0edbb6fe573958bd3a31ea9ea4593c1b21822835f6c65be0cae0157ff59bb316bd39c6d276d9cc4e77a4ad1f6f8280307b1a3a7cbfef7243aab6aa437da633047dbb4e0dd7eae299290b4d45f8928cd359e2547ccf773884a590e14feed71062bda2b241ec67de77ef7a96d5f01a0d132086f6f0915bfda1f7907787f3fea20865f7f1a9557d5a4572c8e21003e993262e7c328700aba0b0f9335a030bb2c5fdd89f01130030d791a6be95e5c19e3b0a20fe80588c5463ad8f7915af340e2ba3917cfbb716a9557f3a24702cec53e23448d97e25e6aca074e16ac2f293a2a2631da23458fb19d09f1dc1a233642687469caaf2c64694ec03e8c2b16a4f80103a82454504ba6c1b95b82ce904c8400c0faaac69eff773c20988d5a57cb08420680a9ab38cd5ef4749c54cb95917a79076d032504f2f70ad2ed75e9f3d07fa8a50303eb2a27e3581e3129e577317868f203847bb8ed05d0d57bb9e1126ffb582f7f3a454b23d7a0bd18d840470360ebfd3fa0128c4853843e514e066c4173ea58a5fd84d3ebc574efb7a6e60cd8cfeba513ce9e5877c00095eefa9312a605cf21a43550cdfe94bbeaa1b83fa6a0cbebd7cbd25916ba2a8acec1d66578127ab0c045cad0ebef6e8eaa2f88b117d7d2d0abdd3b323ae03e9b9c7d29c5aa4056bcb27c51cea69640a45db8d483b04ba4f8bc426370f656251c8584dd3efdfad048087eb20010a0e29c3bbcdebee8ea77477e5fa2031215342a03c113e3138b53b3e3743bbd922c89433a98e94712208f801e93a263e55310c08e8722e28e7d49dabd4b3cb24c0d742371606f9db44ecfbdc7587fd4918a0bbed2af951b727b49b8f146459ba2d8dfcb9ca050f455a5f140b8810704c5e8a94f979ab818b3ff8bdc8bd32e143f28d0db91c00c3c0a0e35c647aeab2669bd272d28e6ffc4ca1ebec628c04e0dbeca5fd44aa5330318099043b232f3b9089fff382c94ffabcc2d6896370b4b149068e0a8a93deb09d003942c121fa9ec4856cb8e9d999a47a49ab5a1af3b18570cea699a0568748bf7ca03399318338b57682f97044b3a5a8eb9a56aaf11b7165ae2a797a5db08ae55bfe0b142eb8a54bdb77a47bff3dadd72b012cca7707dd20eda5ea3e426e7c8bf8b8bed57062ca53d2c962bc96e54d971ac5e68f68726ffbabf35ec32c417748d018644029decea8c6b511573ebfa325c331ab21aef16f8968ec2262dad36e49ce6a8ff3ce672a0674ed29054567775249812c4fb15e53916209d37e7ebd90e213203344095699ad5cf06d63887aad8623b107b135610663ae85c54f69b6491128338efae3f60ebc9d1c26b32dc6b0bee7ee3cb9e7a8de26c82b3bf056e83119ca88beb2f5a835092e98d87a4d6eeddc3957ffaf7671b20227a7b6923464a68c4bf94a885c8a9bd29b04a141e049e5b60db40a89d0eb4cc08c0b38974d1012d6fb75be58c5c849f35bb38cc887d7fb8615bb28a84197f695f89fbf9adacdbf49c1a205af8ae312021f217f2af644d203189665622b98c9338663a5d524de4864ff12318e544fe06b851cc723503613217972882300c43032a0d00d9ff11e941ee1def5425e78dd312676cd0bfb36a6848f92cc936e2ea19f4002f8c98a3c37e23389c0c428d97d2152cf5050b2f8422b4730c9047b57bb6e911a3e05486e099148a9e84cef9ed1c6643e949643dd6a122e9b6bf058aab88bf1993f70ffd5306dac7e0066363fb57068fb4cfaabea157071b105f4dd5484968def1ec4139cf66c5bbbc5fcdbd29fa0308eabcc84b61c01e26234115714596ad7ad67676c7a6c6acc4549619f74d828a1f1181826733cd9283e0bb2f0a010cd1765d3cb68825b7d210e486339d0deeee5d7893eb8e04761c3ed0261959717f26ac3802215b9f32e24d574764e10fdc5d19508ac309e1912600709735c1a"
            ),
        ],
    },
    Vector {
        slug: "bitwarden",
        hashcat: &[hc!(
            23400,
            "$bitwarden$2*100000*2*bm9yZXBseUBoYXNoY2F0Lm5ldA==*+v5rHxYydSRUDlan+4pSoiYQwAgEhdmivlb+exQX+fg="
        )],
        john: &[],
    },
    Vector {
        slug: "mongodb-scram",
        hashcat: &[hc!(
            24100,
            "$mongodb-scram$*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw="
        )],
        john: &[],
    },
    Vector {
        slug: "stellar",
        hashcat: &[hc!(
            25500,
            "$stellar$YAlIJziURRcBEWUwRSRDWA==$EutMmmcV5Hbf3p1I$rfSAF349RvGKG4R4Z2VCrH9WjNEKjbJa9hpOja9Yn8MwXruuFEMtw47HPn9CYj+JJ5Rb4Z87Wejj1c4fqpbMZHFOnqtQsVAr"
        )],
        john: &[],
    },
    Vector {
        slug: "exodus",
        hashcat: &[hc!(
            28200,
            "EXODUS:16384:8:1:IYkXZgFETRmFp4wQXyP8XMe3LtuOw8wMdLcBVQ+9YWE=:lq0W9ekN5sC0O7Xw:UD4a6mUUhkTbQtGWitXHZUg0pQ4RHI6W/KUyYE95m3k=:ZuNQckXOtr4r21x+DT1zpQ=="
        )],
        john: &[],
    },
    Vector {
        slug: "axcrypt2",
        hashcat: &[
            hc!(
                23500,
                "$axcrypt$*2*10000*6d44c6d19076bce9920c5fb76b246c161926ce65abb93ec2003919d78898aadd5bc6e5754201ff25d681ad89fa2861d20ef7c3fd7bde051909dfef8adcb50491*68f78a1b80291a42b2a117d6209d3eb3541a8d47ed6b970b2b8294b2bc78347fc2b494a0599f8cba6d45e88fd8fbc5b4dd7e888f6c9543e679489de132167222e130d5925278693ad8599284705fdf99360b2199ed0005be05867b9b7aa6bb4be76f5f979819eb27cf590a47d81830575b2af09dda756360c844b89c7dcec099cfdd27d2d0c95d24f143405f303e4843*1000*debdeb8ea7b9800b01855de09b105fdb8840efc1f67dc742283d13a5570165f8"
            ),
            hc!(
                23600,
                "$axcrypt$*2*10000*79bea2d51670484a065241c52613b41a33bf56d2dda9993770e8b0188e3bbf881bea6552a2986c70dc97240b0f91df2eecfa2c7044998041b3fbd58369cfef79*4982f7a860d4e92079bc677c1f89304aa3a2d9ab8c81efaff6c78a12e2873a3a23e6ae6e23a7144248446d8b44e3e82b19a307b2105570a39e1a7bed70b77bbf6b3e85371fe5bb52d1d4c7fcb3d755b308796ab7c4ff270c9217f05477aff5e8e94e5e8af1fba3ce069ce6fc94ae7aeebcb3da270cab672e95c8042a848cefc70bde7201b52cba9a8a0615ac70315792*1000*e2438859e86f7b4076b0ee4044ad5d17c3bb1f5a05fcb1af28ed7326cf71ced2"
            ),
        ],
        john: &[john_fixture!(
            "axcrypt2-opencl",
            "tests/fixtures/john/axcrypt2-opencl.txt"
        )],
    },
    Vector {
        slug: "apple-keychain",
        hashcat: &[hc!(
            23100,
            "$keychain$*74cd1efd49e54a8fdc8750288801e09fa26a33b1*66001ad4e0498dc7*5a084b7314971b728cb551ac40b2e50b7b5bd8b8496b902efe7af07538863a45394ead8399ec581681f7416003c49cc7"
        )],
        john: &[john!(
            "keychain",
            "$keychain$*10f7445c8510fa40d9ef6b4e0f8c772a9d37e449*f3d19b2a45cdcccb*8c3c3b1c7d48a24dad4ccbd4fd794ca9b0b3f1386a0a4527f3548bfe6e2f1001804b082076641bbedbc9f3a7c33c084b"
        )],
    },
    Vector {
        slug: "stuffit5",
        hashcat: &[hc!(24700, "66a75cb059")],
        john: &[],
    },
    Vector {
        slug: "terra",
        hashcat: &[hc!(
            29600,
            "67445496c838e96c1424a8dae4b146f0fc247c8c34ef33feffeb1e4412018512wZGtBMeN84XZE2LoOKwTGvA4Ee4m7PR1lDGIdWUV6OSUZKRiKFx9tlrnZLt8r8OfOzbwUS2a2Uo+nrrP6F85fh4eHstwPJw0KwzHWB8br58="
        )],
        john: &[],
    },
    Vector {
        slug: "jks-private-key",
        hashcat: &[hc!(
            15500,
            "$jksprivk$*338BD2FBEBA7B3EF198A4CBFC6E18AFF1E229367*5225850113575146134463704406336350011656*D5253EB151EB92DC73E542D8C0A4D7A848A5B0C0E370E625E6547D4E6F23416FC85A27BC295731B8021CDFBD003551C66C434FFBC87DACAD1FDF39022320034A2F86E779F2B1B3325428A666518FA89507AD63E15FD9C57B9E36EF5B642A2F448A9A3F09B79AD93D65F46B8692CD07539FD140146F8F219DC262971AF019E18EDC16C3C240569E1673F4D98BC818CCF28298D5A7BFF038A663DD10FE5E48643C3217C237D342164E2D41EF15075431FBD5B34800E5AE7EB80FAA5AE9982A55F35379AA7B31217E7F1C5F1964A15024A305AE4B3981FE1C80C163BC38ECA5581F11867E5C34C5D124D0367B3737E5E5BB14D2CAB26A698C8DAAB755C82BA6B823BCAECDD4A89C831651ACE5A6029FD0D3515C5D1D53AD8B9062CE8C445373862035CBBF60D490CA2E4975EE6E0358EC32E871FAB15347E3032E21F30F543BAAB01D779BA833CA0B8C7591B42C7C59A8FDD46D7DECEC0E91ADBF331177605E7830ABED62FAD7D5D806D8EFD01C38765940B7F97168FC72C39BF4C98F944FFC310CA8F4EB1D0F960F352CC5E2BB23A1EB221072A5471EDA2CE81C04595B8D37088CFB5C14F6A4A881AD12125DEFBB8154EB4C130AB7FD9933FD36DF1A6A26B51AB169866788678FCED988C8E017CA84354F487A5508210181AFB8B3AD0753E3E28BE674DFBD4E4FBDFD1E30D592F4EA3A77A2F0F5CF9A175DBC590EF5D42971A39918F12B92DCD8BFD56BE9A3459856B5587603C7B53062663A4C8894BBC9894FB1663BF30F32D907664328138B7A50EAC7F8E3183D74562A5C90FE1889AC4C5FE43EBEB8974563B6682F92591ECA4FA0DA72236C3851DA102DB6BA0CC07BFD32F7E962AB0EDCF4A8DEA6525174F5BB5C021E2A9A3F7F761E9CA90B6E27FB7E55CD91DA184FAC5E534E8AD25314C56CE5796506A0CA70881782F9C5147D87705065D68BD67D2B0344205BA6445D562273690004CA5A303274FB283A75F49BA968D7947943AA98F2AF9CB8253B425B86225E7395A331AC4CB1B1700C64D4F458D5D642C54148AE6DA41D9E26657D331B157D76042C2CF3057B83997C23D8BF68FB3C7337CAFB8B324AD0DF7A80B554B4D7F9AD6ED527E7932F1741A573C152A41610F6517E3F4A3BC6B66685871A7CE3795C559BD47CDB8E34CB2C1DFE980518D79E2078C258C54F312EB38609F640E7DC013E0F2A16A25BB5971882B4308D27930CA99FEC231AE927B62215A1B56098C362B7F20593953B29428681875070E84BF5B60BEA3948127151634123DA77C814AAD54CE10905763C8C19BC191C0C40458C809402E1957C4C05C4EAE27576B2D30593F7FDCC9A248DB5DB23CF2FA22A92C016090F611690BF0AB5B8B2866ED25F345EFE85DF3311C9E91C37CEE709CF16E7CB09D01BECD2961D094C02D42EC85BF47FAB1B67A13B9A1741C15F7156D57A71BFFABB03B71E69707913A5C136B3D69CE3F71ABFE376F0A21D723FFA2E60AC180689D3E8AF4348C9F555CD897387327FC8BA2B9C51A7298547E556A11A60441EF5331A1BFB847A3D23DD9F7C50E636A2C6309BC82E1A8852F5A8569B6D93*14*78D6A2424484CF5149932B7EA8BF*test"
        )],
        john: &[],
    },
    Vector {
        slug: "ethereum-presale",
        hashcat: &[hc!(
            16300,
            "$ethereum$w*e94a8e49deac2d62206bf9bfb7d2aaea7eb06c1a378cfc1ac056cc599a569793c0ecc40e6a0c242dee2812f06b644d70f43331b1fa2ce4bd6cbb9f62dd25b443235bdb4c1ffb222084c9ded8c719624b338f17e0fd827b34d79801298ac75f74ed97ae16f72fccecf862d09a03498b1b8bd1d984fc43dd507ede5d4b6223a582352386407266b66c671077eefc1e07b5f42508bf926ab5616658c984968d8eec25c9d5197a4a30eed54c161595c3b4d558b17ab8a75ccca72b3d949919d197158ea5cfbc43ac7dd73cf77807dc2c8fe4ef1e942ccd11ec24fe8a410d48ef4b8a35c93ecf1a21c51a51a08f3225fbdcc338b1e7fdafd7d94b82a81d88c2e9a429acc3f8a5974eafb7af8c912597eb6fdcd80578bd12efddd99de47b44e7c8f6c38f2af3116b08796172eda89422e9ea9b99c7f98a7e331aeb4bb1b06f611e95082b629332c31dbcfd878aed77d300c9ed5c74af9cd6f5a8c4a261dd124317fb790a04481d93aec160af4ad8ec84c04d943a869f65f07f5ccf8295dc1c876f30408eac77f62192cbb25842470b4a5bdb4c8096f56da7e9ed05c21f61b94c54ef1c2e9e417cce627521a40a99e357dd9b7a7149041d589cbacbe0302db57ddc983b9a6d79ce3f2e9ae8ad45fa40b934ed6b36379b780549ae7553dbb1cab238138c05743d0103335325bd90e27d8ae1ea219eb8905503c5ad54fa12d22e9a7d296eee07c8a7b5041b8d56b8af290274d01eb0e4ad174eb26b23b5e9fb46ff7f88398e6266052292acb36554ccb9c2c03139fe72d3f5d30bd5d10bd79d7cb48d2ab24187d8efc3750d5a24980fb12122591455d14e75421a2074599f1cc9fdfc8f498c92ad8b904d3c4307f80c46921d8128*f3abede76ac15228f1b161dd9660bb9094e81b1b*d201ccd492c284484c7824c4d37b1593"
        )],
        john: &[john_fixture!(
            "ethereum-presale-opencl",
            "tests/fixtures/john/ethereum-presale-opencl.txt"
        )],
    },
    Vector {
        slug: "multibit-wallet",
        hashcat: &[hc!(
            27700,
            "$multibit$3*16384*8*1*7523cb5482e81b81*91780fd49b81a782ab840157a69ba7996d81270eaf456c850f314fc1787d9b0b"
        )],
        john: &[],
    },
    Vector {
        slug: "pem-private-key",
        hashcat: &[
            hc!(
                24410,
                "$PEM$1$4$f5662bd8383b4b40$2048$2993b585d3fb2e7b235ed13d90f637e2$1232$73984f2cba4d5e1d327a3f5a538a946099976ab865349091a452a838dc6855b6e539f920a078b14d949d8c739ea7ce26769dc0ba1619a9c0ee1864d1cfca9e61ddf6d9582439f2b65d00a3ff57c78d3176e9e88fc12da7acd421b624ba76f3d5f12926a3a9acd82f502d7638cfe2063fb2c773a56299ae1ec2c85641d33f5f8b3edfc6687fa9898325d384b3db7a7686704facb880c3898f69dd353a5d5d136b58a1e00e4711d3a01e0c632a5f3d5eff64c9e88166296b9b26f072a52bdc4893377e247b5cdb052f34e0b5d4de10a5dffe443a03b1a23f1edbcb00361334dbd6a6d31e16887b5290da2f865fbe1fef7b43c8f8f3432815ca860946560cb601ab83d417e6a4734aaf75692195566bde61e04610a9eff752c08f9ff85a48959daa7c65d03a0eca62e92bf10a55fb4834a49745a6c53d9c79d0591cb13cfa54f0d437d001b7924fd9dd69c98aa25e5d3f19649f79913bca827e7636ede04bf7c41ef54c42936b4eb93c75d941853dc7dda42b51ac5e4f5602fe2c3e62f252d28e02398943780598cf2bd41d183425daf34e86099c748eda2d5372029ebd089f619dab327ea728eb90342f2b48cd364e914a6078599afdb22a6fac6b55e1bf28b3284a0edc748b59c2eaa97e35d457d4c049f86fd3fc618c4c52f08776c0efb33011b96ef6f0b0e6ecf6d37dc20da8ab7d9b8154371c8e396d9b89ee02e6e6b013a0985b1f47c91f3b5a9e6c33736840e6044f46be1dbea4ec7730eccc6e993cb522bb220de4ed55156129f821d7df19439ab86990991cfd1992681716b5ff012ffa5519ad0baa01885f77f6a522469979f449232d408379558fcdfe5253371da835e0c77706dfa67ff28b1cd8d7fdf9e386899838532d8e57ec1ed3d31a96ae03f37b976fb6c503cc247113deaa070697728e3b36ce43de051ce13a4df91d22157c6281e8f9a16de007c6dddf03ffc79a9f4cfc3eaddd637a9a902fdba1c9e857a9ccd7c318db17cd40d8b588b5d97c7d03c0404473dd201aa5c6637e952c6299e35374127276b3eb4aeba754f3176fecea1731a0f917dd049fcdab34264a8c635ba90eec941aeb449a7eca263aaec9e46758bdf21caa896adb4652e9564d75c20e296fcdf28cbdeb702a1e7acf2374d24b51e6492b0bcc72a58748666a7278e2cb54fbdb68c6736ceb85dd92cd0465b19a65f7ad47e25658a34c3531db48c37ef279574e1892d80d80f3e9dee385ab65e6a4537f6e318817a785228160939d01632b8269858ce9092359048b09ae8b9c17ceb575216988bbeb91c1b5861c931f21e07d888ceb9b89d89d17608e2d5f0ae66b6e756f1eac9f80e13749f866ea6b741158296d3ced761999ad901a2121e233bf173865b6c0b32d68e6ef1d39bb411a1ee9d4d1cde870645b9922051b31cc0df640fb01d23c613091ba538999254b873fbb5996efdfbde5c933e1b6ef6d1c7d5e1a9bff6800c8625b07aba2c14143c1a33a0661c357e5db59a2f49aab35c13531774fb5b3795ed853d7f4e38910c7eeb3435353e2cfd0c94e61c16c8126928343f86222c5ef320b9e043d3cd357af4e065500f50e6bf9c260ca298bd5507c9498dbcea4ceec834449b7fb7249fdf199f66aa98d0a820b1057df1d67c43f49c6d18c3c902466b2b2b528075489261ef73bf711c7988fed65693798568bed43e4d70a800cd25b1773c455aaa153cea8f7013eae1e8f24c6793f590c8f6a112b46"
            ),
            hc!(
                24420,
                "$PEM$2$4$ed02960b8a10b1f1$2048$a634c482a95f23bd8fada558e1bac2cf$1232$50b21db4aededb96417a9b88131e6bc3727739b4aa1413417338efaa6a756f27c32db5c339d9c3ba61c746bbe3d6c5e0a023f965e70fb617e78a00890b8c7fc7c9f5e0ab39f35bf58ab40f6ed15441338134d041ca59783437ef681a51132c085abb3830df95e9f94d11da54d61679ca6e40136da96ffe205ce191002458143f03cba3aeca6b22a3f0689d5582b3e6c01baee7a04d875ed44bb84fa0ed0a3aae1ed392645cced385498eef4ec25bf6d1399f1487f3625fad9fee25aabf18edb1ce5e640e834d31251b882601f23c2b2d77a45c84e0fc8a3a42e3ff9f75e7ac815c57a7e943ad803ab3672f85a37c6b92d0813590d47a31788643449dce67f135363a0c14f089629a1274b124539535df5f50df5d4402f7a109738f56467725a8aa3884562c8b4c42c068c3502be86e20ac9c52c0daec22e47dcbefebe902b1dc791ed3cd069c7f9211e43f5a3274450f4b0f0b7c6f59adeca8b39ed130b6cbda7cf98e15bbba21fa1758a28dc2edf2e2f17fc353853dc881458e59184f5a8f6e09456e4d71d90135a8ce67350f7bcb3d900e75585e3a87c0c8482f3917347fcfad4fdb8915991cffd20dae1502d0f69d385244e489e50cc9f24b15a5f9d0b00d62805026db5378b5408d7d719786eb043659a452096736e4a7501548655df83045dc4e86bd3319f2982e6db2bbb239019202cebf2ca68c05b578ba95cef82397b145c80208cd7ffd9b0cd5fc3d0d7ea26401c8e11c28ab8d1a524b884962e7fee597943a5e38137abb8b26a7772f0ad6dad074dcfd0b5794822aa7e43d10cab2c95e63b6459706dc21a1cbbd7ae4c96b40ee4d7039cf84c416cb879b2d30b7ac5e1860dcd2ab5479c39b748f5fd9336934c9c1e8064ffb0906c0c2898479209d1a9c97c3cd1782d7514e94d01b242a371a2df5592d620ebd6e18e63ff24ee8ba182f17e6c578431d738e955a957469e8069a919fd3a15532d460201d4e38ac04ac494b9cde1731d4511bf8faf8420a9de4f8c7d3d721fc30d8c3664683fd91ad3515e97092fb652205fb087890cb594947f5372c9b0b27f08b4b57bf610f777fcf040e6e7b8cedf85113dfd909cbac4b774c7580686f2e1f261898da4c6804d573fb22248005f5e0d3b256a0f3dcb71c47b3d674352bda82c22a513e381f990b6100328185511de9b3352126c5aedb9b0bde15743b42e231ef7227c0fe478044ce69474a740366058f07e56dde7d6089cb76e606482e7ba206355fc0fa180c4a41ae781e4723120e3d5a1dd40224db2c959ecbc9bce88bfeed64082d07b111e88a2d8a6a6fe097c9a298a6c3f76beb5b3b5aecedbbbcd404aac8fd25c069c747338ca0c81e6b63d87fc4f0bc18a86b721e3a16e9875741e0313057de8476ee84e36efe557dc33a7d23a9426f2e359781147607ad79235c9d7846320fe2d963fac79a5c92ff3067595273931174d2173f63cfceb9f62a873e7c240d3c260bcfb02b2697911321a72455cacc6929133d0af2cdf6d59a63293ac508786a4850267f90993fff3b6c07bbf3af0e3c08638148101ae1495da3360614866e238c4f60ca00f615877be80cc708da5ea1c30032acffd0e55429ba29dca409349d901a49831db44c1e58b7530b383d3f7e1cac79200cad9bdf87451783f2ffdab09b230aab52b41fa42fdd9f1f05a3dda0fa16b011c51e330d044adf394bbbb7fa25efc860f3082e42824be3b96943afbe641fe6bb"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "pkcs12",
        hashcat: &[
            hc!(
                24430,
                "$pkcs12$1$2048$16$0123456789abcdef0123456789abcdef$100$308200003082000006092a864886f70d0100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$ae3c0125849b1d877327a42c0aa768be0b1509c6"
            ),
            hc!(
                24440,
                "$pkcs12$256$2048$16$0123456789abcdef0123456789abcdef$100$308200003082000006092a864886f70d0100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$5b3715d7e4ee5fab89f56e803447637e69b8965cdcc6e2ef27e0c97448203671"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "onepassword-agile",
        hashcat: &[hc!(
            6600,
            "1000:d61a54f1efdfcf57:000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000afdb51c887d14df6200bbde872aabfd9e12a1f163eed40e6b3ec33ba394c47e9"
        )],
        john: &[],
    },
    Vector {
        slug: "onepassword-cloud",
        hashcat: &[hc!(
            8200,
            "9b6933f4a1f65baf02737545efc8c1caee4c7a5a82ce3ab637bcc19b0b51f5c5:30b952120ca9a190ac673a5e12a358e4:40000:e29b48a8cfd216701a8ced536038d0d49cf58dd25686e02d7ba3aa0463cc369062045db9e95653ac176e2192732b49073d481c26f29e1c611c84aaba93e553a6c51d1a9f7cfce0d01e099fb19f6a412bacd8034a333f7165fda1cc89df845e019c03ac9a09bc77b26c49524ade5c5a812230322f014f058b3bb790319e4a788f917aa164e56e78941f74e9c08921144e14be9b60da1a7321a0d178a1b8c1dcf83ffcadcb1599039049650577780d6913ee924e6529401e7a65b7d71c169a107e502dbd13b6b01c58e0483afb61b926313fa4273e685dd4890218bb797fab038c6a24df90883c7acd2358908edc1f7d95ef498757a3e0659aaaf6981c744ab69254267127fc806cf3cd1ced99ab455ece06479c91c892769af5db0c0f7a70dd83e4341bf86d085bbdc6a7e195ab08fc26"
        )],
        john: &[],
    },
    Vector {
        slug: "lastpass",
        hashcat: &[hc!(
            6800,
            "02eb97e869e0ddc7dc760fc633b4b54d:100100:pmix@trash-mail.com:9b071db7b8e265d4cadd3eb65ac0864a"
        )],
        john: &[],
    },
    Vector {
        slug: "lotus5",
        hashcat: &[hc!(8600, "3dd2e1e5ac03e230243d58b8c5ada076")],
        john: &[],
    },
    Vector {
        slug: "iwork",
        hashcat: &[hc!(
            23300,
            "$iwork$2$1$1$4000$b31b7320d1e7a5ee$01f54d6f9e5090eb16fef2b05f8242bc$69561c985268326b7353fb22c3685a378341127557bd2bbea1bd10afb31f2127344707b662a2c29480c32b8b93dea0538327f604e5aa8733be83af25f370f7ac"
        )],
        john: &[john!(
            "iwork",
            "$iwork$1$2$1$100000$d77ce46a68697e08b76ac91de9117541$e7b72b2848dc27efed883963b00b1ac7$e794144cd2f04bd50e23957b30affb2898554a99a3accb7506c17132654e09c04bbeff45dc4f8a8a1db5fd1592f699eeff2f9a8c31b503e9631a25a344b517f7"
        )],
    },
    Vector {
        slug: "windows-hello",
        hashcat: &[hc!(
            28100,
            "$WINHELLO$*SHA512*10000*00761655*3b3d3197efb2839a6072e922cc03be910be55d1e60389689c05b520d2d57c06258dc5a48798ba65424004cbe2e003d0509036f3394bcae108eb6b77c7eb306d7*c0772a3aca949db60f274f315b3a5f63fea552fc0d1f2032db5293ca9690735217d918d4cf697aa45b2fe598168804040e18fe00758be94aac971985ea7a5521*bff47e398df761733b5aeda7035cdf289547db3afb94b70cbad2aaea21a5cd58*8a4d5b88832e10bad57303324e6c9021733733df4acbf91366f51cebdc755e00fe1d01b3202469ee6ad5e667975b4f50e3110b00ef60414cd2cf96cc47df532e36b997727ffec2924d979d3fb6e677cb5827f4313131a46be8712926c42158339b55183e2fd7f2f0761980b1413897825c3759c566ff8a438189a6c8fb2d630dc33c6330de45c784d11957c686b40b6fe31fd8f2b1b664f542392326af5d334fdf92155343335e1b964955ac0b0e6f7254a599f0f0dc99becc2216515ba9e9472a54e60a14507fc353ebc47b9f0a8249a2a1bfa5d2cf526bd15ee68bd52e944ece9de6bbda913bc5083e26229673340fcc5285df0d38cbc7bb14584ced2fe9e9b3c283fa3c5ad4dd2034b7a67c8e7a1632fae8979a0abdd19be91c6bc371966121e04d433923e44df0b60c156bd90bc61c9fed01a7a76353f79dd4da3e07e12810ec3765128ec44b44b0789d6aa9e9702211a22ab8055ea32e9513fb1bd9d24ca04b33282632f63ab1b213e9644f97bc31dc4d2e7050c1fa23c0000facbf7c76fd7be4b112586f73f0c27abcf7cbe8c9d9fb83af70f60c490936fef84ed5301f73917b4e4170674a5d5e4bfbebdfeda9584221a0f190545efea7245dd2517ade393bedc255c4e016d9919e6e3f3711bca677fc099bf4e1730a752ea2a90a20ff3d09c909771849d3b009ba8d95d2b84fff889e38b079f1325aa42daa067a52abb5c064de3a5040e4a64e76b397b5c9ee6d045f3b5150cf428a92c141735908bb278077d52beefdc87efa156b8ebda071cb425fad0372a8a7cb6eb29926e8f6411ff1b818750c5b6888302fee9b1591b1c23db131538db2aa3de61dcd76fb7067be7ab71ee372bac18be0f446c974e92e79e27e7e3b2aa5ffc3f5f923f2df8ac2edcbb9392d1ac35e4cd52037d9dceedec6391e713e78770307bfde6a31b4e115904d285ac35db055ae8253b9968b7ed7b948da5f*785435725a573571565662727670754100"
        )],
        john: &[],
    },
    Vector {
        slug: "lotus-notes",
        hashcat: &[
            hc!(8700, "(GDJ0nDZI8l8RJzlRbemg)"),
            hc!(9100, "(HC34tD3KtDp4oCZWmCJ4qC30mC30mC3KmC30mCcA5ovrMLH9M)"),
        ],
        john: &[],
    },
    Vector {
        slug: "axcrypt1",
        hashcat: &[hc!(
            13200,
            "$axcrypt$*1*10467*9a7cd609bb262c738d9f0e4977039b94*ecbe0fd05a96fd2099d88a92eebb76c59d6837dfe55b3631"
        )],
        john: &[john!(
            "AxCrypt",
            "$axcrypt$*1*10467*9a7cd609bb262c738d9f0e4977039b94*ecbe0fd05a96fd2099d88a92eebb76c59d6837dfe55b3631"
        )],
    },
    Vector {
        slug: "axcrypt-sha1",
        hashcat: &[hc!(13300, "$axcrypt_sha1$b89eaac7e61417341b710b727768294d")],
        john: &[],
    },
    Vector {
        slug: "bestcrypt",
        hashcat: &[
            hc!(
                23900,
                "$bcve$3$08$234b8182cee7098b$35c12ef76a1e88175c4c222da3558310a0075bc7a06ecf46746d149c02a81fb8a97637d1103d2e13ddd5deaf982889594b18c12d7ca18a54875c5da4a47f90ae615ab94b8e3ed9e3c793d872a1b5ac35cfdb66c221d6d0853e9ff2e0f4435b43"
            ),
            hc!(
                24000,
                "$bcve$4$08$323631353538333233323034363039393534383233393530$9f7892b8324b1d8cd36b5f2f8705b407131261620a89370db8369046646f5f82b96780453948db53b04928ae0cc47066f13454b34e31b58ea44ce943bcba14fcbd87f17205a31a896df182629ceea164d87e9e29127e8d865ca0bee52f832723"
            ),
        ],
        john: &[john!(
            "BestCryptVE4",
            "$bcve$4$8$4944e8bfed6c688b6b30ed3aedb21c9efeba82a1425ebf8e$a4b51d5e6d0b15ba039d0a62cb1a2f4a1d0f6c0325658b15334657b7732a6dc4ec72de7a7c04216d0dd5167bc23e384ac99bca490307445bcbeeaf09da15465ba6540daa52422afdce6f199f92632e0675d9f90693a49ec964beb2358c7a95ff"
        )],
    },
    Vector {
        slug: "pkzip-master-key",
        hashcat: &[
            hc_ambiguous!(20500, "f1eff5c0368d10311dcfc419"),
            hc_ambiguous!(20510, "f1eff5c0368d10311dcfc419"),
        ],
        john: &[],
    },
    Vector {
        slug: "mozilla-key3",
        hashcat: &[hc!(
            26000,
            "$mozilla$*3DES*b735d19e6cadb5136376a98c2369f22819d08c79*2b36961682200a877f7d5550975b614acc9fefe3*f03f3575fd5bdbc9e32232316eab7623"
        )],
        john: &[],
    },
    Vector {
        slug: "mozilla-key4",
        hashcat: &[
            hc!(
                26100,
                "$mozilla$*AES*5add91733b9b13310ea79a4b38de5c3f797c3bf1*54c17e2a8a066cbdc55f2080c5e9f02ea3954d712cb34b4547f5186548f46512*10000*040e4b5a00f993e63f67a34f6cfc5704*eae9c6c003e6d1b2aa8aa21630838808"
            ),
            hc!(
                26150,
                "$mozilla$*AES*95f6acda22fbfb543226eca01b2e65099730d20cb3114c47536bc33a96b9137ea4a1dcebbcb8d924d20f5784be1fb1f3*b3edd4ec861f2e7a16c72771302a55f11b1504ac1792a4c408c44aa82023ef7f*10000*040eaff904bd66d4f3ba86cbb13ced52*a0b908a87ba816a5cb4d9632f015a972"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "blockchain",
        hashcat: &[
            hc_ambiguous!(
                34700,
                "$blockchain$269$0349575305940509451603791869345994679e29d1618f26ed65ee15ad65d1af046f51ffcfbfa82dcccea07bb0f0fff725af53b96910646440b361453addc5caeb2a09479dc6cce3a1ebf138e2649689ab286ba2db6bd5edef310cac8f9386f002a534e9346cdc61bd0e21ca738eb2418a8158c83a43517981c43d8792cad6f290cbf40d5a3c1bb20283fcb44c59cae2dc90c898dbc4e960ca666653a08d90471610a8b9bf590752e8d8bee27e7aa58d015324dae83c87a46384ed8f947e37e65d4572018b5bfd8fd8ea70df777c8b692bc613ccb528356d1844490ac2b3be2dd8927fbf1aabf9b6cedec39742ed92a03220f4468bd32c1eed5d5c3c3aa0be459e06466c94991df97f335bd661"
            ),
            hc!(
                12700,
                "$blockchain$288$713253722114000682636604801283547365b7a53a802a7388d08eb7e6c32c1efb4a157fe19bca940a753d7f16e8bdaf491aa9cf6cda4035ac48d56bb025aced81455424272f3e0459ec7674df3e82abd7323bc09af4fd0869fd790b3f17f8fe424b8ec81a013e1476a5c5a6a53c4b85a055eecfbc13eccf855f905d3ddc3f0c54015b8cb177401d5942af833f655947bfc12fc00656302f31339187de2a69ab06bc61073933b3a48c9f144177ae4b330968eb919f8a22cec312f734475b28cdfe5c25b43c035bf132887f3241d86b71eb7e1cf517f99305b19c47997a1a1f89df6248749ac7f38ca7c88719cf16d6af2394307dce55600b8858f4789cf1ae8fd362ef565cd9332f32068b3c04c9282553e658b759c2e76ed092d67bd55961ae"
            ),
            hc!(
                15200,
                "$blockchain$v2$5000$288$324724252428471806184866704068819419467b2b32fd9593fd1a274e0b68bf2c72e5a1f5e748fd319056d1e47ca7b40767136a2d97d7133d14faaeca50986f66cdbc0faec0a3fabbd0ba5d08d5322b6b53da021aacfc439c45bec0e9fe02ad81db82f94e9bd36a7d4d76b505c2339fcd46565d3abab958fbeb1de8bfc53beb96cde8fe44128965477c9ef0762c62bbb1d66532b4888e174ea949db54374a2ed9686a63eb0b5b17ae293f7410bb4ae5106f108314a259c5fd097d558515d79350713412159103a8a174cd384a14f3da45efe18044e1146036000231f6042577d0add98fc959d265368e398dc1550b0bc693e9023cd9d51b40e701bd786e19c3a281a90465aa6ea3f9e756d430164ab2eb43be5b6796d7ac15b2fe99217410f2"
            ),
        ],
        john: &[john!(
            "Blockchain",
            "$blockchain$v2$5000$544$9a4d5157d4969636b2fe0738f77a376feda2fb979738c5cf0e712f5d4a2f001608824a865d25041bc85e0ad35985999fcfae7d218eb109a703781f57e7b5a03c29ffdfb756ec8ee38ed8941b056922cdd174c8e89feb40e1a0e1766792845f57992ae9d7667eff41a5e5580f3f289b050d76cc0f049cbd30c675efc3a553c0f19f30cb9589c7c3773dd095de92a991963789408351f543c1dc307751e5f781c278da77270035e3743df01ab4e41155b6437d9c7e64388a28f8331aca4822e6b89cdd5f45061b99768218d853a3575bbd029564826bcb188d55444273cda588d4e593fc5d29696713d747cfc8302a3e9c9dbb1bb3754c2e00f28b69d8faeb2e45c04085359c6a9b6bfecfd0a6a8f27ad647b6bfd498f2224a8c0442f7fe730656263ac2869923b296ad9955dbad515b4f88ad33619bdacc33ae7f14c65fce029e0f9e4a9c414716d9a23e4361aa264493bb6fc9a7fda82599b0232174b9fc92a1c717ca2cc6deb8bd6aaf3706b95fdfdc582316cb3d271178dafe3a6704a918e07be057bef676bb144840c7f26676f183f2744fc2fe22c9c3feb7461b4383981c00b6fff403fef578f6e5464dc2d0bcb7b8d0dc2e7add502b34c8fe9f9b638eebe7ede25e351b17ea8b8c1f5213b69780c0ba7ef3d5734c0635e9d2ee49524914f047d45536180be25e7610db809db694ceeb16a3bfd8abd5ab0cda4415203408387698fe707568566f7f567164707091a806ac2d11b9b9dd0c3c991ff037f457"
        )],
    },
    Vector {
        slug: "rar3p",
        hashcat: &[
            hc!(
                23700,
                "$RAR3$*1*e54a73729887cb53*49b0a846*16*14*1*34620bcca8176642a210b1051901921e*30"
            ),
            hc!(
                23800,
                "$RAR3$*1*ad56eb40219c9da2*834064ce*32*13*1*eb47b1abe17a1a75bce6c92ab1cef3f4126035ea95deaf08b3f32a0c7b8078e1*33"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "cram-md5",
        hashcat: &[hc!(
            10200,
            "$cram_md5$MTI=$dXNlciBiOGYwNjk5MTE0YjA1Nzg4OTIyM2RmMDg0ZjgyMjQ2Zg=="
        )],
        john: &[],
    },
    Vector {
        slug: "ipmi2-rakp-sha1",
        hashcat: &[hc!(
            7300,
            "3437343735333336383831353232323433383333303236303337333338363232303135383237333638363532373231343030313131333838323734373138363632343133333335353030353633373533333133313530363533303738343334313330303630343633333237373037383537333630303233303830303437323838333237313438363238343434383831363634323431333430383735323038:f4b376e25868751fc0264f573ff1fe50b65ce5a2"
        )],
        john: &[],
    },
    Vector {
        slug: "ipmi2-rakp-md5",
        hashcat: &[hc!(
            7350,
            "08b017f3628b9835c748521e412429c9:f3450000df540000cdd981b0b3441be8774a61e69321291891a29a0c5fdac3f06194bd2c29fa5246000000000000000000000000000000001400"
        )],
        john: &[],
    },
    Vector {
        slug: "sap-bcode",
        hashcat: &[
            hc!(7700, "027642760180$77EC38630C08DF8D"),
            hc!(7701, "027642760180$77EC386300000000"),
        ],
        john: &[john!("sapb", "DDIC$C94E2F7DD0178374")],
    },
    Vector {
        slug: "sap-passcode",
        hashcat: &[
            hc!(
                7800,
                "604020408266$32837BA7B97672BA4E5AC74767A4E6E1AE802651"
            ),
            hc!(
                7801,
                "604020408266$32837BA7B97672BA4E5A00000000000000000000"
            ),
        ],
        john: &[john!(
            "sapg",
            "DDIC$6066CD3147915331EC4C602847D27A75EB3E8F0A"
        )],
    },
    Vector {
        slug: "android-fde",
        hashcat: &[hc!(
            8800,
            "$fde$16$ca56e82e7b5a9c2fc1e3b5a7d671c2f9$16$7c124af19ac913be0fc137b75a34b20d$eac806ae7277c8d48243d52a8644fa57a817317bd3457f94dca727964cbc27c88296954f289597a9de3314a4e9d9f28dce70cf9ce3e1c3c0c6fc041687a0ad3cb333d4449bc9da8fcc7d5f85948a7ac3bc6d34f505e9d0d91da4396e35840bde3465ad11c5086c89ee6db68d65e47a2e5413f272caa01e02224e5ff3dc3bed3953a702e85e964e562e62f5c97a2df6c47547bfb5aeeb329ff8f9c9666724d399043fe970c8b282b45e93d008333f3b4edd5eb147bd023ed18ac1f9f75a6cd33444b507694c64e1e98a964b48c0a77276e9930250d01801813c235169a7b1952891c63ce0d462abc688bd96c0337174695a957858b4c9fd277d04abe8a0c2c5def4b352ba29410f8dbec91bcb2ca2b8faf26d44f02340b3373bc94e7487ce014e6adfbf7edfdd2057225f8aeb324c9d1be877c6ae4211ae387e07bf2a056984d2ed2815149b3e9cf9fbfae852f7dd5906c2b86e7910c0d7755ef5bcc39f0e135bf546c839693dc4af3e50b8382c7c8c754d4ee218fa85d70ee0a5707a9f827209a7ddb6c2fb9431a61c9775112cc88aa2a34f97c2f53dfce082aa0758917269a5fc30049ceab67d3efd721fee021ffca979f839b4f052e27f5c382c0dd5c02fd39fbc9b26e04bf9e051d1923eff9a7cde3244902bb8538b1b9f11631def5aad7c21d2113bcdc989b771ff6bf220f94354034dd417510117b55a669e969fc3bc6c5dcd4741b8313bf7d999dc94d4949f27eec0cd06f906c17a80d09f583a5dd601854832673b78d125a2c5ad0352932be7b93c611fee8c6049670442d8c532674f3d21d45d3d009211d2a9e6568252ac4682982172cb43e7c6b05e85851787ad90e25b77cce3f7968d455f92653a1d3790bc50e5f6e1f743ac47275ffa8e81bbe832a8d7d78d5d5a7c73f95703aebb355849ae566492093bd9cb51070f39c69bb4e22b99cc0e60e96d048385bb69f1c44a3b79547fbc19a873a632f43f05fa2d8a6f9155e59d153e2851b739c42444018b8c4e09a93be43570834667d0b5a5d2a53b1572dab3e750b3f9e641e303559bace06612fbd451a5e822201442828e79168c567a85d8c024cd8ce32bf650105b1af98cc5428675f4f4bbede37a0ef98d1533a8a6dcb27d87a2b799f18706f4677edaa0411becac4c591ede83993aedba660d1dd67f6c4a5c141ad3e6e0c77730cb0ecbf4f4bd8ef6067e05ca3bc563d9e1554a893fea0050bdd1733c883f533f87eac39cceee0ccf817fc1f19bcfdd13e9f241b89bfb149b509e9a0747658438536b6705514cc6d6bb3c64c903e4710435d8bebc35297d1ebbdff8074b203f37d1910d8b4637e4d3dab997f4aa378a7a67c79e698a11e83d0d7e759d0e7969c4f5408168b282fe28d3279ec1d4cc6f85a0f8e5d01f21c7508a69773c44167ff8d467d0801f9ec54f9ee2496d4e7e470214abc1ca11355bb18cd23273aac6b05b47f9e301b42b137a2455758c24e2716dcd2e55bbeb780f592e664e7392bf6eccb80959f24c8800816c84f2575e82e1f3559c33a5be7a3a0c843c2989f486b113d5eeada007caf6b5a0f6d71e2f5c09a4def57c7057168051868317a9ec790d570d76a0d21a45ad951c475db5a66101475871147c5a5907ec4e6b14128ed6695bb73c1c97952e96826eeb6003aa13462093e4afc209627241f03b0247e110fbab983640423b7cdf112e01579fed68c80ac7df7449d9d2114b9ae5539c03c2037be45c5f74e7357b25c6a24b7bd503864437147e50d7ac4ccc4bbd0cabecdc6bac60a362285fe450e2c2d0a446578c8880dc957e6e8061e691b83eb8062d1aad476e0c7b25e4d5454f1288686eb525f37fe649637b235b7828366b0219a9c63d6ddbb696dc3585a2ebfbd5f5e4c170d6784ab9993e15142535e194d2bee3dc9477ef8b8e1b07605e0c04f49edf6d42be3a9dabbc592dde78ce8b7dd9684bfcf4ca2f5a44b1872abe18fb6fa67a79390f273a9d12f9269389629456d71b9e7ed3447462269a849ce83e1893f253c832537f850b1acce5b11d2ba6b7c2f99e8e7c8085f390c21f69e1ce4bbf85b4e1ad86c0d6706432766978076f4cada9ca6f28d395d9cc5e74b2a6b46eb9d1de79eeecff7dc97ec2a8d8870e3894e1e4e26ccb98dd2f88c0229bbd3152fa149f0cc132561f"
        )],
        john: &[john!(
            "fde",
            "$fde$16$04b36d4290b56e0fcca9778b74719ab8$16$b45f0f051f13f84872d1ef1abe0ada59$0f61d28f7466c0435040cc845a67e6734500de15df3ba6f48d2534ca2a7b8f910d7547357e8f1ec7364bab41383f5df9b5fb43fcd4a1e06189ce3c6ba77ec908b066e73a508e201c941fb409e9abdc051c3c052a735b01e56be61efa635e82cbceab18db1ba645b93f7befb83155852f0004a7c7d6800e9fa5f0d3c133dd2496f92110c3cdcfb16dcf57df8de830969e18514a34d4917de14597da19f9f7dc81eca2d7d461c91e0a8aeac06bafe89866d24f2b4991b4295b6277d0ff4ad97f1fa58e20f8a24e2062f84c318eb36cfbb4671117bc3522afcf7737353589cae0dce0d7c3341f457af654543758f3f005bd4d68fa2b35777cb2ea5f8f69c4debcfb1d8b2a601320e4f8621dc6e99434007388bdc0ceebc722f9ed44cbce3914bf144db332276e719f6b48108cde55916d861d19dc8c03ac76a2dad322457073111e441488228f13649073aa3aadfab51dadf89a0827acba284154a9e18d926facef43852a0733660a1fbcca8e81d2f41efd9f645a61f9395b75fc7ad446885d304808d511f2ba2e7c6138588c4292aee4ef6f2537bb00c7b015cee4a91d2defa87b67abc1315e71f0489e271673b36412377219e93aba6af3cfd504bf3f6bc24f2b6148536339d91ddd2f013314544650c1c11e7317028a7014909d0c850f78692e476c4f57da586fe26786504130aba22ba5261b989aeb47483d8cb9d5052120a4e5690b5b0cd009aadaadc351db7b6a230ebc1fa771651cb64d78daa56b7a6c6808db3b688afee9b7edaa617d8cb16ac7290465987bd443ea41ce38aa14e0c88874fb2707394b83679de82134efe351b4d021c63b2992a8314b2e93908906400628a7f753c9a4d85e917a207561b7840ce121800fab4026508d1b00fe8e7e756573743e11380f76f6bb7c0e528cb98875e6ad88bff51236601e6942964e37ffe0316b1a1f7bc0d84334fa024bf03c261bd06a07c01f099ad23fb9a1d8c98447463b8988cb33f3e1fb7d7a7c547f9a6d51cf7b75649d3c8cb5bf93be79eba1a961659b5fe928a1c7e80aca857825c6bc11493cb230e66126ef7b7284abe0823b5735bb1dfe844029f175c63442ca774784b775ecf02e48d029ac0f236813be91aca66905640666b89bd08118e3c18c75764bc49d00d1fe53ee92ccaa487852c613cba91f637b6de06dcaa1953a7cfb5333df573273a67f0157b63fbbf48c48f16c423caefaf29cdb5d34b19ac0f57b972b9e5ff1bc5cf25bdcdf8d29fb75865c4501458f19bfd64c844fd52a27feec97dc31ba922aea75706404d853071707d0c6001c59664676be6426ca5c7efbfc09ffa9acac91441f9175fd3148fb046c31a49d7c7ad10bf3c4b413dd148666b72b5a533f600cb02d7623270e5d1ad33355dd318d06aa8b3d7517cb7d5be40d222a026380cfbf5b79014e7631d677b07bcd805d9ea7103cf1d057bf883b29fb99b064c4e3cb4271596a74895c1c3f7c7c49d2be54b1435af4440ecd019dde11cee14a320712c9275bef339a15d3a18d9f38918d7af0a50a35199980429d74d4cc2a16dea619619a7c19827f4f78d3ebaf13340abf6717cec6bff8399b067fb17f11cdb1f9909c51253f7466ee769546d1d96319bcc1b04a6b1f8d8068f96b959d507c9004d75717792733fadb7a94a2d5db514a61cbd90eef89d1ace5a3138120168d62f1ebef5efbbd4e7f7e987834db81fe8c4877f3edcc71c61e96b20ca26c5a91e28fa11e484c1dcbfd5a0461065fe52f042ee9a09687d800c90a0a792f3dbe257965247f8eecd122b9b234b734454fa1477212a0295a347ae44463de4de405bf4fd91cde400b63d7fced6d7ccd20d79a4899139a79085f8742c3dfe7fbadca56c4e8aa95ce7841ad9675659349f6671d047efa0951feb9c61381f5f9e39182c1ec0a3ebd2ef5e036312c6ed6a0e59777813229ffdac771788e609c7d9f96848f63b428789c55e85c509068df8d5a0a7fc066be8c76205860d86d6c5bb7c2bc85a922a2ad86e6a791fe238420eedd1cf7ac770dd8316ca30c9577441a34873cdf0c5dc2103457a93fa0dd42da5eb2d6f82e9ff47b4bb6cd1d3fcba5645caace577a89c7bd70ff432f8dae113a7877a41a41043dac4c0d21860ad8198a1b9640d979322a20d4b90caa77a5d2b31c5bd06e"
        )],
    },
    Vector {
        slug: "android-fde-samsung",
        hashcat: &[hc!(
            12900,
            "15738301074686823451275227041071157383010746868234512752270410712bc4be900bf96ccf43c9852fff49b5f5874a9f6e7bf301686fa6d98286de151f15738301074686823451275227041071"
        )],
        john: &[],
    },
    Vector {
        slug: "chacha20",
        hashcat: &[hc!(
            15400,
            "$chacha20$*0400000000000003*16*0200000000000001*5152535455565758*6b05fe554b0bc3b3"
        )],
        john: &[],
    },
    Vector {
        slug: "bitcoin-wallet",
        hashcat: &[hc!(
            11300,
            "$bitcoin$96$c265931309b4a59307921cf054b4ec6b6e4554369be79802e94e16477645777d948ae1d375191831efc78e5acd1f0443$16$8017214013543185$200460$96$480008005625057442352316337722323437108374245623701184230273883222762730232857701607167815448714$66$014754433300175043011633205413774877455616682000536368706315333388"
        )],
        john: &[john!(
            "Bitcoin",
            "$bitcoin$96$c265931309b4a59307921cf054b4ec6b6e4554369be79802e94e16477645777d948ae1d375191831efc78e5acd1f0443$16$8017214013543185$200460$96$480008005625057442352316337722323437108374245623701184230273883222762730232857701607167815448714$66$014754433300175043011633205413774877455616682000536368706315333388"
        )],
    },
    Vector {
        slug: "oldoffice",
        hashcat: &[
            hc!(
                9700,
                "$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2"
            ),
            hc_ambiguous!(
                9710,
                "$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2"
            ),
            hc_ambiguous!(
                9720,
                "$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2:91b2e062b9"
            ),
            hc!(
                9800,
                "$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd"
            ),
            hc_ambiguous!(
                9810,
                "$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd"
            ),
            hc_ambiguous!(
                9820,
                "$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd:b8f63619ca"
            ),
        ],
        john: &[john!(
            "oldoffice",
            "$oldoffice$1*de17a7f3c3ff03a39937ba9666d6e952*2374d5b6ce7449f57c9f252f9f9b53d2*e60e1185f7aecedba262f869c0236f81"
        )],
    },
    Vector {
        slug: "office",
        hashcat: &[
            hc!(
                9400,
                "$office$*2007*20*128*16*18410007331073848057180885845227*944c70a5ee6e5ab2a6a86ff54b5f621a*e6650f1f2630c27fd8fc0f5e56e2e01f99784b9f"
            ),
            hc!(
                9500,
                "$office$*2010*100000*128*16*34170046140146368675746031258762*de5bc114991bb3a5679a6e24320bdb09*1b72a4ddffba3dcd5395f6a5ff75b126cb832b733c298e86162028ca47a235a9"
            ),
            hc!(
                9600,
                "$office$*2013*100000*256*16*67805436882475302087847656644837*0c392d3b9ca889656d1e615c54f9f3c9*612b79e33b96322c3253fc8a0f314463cd76bc4efe1352f7efffca0f374f7e4b"
            ),
        ],
        john: &[john!(
            "Office",
            "$office$*2007*20*128*16*8b2c9e8c878844fc842012273be4bea8*aa862168b80d8c45c852696a8bb499eb*a413507fabe2d87606595f987f679ff4b5b4c2cd"
        )],
    },
    Vector {
        slug: "pdf",
        hashcat: &[
            hc_ambiguous!(
                25400,
                "$pdf$2*3*128*-3904*1*16*631ed33746e50fba5caf56bcc39e09c6*32*5f9d0e4f0b39835dace0d306c40cd6b700000000000000000000000000000000*32*842103b0a0dc886db9223b94afe2d7cd63389079b61986a4fcf70095ad630c24"
            ),
            hc!(
                10400,
                "$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000"
            ),
            hc_ambiguous!(
                10410,
                "$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000"
            ),
            hc_ambiguous!(
                10420,
                "$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000:6a8aedccb7"
            ),
            hc!(
                10500,
                "$pdf$2*3*128*-4*1*16*62888255846156252261477183186121*32*6879919b1afd520bd3b7dbcc0868a0a500000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000"
            ),
            hc!(
                10510,
                "$pdf$1*3*40*-4*1*16*5e1f73575e1f73575e1f73575e1f7357*32*c0be424bef466277092f2a1ba0fbe506ebabe5c01db100dedc0ffeebabe5c01d*32*0ff1cedeadce110ff1cedeadce110ff1cedeadce110ff1cedeadce11babebabe"
            ),
            hc!(
                10600,
                "$pdf$5*5*256*-1028*1*16*28562274676426582441147358074521*127*a3aab04cff2c536118870976d768f1fdd445754d6b2dd81fba10bb6e742acd7f2856227467642658244114735807452100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000"
            ),
            hc!(
                10700,
                "$pdf$5*6*256*-1028*1*16*62137640825124540503886403748430*127*0391647179352257f7181236ba371e540c2dbb82fac1c462313eb58b772a54956213764082512454050388640374843000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000"
            ),
        ],
        john: &[john!(
            "PDF",
            "$pdf$1*2*40*-4*1*36*65623237393831382d636439372d343130332d613835372d343164303037316639386134*32*c7230519f7db63ab1676fa30686428f0f997932bf831f1c1dcfa48cfb3b7fe99*32*161cd2f7c95283ca9db930b36aad3571ee6f5fb5632f30dc790e19c5069c86b8"
        )],
    },
    Vector {
        slug: "gpg",
        hashcat: &[
            hc_ambiguous!(
                17010,
                "$gpg$*1*348*1024*8833fa3812b5500aa9eb7e46febfa31a0584b7e4a5b13c198f5c9b0814243895cce45ac3714e79692fb5a130a1c943b9130315ce303cb7e6831be68ce427892858f313fc29f533434dbe0ef26573f2071bbcc1499dc49bda90648221ef3823757e2fba6099a18c0c83386b21d8c9b522ec935ecd540210dbf0f21c859429fd4d35fa056415d8087f27b3e66b16081ea18c544d8b2ea414484f17097bc83b773d92743f76eb2ccb4df8ba5f5ff84a5474a5e8a8e5179a5b0908503c55e428de04b40628325739874e1b4aa004c4cbdf09b0b620990a8479f1c9b4187e33e63fe48a565bc1264bbf4062559631bef9e346a7217f1cabe101a38ac4be9fa94f6dafe6b0301e67792ed51bca04140cddd5cb6e80ac6e95e9a09378c9651588fe360954b622c258a3897f11246c944a588822cc6daf1cb81ccc95098c3bea8432f1ee0c663b193a7c7f1cdfeb91eee0195296bf4783025655cbebd7c70236*3*254*2*7*16*a47ef38987beab0a0b9bfe74b72822e8*65536*1f5c90d9820997db"
            ),
            hc_ambiguous!(
                17020,
                "$gpg$*1*668*2048*57e1f19c69a86038e23d7e5af5d810f4f86d32e9aaaf04b54281cda2194dcca99ee1f23f4aa3a011d5d2dc9e47689c449f398d315f91a03f4765742d20a7046e986a9696f0e07380a73fdd61e7ab2caa463a049a5869e008e16bb30d22f93f9aa8b0fdd41d2b19e669d58ca462498905e79944bff578c24139a88ef44582aef93f94fe22406a3ae32dcc0f0602e2f4345db2bd9d775eaeb14a8d7aff963e1ca8c29bab2fc3d459941587f4242af6e100e2e668a6c9247c19969ba294f6f2ab60ef84d42aab2e3512153a283d321442840189733dc6024dab0ea5d10d2e07fee914fc2e7177b310e8835bf8a5ffe1bde5ce0a74d3dd570c1b2652672873d3c520364acc0af35f5f7d0e0e95df8c2db3855936e0a4a24cc463bf277b0c5ea37d4ac1ddae6ef9da18852620de15ab648306f3d7acbb918e79f3ab7a3eaf4f59416560c4d31d8a0220c3301c95db4b8fe6b69348657aed52d5e15aefb17fedd15a50630a4edbad362ba9b79a048b4966a70643d8fa31fb397a531db85e8ad5bb169f5188449dbcc1bbaf42440d1794a34296c2407092c76e59544133959309ce42a05899162c55a865018085a4c57068294a5389cf6fbf1c93b5ab7732625fb6a465bd7ec51a128c2f9b0cf3fd0367f92667098b3a8af40f9f434a2a727b09bddbad1762127cc785eda419ac3ff24c8724e04ea2d330b0b441f34623955efd383f20578cdc527f3076ee068b727cd399ce17ff9d5233409b2d16d55c5c80cb8ca01019cd068c6e803217d6f2b7124e354b89de0eb0dfd241384026a1cdca529b6fed37aa0ececb0d6c26de06407d75a6e3108b0d25621db418206291a67216306e1a18c992736e45ef7f87373c0a3f28ddc1b4543604cd154f6b79265a6d8c13550078c3bcf55063263e5bc5cae6b925c1dbb67f972e234006867849e653*3*254*10*9*16*d1547688c9cc944482d16dff17df0858*20971520*1fef4e57e302d34e"
            ),
            hc_ambiguous!(
                17030,
                "$gpg$*1*668*2048*e75985b4e7d0bce9e38925a5cf69494ae9a2ccfe2973f077d9423642fffec8bee0e327178a4a3431875ca1f377b9f89269e7c42b94150859d9e5bf5c4504d63076b270118183dda75d253492be8b680c0061e7f130010a00a09a0456710051f2483052ad209fcb9f194f78ecd04fd04953fa1cd6f7ce9babca8b2ee6432730de069648460b2822fe355ed19e0055c69251097681901d7183626019d938727399df47f5249f25b1c73e8654bf935014533845f278e6dd94b8c2964ad6a87c718967686f39a88b21a0e5a93321d4733c81d9310955db6990d8cd02bcf73159b1f48f5615def601aa3e12bf30384da41b558b1eef1111cfc85c8772c123a7b977e2ba399f65679c35b9a2abfde0230a5706fe99f5460c700b1498b1661353ec30eab25defb9af2e7e744fd050d2e7c87542d8bc49e728a7734accf2801dc5972192670858f2004308f3afdd94acd44e1161c44dd372296ca7fe40cbb541c21d640a10df34460c4f5c7cd1bf3b3282668d7edb53be4d843aef4b6f0357526d9c4432aa2a45e113a73e75bfec98cb4cc020ab6cca35336fd188140fd16183dbe288707421e698b6e4801508ae903de3e5d600bd613ea612af92780e53be37722897edb8a588193e7d28819c2f0cbb4e97c3e830113ce14ab05ddb82552fc5e82c386ec2fe9b2d86fc7ade39e341e3dd828502cc3dd038cb21cb0512e79dca9f5a9eae78b2e91aa0732ac77fbc3bc5575c210f519c178669ea99bef62eb6761dfa76407d0d501b07a696a0214dafde7b0bfb48e8ba445b6b42a859a63cb91c9d991ed030ef9e6c63f53b395e14821d7039e4455e0e3712f77f64b7abaa04467bd5b9be26c5e098430187676d0aa7206e2e4fa2e5b7bd486d18b0f3859e94319ccac587574a7bae6ccb3e9414cc769761cf6a0fa1b33cccd1a4b0b04c0d52cd*3*254*8*9*16*343d26cf2c10a8f8a161874fbb218c12*65536*666ae8d1c98404b0"
            ),
            hc_ambiguous!(
                17040,
                "$gpg$*1*1308*4096*ddf02802e2d06319bcf5962745b73677ecfa229649fed991e3360bdf2fffe71f521b8f877bccfcdce9a4fb4aeb63bd21fed6e37f96f193a6f7d3c476f4a7e01e7421d0eba5bfcd59544e37887572cd40e8d03e901574ec0f3afdff35ad3f25cb818ddadee84ddfef636207febd8d12d8a98983c86afa46608d178dba5ec51e98a182bd9687b6431fba87b5a16b5e0cf872db7dc12c55bfe7faaa443044d5a84ddf034198e5bc6b4b707b5f4a4c5999ff3885975113fca02693620f36f8f20570bdaf581726053b6c982cb988a3091dc206624f9d36372b151b22c7dc2cb71b9aaed95dc5630c4c4b045f80c403836cc9c84951fc04b8d6e413e1d4f6b3815508f43cf80c25c7db3882b5b6572f1395a00dcda7fe65ce2155f9ea2cfe13588e0fb10316e7dd978e1d89cffc06a5e722ec765315926d2ee9060d8f449ead31cbacea88a5251be3b518d23984530da9f930114e614b7ed30f748c7512bddca8604bb5310ed76b9982eb88acaf49a29325e9db6987c6dea3878e2cb7daf3800177579ddcaafeacdba8edd147fae61bae36ab83a98db69a6c92017b3db8cff68985db989a03ee1bd045e6a577151486cdaeaf26517027b2f140b8493e2f401ea222511c2ce61c7057d64e8c3568e3f547f4b2875db59bc8c4f3346e0faf54e30745f583494b59e570bacb2b9eb71eb834e57f68aadda9af4bdb03276f71770c611aad0278033bb8c108471c4f4a2aa9070774367b9334661daf8a5e3eaf3d8dcca723d64ae7264c8709987a6cee9f42287b6e20d1d753262ff74886f3995412e59d09c61e4c637b6e97e6a3b08f9fa6adf9a1ec44a0372e893febd6712decc00bbd9cdacaf6bb9302fe8bd2ca27fdf5156c33582d56781ab0e5bd14da4b1edd73edd8f2a034a56d1a6f836724b605657f4714d59d522805e0ab02c6c5daed0973f93120ae01623ce0a96fbdf4402ce20ebb4f97fabbc90da5bb12aac3cd5f15c1add2d3863be59e843dca564ce9aa25b43ca1044b1e7e65d03d1f55f77d2a39cd85536ff38058837a23743c4e252f7de5654a562506b55d2b8fa29c7f4ecd307a8ae686cbb73fea6a8f72775d9e417ec346415024263a9f339dda286b682ccc8f93f7d4f59921620dd276188441fd44fc63925d18caa30a75c79c37a2ea45d14f6e423d2146281f9c6699a0658e50d69cfbc174090a0420bbb6f4e6b5b1f2b81b26f035aaf5c2e558c812496cb494587c78bf75350fb1a36e8c88076b4684094e0cba5dcdc4f672dbd2b432306b75077ae07b8fd88ba5b829eaed3fd2959a09b162329b75ac8fc20d4eea6e5971f54b31a23952dd4c111765822182cd60ee0de3cce3752c648918e3ec4c52643223132dcc885140faf8108230ebf4ef4149cbfa3070c91ec013404c15c1cecaa1efd544ab8313d378ef0e77c615b76b8ec07769960873ce9c7bdb1d75e7faef4c8a0b015c95a4e2bcd9ff7f5dfddd9a243fc0688db09e534ef1f3ebebd0c73b75bd57b8e02667da5744b1400dc695d4ae1e255d3487d1dead115de7d48962a15c7aecb97444173c40c028a46a7cfdd8cc7421f71d757cb809341c5148aedeab16f9289bc55b7475d646ae4993ab36fe5609a05121d140d4390289c94e4d87fd902fe03c8bfa13e7cfc9c21355ab6461d214137e4d90dff4a8f599020f12d7560fa4b5aaee1727f21c873fde76415b65357ecb923a547ddcdb20dde0880a287ed26d5ea4ce45514b907e368527c62e39ffdf2efeb817cd59694d23bafd48862e723f45e3c258cff3c804c5d2f17e24be8fe81a00f11f519beb9cde7be95226ac2a7f11e0f4f09dc040c11e1bf63172aa0f8a*1*254*2*3*8*0000000000000000*0*a11df265e4e54bee"
            ),
            hc_ambiguous!(
                17050,
                "$gpg$*1*60*4096*71cdae39dd004b5fd4571575c683a33ecb0d2ea4495655b2544a63397b4f92e1b7d2c5243143398f9d44aba1e7b97c88b7030080b97c811d757264be*1*254*2*7*12*07f4ca8d366ae2e0ab55da75*329368576*199d8afecccd9dd6"
            ),
        ],
        john: &[john!(
            "gpg",
            "$gpg$*1*348*1024*8833fa3812b5500aa9eb7e46febfa31a0584b7e4a5b13c198f5c9b0814243895cce45ac3714e79692fb5a130a1c943b9130315ce303cb7e6831be68ce427892858f313fc29f533434dbe0ef26573f2071bbcc1499dc49bda90648221ef3823757e2fba6099a18c0c83386b21d8c9b522ec935ecd540210dbf0f21c859429fd4d35fa056415d8087f27b3e66b16081ea18c544d8b2ea414484f17097bc83b773d92743f76eb2ccb4df8ba5f5ff84a5474a5e8a8e5179a5b0908503c55e428de04b40628325739874e1b4aa004c4cbdf09b0b620990a8479f1c9b4187e33e63fe48a565bc1264bbf4062559631bef9e346a7217f1cabe101a38ac4be9fa94f6dafe6b0301e67792ed51bca04140cddd5cb6e80ac6e95e9a09378c9651588fe360954b622c258a3897f11246c944a588822cc6daf1cb81ccc95098c3bea8432f1ee0c663b193a7c7f1cdfeb91eee0195296bf4783025655cbebd7c70236*3*254*2*7*16*a47ef38987beab0a0b9bfe74b72822e8*65536*1f5c90d9820997db"
        )],
    },
    Vector {
        slug: "rar3hp",
        hashcat: &[hc!(
            12500,
            "$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317"
        )],
        john: &[john!(
            "rar",
            "$RAR3$*0*b109105f5fe0b899*d4f96690b1a8fe1f120b0290a85a2121"
        )],
    },
    Vector {
        slug: "rar5",
        hashcat: &[hc!(
            13000,
            "$rar5$16$38466361001011015181344360681307$15$00000000000000000000000000000000$8$cc7a30583e62676a"
        )],
        john: &[john!(
            "RAR5",
            "$rar5$16$37526a0922b4adcc32f8fed5d51bb6c8$15$8955617d9b801def51d734095bb8ecdb$8$9f0b23c98ebb3653"
        )],
    },
    Vector {
        slug: "winzip",
        hashcat: &[hc!(
            13600,
            "$zip2$*0*1*0*0675369741458183*5dc5*0**36b85538918416712640*$/zip2$"
        )],
        john: &[john!(
            "ZIP",
            "$zip2$*0*1*0*0675369741458183*5dc5*0**36b85538918416712640*$/zip2$"
        )],
    },
    Vector {
        slug: "filevault2",
        hashcat: &[hc!(
            16700,
            "$fvde$1$16$84286044060108438487434858307513$20000$f1620ab93192112f0a23eea89b5d4df065661f974b704191"
        )],
        john: &[john!(
            "FVDE",
            "$fvde$1$16$84286044060108438487434858307513$20000$f1620ab93192112f0a23eea89b5d4df065661f974b704191"
        )],
    },
    Vector {
        slug: "sevenzip",
        hashcat: &[hc!(
            11600,
            "$7z$0$14$0$$11$33363437353138333138300000000000$2365089182$16$12$d00321533b483f54a523f624a5f63269"
        )],
        john: &[john!(
            "7z",
            "$7z$128$19$0$1122$8$a264c94f2cd72bec0000000000000000$725883103$112$108$64749c0963e20c74602379ca740165b9511204619859d1914819bc427b7e5f0f8fc67f53a0b53c114f6fcf4542a28e4a9d3914b4bc76baaa616d6a7ec9efc3f051cb330b682691193e6fa48159208329460c3025fb273232b82450645f2c12a9ea38b53a2331a1d0858813c8bf25a831"
        )],
    },
    Vector {
        slug: "dpapi",
        hashcat: &[
            hc!(
                15300,
                "$DPAPImk$1*1*S-15-21-466364039-425773974-453930460-1925*des3*sha1*24000*b038489dee5ad04e3e3cab4d957258b5*208*cb9b5b7d96a0d2a00305ca403d3fd9c47c561e35b4b2cf3aebfd1d3199a6481d56972be7ebd6c291b199e6f1c2ffaee91978706737e9b1209e6c7d3aa3d8c3c3e38ad1ccfa39400d62c2415961c17fd0bd6b0f7bbd49cc1de1a394e64b7237f56244238da8d37d78"
            ),
            hc!(
                15310,
                "$DPAPImk$1*3*S-15-21-407415836-404165111-436049749-1915*des3*sha1*14825*3e86e7d8437c4d5582ff668a83632cb2*208*96ad763b59e67c9f5c3d925e42bbe28a1412b919d1dc4abf03b2bed4c5c244056c14931d94d441117529b7171dfd6ebbe6eecf5d958b65574c293778fbadb892351cc59d5c65d65d2fcda73f5b056548a4a5550106d03d0c39d3cca7e5cdc0d521f48ac9e51cecc5"
            ),
            hc!(
                15900,
                "$DPAPImk$2*1*S-15-21-439882973-489230393-482956683-1522*aes256*sha512*12900*79f7ca399f2626e21aad108c3922af7c*288*c47bc8a985ca6aa708b01c97b004bff20cc52379dc2635b4acf59ce17970a2cb47ace98c7e8de977f265243c5c03d0a97e4b954b494d9e38d9158d0c1e729d16a28ba69e2e7c6c3bc0e3afc9c9b6306b83372ccb35d89b98925728fd36315b8ee95b4d4eccdcb31564769f9a4b9ee10828184e16d4af336675d5e31d987dd87233d34fbbb98880c5e1f64cbb9b043ad8"
            ),
            hc!(
                15910,
                "$DPAPImk$2*3*S-15-21-464497560-472124119-475628788-1088*aes256*sha512*13450*685165fdb6d0627a15100215ec331ed8*288*7e1ea6f7ec3c2111f2a3903c73aefe66e524d8b241dc1482d0bd07cc1f3ccdadd8cebd4263b3b7c2496da48f40d2eb4890513e6624aeefbe6bbc6ea73f2f71fecf9cc5fef3891a2e697a4415ba7a069642069c142335d53cc750d42a4f4d2b0592956b4a0e57a5d5b1bfd27f0a8eac9d0d5fc5c5e5e23af18ce1a8eff442ed335e5db3bad6e89146f71aa9351e132fd9"
            ),
        ],
        john: &[john!(
            "DPAPImk",
            "$DPAPImk$1*1*S-15-21-466364039-425773974-453930460-1925*des3*sha1*24000*b038489dee5ad04e3e3cab4d957258b5*208*cb9b5b7d96a0d2a00305ca403d3fd9c47c561e35b4b2cf3aebfd1d3199a6481d56972be7ebd6c291b199e6f1c2ffaee91978706737e9b1209e6c7d3aa3d8c3c3e38ad1ccfa39400d62c2415961c17fd0bd6b0f7bbd49cc1de1a394e64b7237f56244238da8d37d78"
        )],
    },
    Vector {
        slug: "keepass",
        hashcat: &[
            hc!(
                13400,
                "$keepass$*2*24569*0*c40432355cce7348c48053ceea0a28e7d18859c4ea47e3a799c6300861f64b95*265dafcc42e1537ff42e97e1e283c70014133be0fe2d420b4d24c6d57c9d2207*a00e20a852694c15aabb074d61b902fa*48dd553fb96f7996635f2414bfe6a1a8429ef0ffb71a1752abbef31853172c35*a44ae659958ad7fae8c8952cb83f3cf03fec2371ce22a8bf7fac1e687af2f249*1*64*5a26ea376cc5afc955104c334571d30486acbac512a94b75ca82a9e31dd97bf7"
            ),
            hc_ambiguous!(
                29700,
                "$keepass$*2*60000*0*02078d460c3c837003f22ee2ba42b3ac2a9ad9e913efb61349b3f91aacd0b004*c901781373cb6806df4b4c7b427ba698440f9e9dd68101e6a198e4a95cb10098*c602f182f8b03671c944a5af357eede7*135443633e6d2b6dba314dee0a1e2b5d0c025ca5fcaf692a20d77fb62cc44f63*51b0b2d19d82c88a0d1a646151be0b68c5e3c841a7a21b4abb2e9be14f298ed1"
            ),
        ],
        john: &[john!(
            "KeePass",
            "$keepass$*2*24569*0*c40432355cce7348c48053ceea0a28e7d18859c4ea47e3a799c6300861f64b95*265dafcc42e1537ff42e97e1e283c70014133be0fe2d420b4d24c6d57c9d2207*a00e20a852694c15aabb074d61b902fa*48dd553fb96f7996635f2414bfe6a1a8429ef0ffb71a1752abbef31853172c35*a44ae659958ad7fae8c8952cb83f3cf03fec2371ce22a8bf7fac1e687af2f249*1*64*5a26ea376cc5afc955104c334571d30486acbac512a94b75ca82a9e31dd97bf7"
        )],
    },
    Vector {
        slug: "keepass4",
        hashcat: &[
            hc!(
                34300,
                "$keepass$*4*2*ef636ddf*67108864*19*2*e4e48422ecb07da38401597150a7326fdd1519007b28c306c6e7418fb8ed29cb*af527945ec56bbb37f84ef85093735b689139f46c8003f82cad269837eb69d5f*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000e4e48422ecb07da38401597150a7326fdd1519007b28c306c6e7418fb8ed29cb0b8b00000000014205000000245555494410000000ef636ddf8c29444b91f7a9a403e30a0c040100000056040000001300000005010000004908000000020000000000000005010000004d080000000000000400000000040100000050040000000200000042010000005320000000af527945ec56bbb37f84ef85093735b689139f46c8003f82cad269837eb69d5f000710000000257fccc1e57ecdea03bbc06aab7cd13200040000000d0a0d0a*63249b86a7539e2bbdbf0ac7f196d460e781e221d1c580d4c718dcc1493eefa9"
            ),
            hc!(
                34301,
                "$keepass$*4*600000*c9d9f39a*0*0*0*824e99f947e7da61a3d2c4b46f59779d46695ea86e3cc6de684dc2106744d630*871b472ef007cd2fb03fae5b802556844e224b021ea058c94382d1f315a6d628*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000824e99f947e7da61a3d2c4b46f59779d46695ea86e3cc6de684dc2106744d6300b5d00000000014205000000245555494410000000c9d9f39a628a4460bf740d08c18a4fea05010000005208000000c02709000000000042010000005320000000871b472ef007cd2fb03fae5b802556844e224b021ea058c94382d1f315a6d6280007100000004131c9acd9c70ac00790dc17059c1b1f00040000000d0a0d0a*6f9ccf175ddd593a654a53fd3ec50f8559fc0abb4acf03b4f2a74353058afb39"
            ),
        ],
        john: &[john!(
            "KeePass",
            "$keepass$*4*2*ef636ddf*67108864*19*2*e4e48422ecb07da38401597150a7326fdd1519007b28c306c6e7418fb8ed29cb*af527945ec56bbb37f84ef85093735b689139f46c8003f82cad269837eb69d5f*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000e4e48422ecb07da38401597150a7326fdd1519007b28c306c6e7418fb8ed29cb0b8b00000000014205000000245555494410000000ef636ddf8c29444b91f7a9a403e30a0c040100000056040000001300000005010000004908000000020000000000000005010000004d080000000000000400000000040100000050040000000200000042010000005320000000af527945ec56bbb37f84ef85093735b689139f46c8003f82cad269837eb69d5f000710000000257fccc1e57ecdea03bbc06aab7cd13200040000000d0a0d0a*63249b86a7539e2bbdbf0ac7f196d460e781e221d1c580d4c718dcc1493eefa9"
        )],
    },
    Vector {
        slug: "odf",
        hashcat: &[
            hc!(
                18400,
                "$odf$*1*1*100000*32*751854d8b90731ce0579f96bea6f0d4ac2fb2f546b31f1b6af9a5f66952a0bf4*16*2185a966155baa9e2fb597298febecbc*16*c18eaae34bcbbe9119be017fe5f8b52d*0*051e0f1ce0e866f2b771029e03a6c7119aad132af54c4e45824f16f61f357a40407ab82744fe6370c7b2346075fcd4c2e58ab244411b3ab1d532a46e2321599ef13c3d3472fc2f14d480d8c33215e473da67f90540279d3ef1f62dde314fa222796046e496c951235ddf88aa754620b7810d22ebc8835c90dce9276946f52b8ea7d95d2f86e4cc725366a8b3edacc2ce88518e535991a5f84d5ea8795dc02bfb731b5f202ecaf7d4b245d928c4248709fcdf3fba2acf1a08be0c1eee7dbeda07e8c3a6983565635e99952b8ad79d31c965f245ae90b5cc3dba6387898c66fa35cad9ac9595c41b62e68efcdd73185b38e220cf004269b77ec6974474b03b7569afc3b503a2bf8b2d035756f3f4cb880d9ba815e5c944508a0bde214076c35bf0e0814a96d21ccaa744c9056948ed935209f5c7933841d2ede3d28dd84da89d477d4a0041ce6d8ddab891d929340db6daa921d69b46fd5aee306d0bcef88c38acbb495d0466df7e2f744e3d10201081215c02db5dd479a4cda15a3338969c7baec9d3d2c378a8dd30449319b149dc3b4e7f00996a59fcb5f243d0df2cbaf749241033f7865aefa960adfeb8ebf205b270f90b1f82c34f80d5a8a0db7aec89972a32f5daa2a73c5895d1fced01b3ab8e576bd2630eff01cad97781f4966d4b528e1b15f011f28ae907a352073c96b203adc7742d2b79b2e2f440b17e7856ae119e08d15d8bdf951f6d4a3f9b516da2d9a8f9dd93488f8e0119f3da19138ab787f0d7098a652cccd914aa0ff81d375bd6a5a165acc936f591639059287975cfc3ca4342e5f9501b3249a76d14e56d6d56b319e036bc0449ac7b5afa24ffbea11babed8183edf8d4fdca1c3f0d23bfd4a02797627d556634f1a9304e03737604bd86f6b5a26aa687d6df73383e0f7dfe62a131e8dbb8c3f4f13d24857dd29d76984eac6c45df7428fc79323ffa1f4e7962d705df74320141ed1f16d1ad483b872168df60315ffadbfa1b7f4afaed8a0017421bf5e05348cb5c707a5e852d6fee6077ec1c33bc707bcd97b7701ee05a03d6fa78b0d31c8c97ea16e0edf434961bd5cc7cbb7eb2553730f0405c9bd21cee09b3f7c1bc57779fdfc15f3935985737a1b522004c4436b631a39a66e8577a03f5020e6aa41952c0662c8c57f66caa483b47af38b8cb5d457245fd3241749e17433e6f929233e8862d7c584111b1991b2d6e94278e7e6e1908cee5a83d94c78b75a84a695d25aeb9fdde72174fe6dd75e8d406671f44892a385a4a1e249f61ebc993e985607423a0a5742e668d52c1ebf5cecae7c2b7908f4627b92ec49354a9ccff8cb5763ad074a00e65a485a41bf4c25ce7e6fae49358a58547b1c0ca79713e297310c0a367c3de196f1dd685ca4be643bdf1e4f6b034211d020557e37a3b6614d061010b4a3416b6b279728c245d3322"
            ),
            hc!(
                18600,
                "$odf$*0*0*1024*16*bff753835f4ea15644b8a2f8e4b5be3d147b9576*8*ee371da34333b69d*16*a902eff54a4d782a26a899a31f97bef4*0*dae7e41fbc3a500d3ce152edd8876c4f38fb17d673ee2ac44ef1e0e283622cd2ae298a82d8d98f2ea737247881fc353e73a2f535c6e13e0cdc60821c1a61c53a4b0c46ff3a3b355d7b793fad50de15999fc7c1194321d1c54316c3806956c4a3ade7daabb912a2a36398eba883af088b3cb69b43365d9ba9fce3fb0c1524f73947a7e9fc1bf3adb5f85a367035feacb5d97c578b037144c2793f34aa09dcd04bdaa455aee0d4c52fe377248611dd56f2bd4eb294673525db905f5d905a28dec0909348e6bf94bcebf03ddd61a48797cd5728ce6dbb71037b268f526e806401abcf495f6edd0b5d87118671ec690d4627f86a43e51c7f6d42a75a56eec51204d47e115e813ed4425c97b16b195e02ce776c185194b9de43ae89f356e29face016cb393d6fb93af8ea305d921d5592dd184051ac790b9b90266f52b8d53ce1cb1d762942d6d5bbd0e3821be21af9fa6874ba0c60e64f41d3e5b6caca1c53b575afdc5d8f6a3edbf874dbe009c6cb296466fe9637aed4aed8a43a95ea7d26b4090ad33d4ee7a83844b0893e8bc0f04944205fb9576cb5720f019028cd75ca9ac47b3e5fa231354d74135564df43b659cfaea7e195c4a896e0e0e0c85dc9ce3a9ce9ba552bc2a6dbac4901c19558818e1957ed72d78662bb5ba53475ca584371f1825ae0c92322a4404e63c2baad92665aac29b5c6f96e1e6338d48fb0aef4d0b686063974f58b839484f8dcf0a02537cba67a7d2c4de13125d74820cb07ec72782035af1ea6c4db61c77016d1c021b63c8b07adb4e8510f5c41bbc501f60f3dd16462399b52eb146787e38e700147c7aa23ac4d5d22d9d1c93e67a01c92a197d4765cbf8d56a862a1205abb450a182913a69b8d5334a59924f86fb3ccd0dcfe7426053e26ba26b57c05f38d85863fff1f81135b0366e8cd8680663ae8aaf7d005317b849d5e08be882708fa0d8d02d47e89150124b507c34845c922b95e62aa0b3fef218773d7aeb572c67b35ad8787f31ecc6e1846b673b8ba6172223176eabf0020b6aa3aa71405b40b2fc2127bf9741a103f1d8eca21bf27328cdf15153f2f223eff7b831a72ed8ecacf4ea8df4ea44f3a3921e5a88fb2cfa355ece0f05cbc88fdd1ecd368d6e3b2dfabd999e5b708f1bccaeebb296c9d7b76659967742fe966aa6871cbbffe710b0cd838c6e02e6eb608cb5c81d066b60b5b3604396331d97d4a2c4c2317406e48c9f5387a2c72511d1e6899bd450e9ca88d535755bcfddb53a6df118cd9cdc7d8b4b814f7bc17684d8e5975defaa25d06f410ed0724c16b8f69ec3869bc1f05c71483666968d1c04509875dadd72c6182733d564eb1a7d555dc34f6b817c5418626214d0b2c3901c5a46f5b20fddfdf9f71a7dfd75b9928778a3f65e1832dff22be973c2b259744d500a3027c2a2e08972eaaad4c5c4ec871"
            ),
        ],
        john: &[john!(
            "ODF",
            "$odf$*1*1*100000*32*751854d8b90731ce0579f96bea6f0d4ac2fb2f546b31f1b6af9a5f66952a0bf4*16*2185a966155baa9e2fb597298febecbc*16*c18eaae34bcbbe9119be017fe5f8b52d*0*051e0f1ce0e866f2b771029e03a6c7119aad132af54c4e45824f16f61f357a40407ab82744fe6370c7b2346075fcd4c2e58ab244411b3ab1d532a46e2321599ef13c3d3472fc2f14d480d8c33215e473da67f90540279d3ef1f62dde314fa222796046e496c951235ddf88aa754620b7810d22ebc8835c90dce9276946f52b8ea7d95d2f86e4cc725366a8b3edacc2ce88518e535991a5f84d5ea8795dc02bfb731b5f202ecaf7d4b245d928c4248709fcdf3fba2acf1a08be0c1eee7dbeda07e8c3a6983565635e99952b8ad79d31c965f245ae90b5cc3dba6387898c66fa35cad9ac9595c41b62e68efcdd73185b38e220cf004269b77ec6974474b03b7569afc3b503a2bf8b2d035756f3f4cb880d9ba815e5c944508a0bde214076c35bf0e0814a96d21ccaa744c9056948ed935209f5c7933841d2ede3d28dd84da89d477d4a0041ce6d8ddab891d929340db6daa921d69b46fd5aee306d0bcef88c38acbb495d0466df7e2f744e3d10201081215c02db5dd479a4cda15a3338969c7baec9d3d2c378a8dd30449319b149dc3b4e7f00996a59fcb5f243d0df2cbaf749241033f7865aefa960adfeb8ebf205b270f90b1f82c34f80d5a8a0db7aec89972a32f5daa2a73c5895d1fced01b3ab8e576bd2630eff01cad97781f4966d4b528e1b15f011f28ae907a352073c96b203adc7742d2b79b2e2f440b17e7856ae119e08d15d8bdf951f6d4a3f9b516da2d9a8f9dd93488f8e0119f3da19138ab787f0d7098a652cccd914aa0ff81d375bd6a5a165acc936f591639059287975cfc3ca4342e5f9501b3249a76d14e56d6d56b319e036bc0449ac7b5afa24ffbea11babed8183edf8d4fdca1c3f0d23bfd4a02797627d556634f1a9304e03737604bd86f6b5a26aa687d6df73383e0f7dfe62a131e8dbb8c3f4f13d24857dd29d76984eac6c45df7428fc79323ffa1f4e7962d705df74320141ed1f16d1ad483b872168df60315ffadbfa1b7f4afaed8a0017421bf5e05348cb5c707a5e852d6fee6077ec1c33bc707bcd97b7701ee05a03d6fa78b0d31c8c97ea16e0edf434961bd5cc7cbb7eb2553730f0405c9bd21cee09b3f7c1bc57779fdfc15f3935985737a1b522004c4436b631a39a66e8577a03f5020e6aa41952c0662c8c57f66caa483b47af38b8cb5d457245fd3241749e17433e6f929233e8862d7c584111b1991b2d6e94278e7e6e1908cee5a83d94c78b75a84a695d25aeb9fdde72174fe6dd75e8d406671f44892a385a4a1e249f61ebc993e985607423a0a5742e668d52c1ebf5cecae7c2b7908f4627b92ec49354a9ccff8cb5763ad074a00e65a485a41bf4c25ce7e6fae49358a58547b1c0ca79713e297310c0a367c3de196f1dd685ca4be643bdf1e4f6b034211d020557e37a3b6614d061010b4a3416b6b279728c245d3322"
        )],
    },
    Vector {
        slug: "apfs",
        hashcat: &[hc!(
            18300,
            "$fvde$2$16$58778104701476542047675521040224$20000$39602e86b7cea4a34f4ff69ff6ed706d68954ee474de1d2a9f6a6f2d24d172001e484c1d4eaa237d"
        )],
        john: &[],
    },
    Vector {
        slug: "android-backup",
        hashcat: &[hc!(
            18900,
            "$ab$5*0*10000*b8900e4885ff9cad8f01ee1957a43bd633fea12491440514ae27aa83f2f5c006ec7e7fa0bce040add619919b4eb60608304b7d571a2ed87fd58c9ad6bc5fcf4c*7d254d93e16be9312fb1ccbfc6265c40cb0c5eab7b605a95a116e2383fb1cf12b688223f96221dcd2bf5410d4ca6f90e0789ee00157fa91658b42665d6b6844c*fc9f6be604d1c59ac32664ec2c5b9b30*00c4972149af3adcc235899e9d20611ea6e8de2212afcb9fcfefde7e35b691c2d0994eb47e4f9a260526ba47f4caea71af9c7fadcd5685d50126276f6acdd59966528b13ccc26036a0eaba2f2451aa64b05766d0edd03c988dcf87e2a9eec52d"
        )],
        john: &[john!(
            "AndroidBackup",
            "$ab$5*0*10000*b8900e4885ff9cad8f01ee1957a43bd633fea12491440514ae27aa83f2f5c006ec7e7fa0bce040add619919b4eb60608304b7d571a2ed87fd58c9ad6bc5fcf4c*7d254d93e16be9312fb1ccbfc6265c40cb0c5eab7b605a95a116e2383fb1cf12b688223f96221dcd2bf5410d4ca6f90e0789ee00157fa91658b42665d6b6844c*fc9f6be604d1c59ac32664ec2c5b9b30*00c4972149af3adcc235899e9d20611ea6e8de2212afcb9fcfefde7e35b691c2d0994eb47e4f9a260526ba47f4caea71af9c7fadcd5685d50126276f6acdd59966528b13ccc26036a0eaba2f2451aa64b05766d0edd03c988dcf87e2a9eec52d"
        )],
    },
    Vector {
        slug: "ecryptfs",
        hashcat: &[hc!(
            12200,
            "$ecryptfs$0$1$4207883745556753$567daa975114206c"
        )],
        john: &[john!(
            "eCryptfs",
            "$ecryptfs$0$1$4207883745556753$567daa975114206c"
        )],
    },
    Vector {
        slug: "multibit-hd",
        hashcat: &[hc!(
            22700,
            "$multibit$2*2e311aa2cc5ec99f7073cacc8a2d1938*e3ad782e7f92d66a3cdfaec43a46be29*5d1cabd4f4a50ba125f88c47027fff9b"
        )],
        john: &[],
    },
    Vector {
        slug: "itunes-backup",
        hashcat: &[
            hc!(
                14700,
                "$itunes_backup$*9*ebd7f9b33293b2511f0a4139d5b213feff51476968863cef60ec38d720497b6ff39a0bb63fa9f84e*10000*2202015774208421818002001652122401871832**"
            ),
            hc!(
                14800,
                "$itunes_backup$*10*17a3b858e79bc273be43a9f113b71efe7ec8e7e401396b350180b4592ef45db67ffef7b2d64329a5*10000*2721336781705041205314422175267631184867*1000*99fafc983e732998adb9fadc162a2e382143f115"
            ),
        ],
        john: &[john!(
            "itunes-backup",
            "$itunes_backup$*9*ebd7f9b33293b2511f0a4139d5b213feff51476968863cef60ec38d720497b6ff39a0bb63fa9f84e*10000*2202015774208421818002001652122401871832**"
        )],
    },
    Vector {
        slug: "sshng",
        hashcat: &[
            hc!(
                36800,
                "$sshng$6$16$89b7dac5965613fa4f2faf9284983843$274$6f70656e7373682d6b65792d7631000000000a6165733235362d63747200000006626372797074000000180000001089b7dac5965613fa4f2faf92849838430000001000000001000000330000000b7373682d6564323535313900000020979ccdbbb3f2c8b04842e77fdd5475b21963e7ddad9a4d029d712322f5c930ee000000909e38aa2f92ae189f7e4f04ef62fcd869ceb572e5c047ea0e9dfbb4657c38a13506d580ff8709a8787810a53688e3b0c7b7af155422aed8089da87a63da0147d8c8e04a6d236e70f0c6be5fbeb0b620d7abe928b10169fd3e48c1b526d3ead3a28fa4385969aebea6621baada8821a20035be97e2fa42575f5e4246e174ac3c96b19e89623ff267a2629090da6f79f7e4$16$130"
            ),
            hc!(
                22911,
                "$sshng$0$8$7532262427635482$1224$e1b1690703b83fd0ab6677c89a00dfce57fc2f345ebd2b2993bf0d8bb267449d08839213dc234dd23c7a181077e00080ced2700a161c4352ce5574b9758926f09106157715b6d756cf6dd844e473c6bb3c2b591cdbf684394a49935f7d62bcc324c1392aee499e3d6235db0556d27adc6e35ef4654ee5fc72e60dff605484e75c6fd6ae29cb476f8a658dbcce9f9591a9dad023f6d9aa223c3d56261e056c5cafa93438937e0762b989cd10e6280a09488be07423c549514ff9686338e72dbe6bdc5015944739a9f183cacf04c1c141dc8c8d8aa8636c85a6c0578a5983ed33d5ff5ee6a66a54d86defd1c4f9d6a59446861bf4cc7bd667bc92b9d328c154f442d1d03d4d370dcc065a1d5420c5b71e4c35a457e11a0c9f489636559a2ac53bb4cfee2b0058f8a9d1ccc38a844ee0d1ff5d6938427bf24d6e4c69f10e6ebce9187d51e867ac3b362b9c6149712e8378a9ac91d1aab1a7a5f088ddbdead0cc754c30961b7a71284b5c6658f7219632de6007d5145a1ae062f807234230ff73a3436ce28ae3bfa0f880d1e49ec8a288da18db14905bc7a7b061a51c429876db81ad528efb469ba2bf46c7344aadc7d082efc83ede3894bf6b1738151e642f6f60a41069ad862d2f4f8d55733bd6d85086d1d9bb1913a9d4680ea0b49f712c590a3c18b91ef745b9bdf461af67879d94f9672de4abe0b7d2e4efba1f8bb6ffbb4a095742d5cff0e225b1b5e166854bb9821e4283d97f80855c81efea1eb3e7881a6049186650bfbf68f30302c069883668e373c12ce9a39de8d7c1be22a717d9c74410c45093aae03c5de8cc0ec662fe3bb81bf952e17b854001bcad9b36cab2f473a609878a419b735c66f3732bd5540fb1cba9fe081f87cecf63a6243cd2049dfa25a763ef2e0633bfb13a411207d8ca1c8f3c0c30b8a7583436cad7bd8c28ba625b9c53dc280b314671b0a55d75a28d3b21de250e3c554b86ca5d32821ab912c6607687c4dc5b3214216a7409621ce6fb89bd5309a7dd8ec9ae4b751bdfb6b5d12d733a89d87722dbdb1b15df5463241f0f56c401e095ea5dee07c0ded1f11ffbd7c93a41add0cfd8c57b44f255fdfd1929cd7d068d6cf951ba8ab0d718996fec10aaa26a4314d4c1272f744adf3c7e4d710ae171c072a7c61c2b020a445cf32be3083d3bc62083f2385bbae4fadddf8714258b996abd574638891bb918e877fdef3a4856b910999a6dc9dbd13c0e938825cd895c96d39cb86bb283a53fac7090c71a9320c6a34af309d2218af64c895f5eff8eee28cf94e7a7437a0922d83bfa39f08bb40e354d9ace07aa586a446dc217ede98b6ca9637545cc11ef56732fc9cd3dc06e459d868137b75d39a87e6721a95f2b84e57c94ef703486a2857821e497b990c95080015d825b6dc63d666f66cfa35912e607c3b650d81dc98c0c53322796ff9249cdfe7a375e1d01607816a85bb43f3969767a9aaed07161344e714d7e875b40f3524f95e476e605dbd2ac51e36075701fa93b66f36470796ebf5d35690a297e19729f9ac59d98622e3ad3e45a2914bdd2b807446c8b430e54c1a607fd25a69bf469a61d2e3bc3697b786c047bc60dbeabe6372d71e9b7c9787bb2559c663a011f864ecf32793e65f4bdd76370d99f602ddcbc7e5aa7d2749f36e8d0f209a378782882bc06ee5b5014c2a6248469f0fe0fc5369383db0bc898c0760b8c40fe20342fa5b"
            ),
            hc!(
                22921,
                "$sshng$6$8$7620048997557487$1224$13517a1204dc69528c474ef5cbb02d548698771f2a607c04ea54eb92f13dedba0f2185d2884b4db0c95ce6432856108ea2db858be443e0f8004ffcd60857e4ff1e42b17f056998ec5f96806a06e39cc6e6d7ef4ce8ae62b57b2ec0d0236c35cf4bc00dd6fda45e4788dcca0f0e44dddae1dad2d6e7b705d076f2f8fc5837eec4a002d9633bcad1f395ca8e85e78459abe293451567494d440c3f087bb7fe4d6588018f92ca327dda514a99d7b4b32434da0e3b1bf9344afb2fe29f8d8315a385fe8b81fd4c202c7d82cd9f0bb1600e59762ab6ea1b42e4e299f0a59ce510767e1e1138453d362d0a1aa6680e86b5aa0bd5c62165f4fe7c2867f9533578085adc36739d6c9cf7b36899aac39dcabac8b39194433423e8e18ba28496bbe14dd01231eb5b091ae9de0f7f9ea714c22edac394077fb758fe496e1880571ade399ac229457ddd98577f8a01a036ad3bc8b03a9fb02e26b4b76f6cb676eabe82d1606fca0c5fca62cd1d82c3df1ed58ab4acd4611b2827ebde722bc05e471a427225818aa36dabf5bf1203ccb0ebc8dec097e49f7f948bfe7b939e6d0ff1125b863c033768f588964f8b77ca1e2425751f873f80e5d6a0671f7860cf4a46533585094726c3afe5f7203fa4a01650fa9839772c713a033139cfc6a6e6f7dc62e5844d4c57ef4fc3321bc85d597a54bd6fe37e9e696cf3b5ec66f55232e0964dc5cf880d8a41a9891150618bd9c088fd9824af0d86f817f2c79429c3d56cd6eb41eb6120f9accc10a863f23a2bb6c57d4bd6193f2283ae0215e2e87e672a8438e2550c044fa9556bdb4afc40d8c2752ffbc6c95571756a3c230bb2fa95f519f8da238ef0857ecf860247a8b26e28269f9bad564e7d8bfba2eac9760b52449251cb35e183f5b309a09071535154c6f1013b58f305b544f3589c9eb0e9ac4267a84374a3eab49c53aa9bedbf97f8f19ebc212d8db74ee03554a3514140667fa4ce8e06aad3f32d1b00015be0e8979fe66736018589beee06d6f318851dbe8d9689e70202185d71fc5e5a3d2996ddb8ae1d7718c49855c6f8c43301e0915f324f30d0d9c6a8504a91ad5a7179aafb87ede58598394949910874850994abe815817359152ff6a7c8cc6f19524dfc5e50ddfd038a2275bf809e3c8f05ed3e3137ebd62d91cd3578533787c3847e3c5e07e5a891480e5ceabcf6c344e7bec8b640ab9a03e90b846b35d2f46ba150accef32d2597b064810b15fd54fca6d2b146feabcd05c0b51617ae95e36f6817a62c3ff42c5c2f6f1d20a8a1fd334d3b7d3f83bba057b79d9b5508bb0cb706ba00acb0ab797401fdcfac80b5b6e38e51aec0b38f33ff4690425ca28d88a2e876591521230150b4e20a4a82e50061cee9c0705100bfe5fdbd8ef27aec20387cf32455ef305bce2a91ae6da91fc41376b97149e9b41c901b24811df9272ff09718923b8d94e8e459a164a22b0eca47653f3efcbf08188c5da78cd9fb9eda1761094f9d8bc3d479e9f40c7d79ebaaba2a5c632329f20a9962040ff8f512b42c5f32a8460d87b8e93c6f980a1562c436eea1c8994fbf671dda3c4ccd3c142acfcdde2ab61227289ad408213ac8e22d9ef487f36925f5ba3b8e7e913d25c4a8592c861d13f03b615bc2760aabc61d68db80d35296a3312fdf4b56c0fbee5ab3fea1cf9caf3960a564046939e8002d2dd909db446d85aeae9dd42a33fe28684f722172e6"
            ),
            hc!(
                22931,
                "$sshng$1$16$14987802644369864387956120434709$1232$ffa56007ed83e49fdc439c776a9dec9656521385073bf71931a2c6503c93917e560cc98940c8cdcf2c709265e9ba20783a3bacc63423a98e40ea8999182613e1f5a80084719ca0e5c390299de1ea947df41f2ff1489bddfe13c6128612c5c82b7fc1ef5105ea28adda7b415729c66fb6cbc4b6b51ef518f74e1971f88e0cfabd69e8c4270678e360149ce15716fef4736df296a20d2607ef269a3c69896fc423683d6057e00064f84e04caf4d4663b51b307cfb1d1dbd6b3bf67764a08847c7b83fa5544e6a1e950f16acda8c8bac30675bc3cea9c7e06790ddc7cd1e4177b93bdd0d9edf9cdceb4a4444b437d967acdb92274a7b10d9cd1073ab4e9b5dd468aabe1f40a02b2e51f19840798c2311b625037eba5f0a0256638b42577385f4d4c730a9cedf4e244ce74656a21bf16756857866433dbb1feff9c4323d234d4235b72ed5a3adc3a6c9bae373472d64b7882d1762911326f330cb42d8ab7931f1ad2de56c4e6e8a6e838108cf9a2728ffa356796f63d94723b1d0aad5b4fcea16ab0730e7553804ad9ffb6ecdbdd925fca05ca1c076ed09a30df8a5add44a43c36b92248dc8dd4605bc2ee557e6e4438abf9ea7d047f764c55a5ba46a41719b9c55e54ad5fbfce6a89b9283c163d8464ecdda5aaf113d038b659950b8c79e87abad019eb77535cc8e63f760a4c87ca344a563475361766df718519b1b7e4b3ab511952fcc9b011f1d8971f9261509139b739afcc2c9acd006ee714dffc8c9a4df0d54770d70c8c28c27cdf9ee7301fd64530ef0ec3eb044fb891b193a7aaa9158625ed9f5a842c86ed09e5377d90a69aea4c5fd321bc3ac9b2a0d34509a5de0b72ac3f81304895c4381e01136b1e8654cec20c220c0ac6a1300f031ffc68ddeab554279024c122589b91556feef394a1663b42fb8460af5fe881cb1cd4984b84be75125411b1d3fc236dd81f99b872aad511d28944e91d2f8853f11be85b6930a15b4d0b3d215d76416970ade5726979c1d737980fb68ecb03d1196a69f4013dd2e296a75a4c69664b0162cb8b22af18c536a8ce51f39b1282f2fe07e6b034627f075cfb20dffee62817aabeea60befea1ac93ba608d957e4030e41be7bc55275bc4037300f6ba736370eb7c9240629853c95f9304b7ffd26a10d55ae735fa943e29aa9ed437b61955fc16cde9ea7a3658d831bdbc38befa45cec80da9ccb6d21da83ff666e32d7c5c0ca0ade2cd685407ee701c1c707fc5c80b22f3af42ac1353fcdc09a459086434db7c78792decdc91572363478a14d1256346a9ac6336b8183ed6252106aa546dd092c0bbb464cdb44ae165d67d1be135877587de3bbbd02b5ef6473f125366f6dae0536ebbe18ab8de8ce2ef3d26d6dd400319e7d07ae276b081e94446e9a72877cf23e9ba52406b1842e3a0dcf7bbdc63a1336b894be475613cc917eb47724f64e621bfc3053d7423e3e2fb141a3368dc8881fa20e040e9a6bc2e7348e923e4c20e506566b8663bf7d557e792cbe4adffcf9c520d58565d77f6bf1c9ed5fa3209f8047765d01b9c264e97a3ef9ff90766ad69a4f508041e168bf0f7419e54ec88bdc4c858231cdba60774a27cc459cd65b46e26a620a43033788c6e2ee8916670568d6e6c700515f2cbca3eef62028ce75245cf8f99cd6e0ba7839a7b335c797a06ff80571950ebec2fccebb89265025b3250e4a5c9c3a62f471324556fc4db044cebe97f62c86913"
            ),
            hc!(
                22941,
                "$sshng$4$16$01684556100059289727957814500256$1232$b04d45fdfdf02a9ca91cbc9c53f9e59956822c72c718929aca9251cffd9ac48e48c490b7b6b6043df3a70cf5fbcc2f358b0e8b70d39155c93032b0fd79ec68f6cb8b7de8422ec95cb027a9eaacc453b0b99b5d3f8d6771d6b95b0242a1d8664de8598e8d6b6d6ee360fda5ae0106061a79e88ef2eef98a000b638f8fdc367155ec2d1120b366f74f0933efe5d174e7107db29dc8fb592b22b9837114415d78036c116b2d31b2080c7159442f2d1a61900f5ae4913548c8e7fc716dd4f812bc7e57b2dd5d3f56c6ae0e91c3bc2897d9341cb282d86b915d43cf20ad16fbd2056104529576142354a430281f5e458923ef8014ff9950351798bfcbbcb66cb98bb2cccea48c134b0e05e978d4308c82617869b207f0ed7b227893f2cdde2d6b6a98246de8a2494d5e018a84724780fbe8d1fa91c922908d18ccffbbbbc81e6578fe8bb5c8596a8cf689f3f12b810dee95887e12439e487313229a37913e3cd12bddba3bac94fab03aad8607f6034fa87f7a7a2ac74d0c0a6e6bc905f569221861e1e388cf379cda799d7b56eac58440d17fe97fa68a537d34317376c00dfa9a99e04725a0d2fcf27ee50463e725813c96fe2eed16de59e8a6944d903e11f7923d57ae6d4a1f8085ce19f4d180f13027806f3965fdf875ea092f103f28a5f42f356254958fa7eb0bca2389a6ad4e305640cc64501e6b16330b063037b1cf6fe64131f308e50d9d1dc687ffa487681941084ff21cb54c1b5903b7a78d9913595fa0124f1dde49b1bee2ea83837efe34e2cd6051a4a7a1437eaa84ad332ffd9946b952ed634948789d9541820a0f9c6f44ab6d3cad645743c76c54e79bfdc4fb8e43a0fd7d871baea98e78131bc530b6d736fa1ec5ac70438609497ab2ff8d516146b4b1b3488791cb84dccc0096b570e2ffb3a93cccefec0af7ce616a64466d2d4196941ba9e051dc00ed05e963a7b4a286973ee0b5df4fd92dfb0b229b10730d454832d945c6a596862212d109ce78ac14ffb5d775548b2f3e2ae4be059a24465cc10b7c810f8cc3db7cb327619cc104ebea575ac097d20701dc623f7aa893b785cc20851f3972390e00ab3355655f7d5bea323832c17d8e078e917843ef7fcaca349366092b6743bf7511d5fceb2d992fbd18574be532365be41ad80a114704a64a7aefdf98c907aa10e4d5c547dd8d21647ea9d5c975fe1b24525d94c3eb03e071742fd5f09f22da669b649fac9f87d8cf16c475d006421f69a9b2d5c4037ccc9bf9f0aa0e7df8ac5fcb0d88a528833f9640799026d2fe8694fa1a0307c5f24002172464b290bedd85667800edbff2f1de7119e5b65730a24922e42d53ef28b0a59817a298426dc72e29a85e59e3d777b19eb934bcd620a903aff72927cdbe7253f77694ab0ef970378b4347f6166ca2a40b23cc31970f0cbefd08d2d72bf2c3961d67c73a5a24f75a65e540dc5735520b0d81250af8980ddca3e22a9b25773afd27c76e564ff437d4208df14d802f1d0848390f45924cdd6ced3c9ffb726bb358b334ea0e0481acdd103f2db05f508f62588621d0b8fa274a69eba0d418d85086d9139391f7e28dc54fe9bab801f1fea854f27ad2e5907ae6f9a4b4527d16a8af3c8cbe2c6d82209dc6c7da060da58294eb00380598330c4c19d45581d09e04c0153a8559700b3a8ceab9b8124f84d397356cd9e38e3916afc1f63a3e1dfbc7df8dd0a7d0704e38a0ea523dfc2b9defd5"
            ),
            hc!(
                22951,
                "$sshng$5$16$52935050547964524511665675049973$1232$febee392e88cea0086b3cdefd3efec8aedb6011ca4ca9884ef9776d09559109c328fd4daef62ea4094a588d90d4617bc0348cc1205ae140e5bdca4e81bf7a8ff4fcc9954d3548ba9a0d143a504750d04d41c455d6100b33dacc5f9a10036ae75be69a81471e945554a52ca12b95640a08f607eab70c4a750dc48917f3c9ee23c537e9b4a49728a9773a999dfd842cf9a38155029ea5d42f617dbec630889d078ffadaf3ff28eed65389a73528f3d0863fffd9a740edd59ca223595e330bca37ac5a003ac556d2b6232f9900fc8654586e73e7b2d83327d61b2fc561a78aacc8aff473bb3d18ddccae87d84de143a8a98550d955d01d4e6074ac62aa0af0bca58a0c53d0d7cf1a26345c1bd3eca7a0c0e711f5c7f942d50bc872be971d0c17dbc5a88f043a937ff5d28c5ef8d8d291e511d070b14a0cc696ee5088a944b113bc7e697cdc793e931c3f0f3a892b44aad1468e6c45becdcaa89febda17fcd5fe6ff430695e04b5b6271e032e3529315367e56337777a5b342c19d3ebc7441ac0f79b93749ad4526b8be0a5cf5756363aac93da6dc19dbfff15bacbbf2dae7a549afdab8e0589321ac0a612576bbfe06fde086075d1244450a3667f793ccc81fd5ccc5b1d08e6f447e3e0cd89b901049bedb1e65b23ede0d8f00ff1c984743b50342c50408e9060ed6a809a7b068972c9542cd91de0767c02a73d192ea600008bf4a6ef339c7f2db767346cc479e61abedb4ba4a67f72e91ac49a2e92bb4bacd97aed0b044c258e2004fa0fb8da3678a57d37187c1246c90a107540161462145fa7307a6d4db34694fb1b090f07bedb9ca0e71aefd3ce5601b87778fd6b66391c3c61d528a5965f91370f52a72f0622620329f96c5dd68561e0f6576f3a2bc5c21a95aed569edc4ed979746b32909178e550907c5f41d7b24480e81a874b931c23f13517ab5f9331f11819d982bf9e5b8a03034b47c8785f8902611eac26716976bccd51d19864f10ee1fbd62f8b0149c22ab06205a20f9f9fcb0a5279552a8923c3ace2e134f6b190653f430c1a4b82f762283028d9c0c8d1a3428731f4f405f40f947f297a43aa3ba2267bbc749a5677da92a63d51d24aa5ca3e9e1d35a8143d7b4bac481f0c56754e980a60cf2d330797fc81f6c6f405760f1257103ac6edf10976c9005f4a261f7aad055400c4f18dc445eb3a403740ad6c58afa4e8edb30fad907488baf0ede2eb3d3687d1e8724dd69c7bd14b90d4f113fc9f84a2c01ab00917f53cd879a4031b1c91a4d4d7d9e712a584959137001d331f6725dca81ea6cc55fac7fc0e8b578dec0983ca98c3789cdf83507e4c3ba056fdcbea26693a313077290d7c6695f4cc6de4848532f0149cc06dbf4c76d02944178520585923b636196ea2cbcacc43950b308fc7929e85de076a2ab65c9bd8ebb0c04c041281178a48d8d2165d315b3e74abf0a38505b71ae5b2a6e7f87861e174cff873a1f61980b53ef3acdd2ea6a25425b162e5dc0bc1aa2992585d2da1625a6593cc2d4fe8c86eeb4df0e27cda54685f7245e5c48063d489e8d93bd5303bebe633139dcdd04afa005d03d1185a64e8711c0b09d9d0b38b35d6ef1b1e35353a7a4396863650a3843c687a00396dd3db53e8d28baf29101abb9f628ba896b091618f24187f6eeb814e4b64130768fb37e89b9b3230e50a7e5aba852a983525c8f193deb1fe27b334cdc3bdfa4c301d04907ee29a848393"
            ),
        ],
        john: &[john!(
            "SSH",
            "$sshng$1$16$14987802644369864387956120434709$1232$ffa56007ed83e49fdc439c776a9dec9656521385073bf71931a2c6503c93917e560cc98940c8cdcf2c709265e9ba20783a3bacc63423a98e40ea8999182613e1f5a80084719ca0e5c390299de1ea947df41f2ff1489bddfe13c6128612c5c82b7fc1ef5105ea28adda7b415729c66fb6cbc4b6b51ef518f74e1971f88e0cfabd69e8c4270678e360149ce15716fef4736df296a20d2607ef269a3c69896fc423683d6057e00064f84e04caf4d4663b51b307cfb1d1dbd6b3bf67764a08847c7b83fa5544e6a1e950f16acda8c8bac30675bc3cea9c7e06790ddc7cd1e4177b93bdd0d9edf9cdceb4a4444b437d967acdb92274a7b10d9cd1073ab4e9b5dd468aabe1f40a02b2e51f19840798c2311b625037eba5f0a0256638b42577385f4d4c730a9cedf4e244ce74656a21bf16756857866433dbb1feff9c4323d234d4235b72ed5a3adc3a6c9bae373472d64b7882d1762911326f330cb42d8ab7931f1ad2de56c4e6e8a6e838108cf9a2728ffa356796f63d94723b1d0aad5b4fcea16ab0730e7553804ad9ffb6ecdbdd925fca05ca1c076ed09a30df8a5add44a43c36b92248dc8dd4605bc2ee557e6e4438abf9ea7d047f764c55a5ba46a41719b9c55e54ad5fbfce6a89b9283c163d8464ecdda5aaf113d038b659950b8c79e87abad019eb77535cc8e63f760a4c87ca344a563475361766df718519b1b7e4b3ab511952fcc9b011f1d8971f9261509139b739afcc2c9acd006ee714dffc8c9a4df0d54770d70c8c28c27cdf9ee7301fd64530ef0ec3eb044fb891b193a7aaa9158625ed9f5a842c86ed09e5377d90a69aea4c5fd321bc3ac9b2a0d34509a5de0b72ac3f81304895c4381e01136b1e8654cec20c220c0ac6a1300f031ffc68ddeab554279024c122589b91556feef394a1663b42fb8460af5fe881cb1cd4984b84be75125411b1d3fc236dd81f99b872aad511d28944e91d2f8853f11be85b6930a15b4d0b3d215d76416970ade5726979c1d737980fb68ecb03d1196a69f4013dd2e296a75a4c69664b0162cb8b22af18c536a8ce51f39b1282f2fe07e6b034627f075cfb20dffee62817aabeea60befea1ac93ba608d957e4030e41be7bc55275bc4037300f6ba736370eb7c9240629853c95f9304b7ffd26a10d55ae735fa943e29aa9ed437b61955fc16cde9ea7a3658d831bdbc38befa45cec80da9ccb6d21da83ff666e32d7c5c0ca0ade2cd685407ee701c1c707fc5c80b22f3af42ac1353fcdc09a459086434db7c78792decdc91572363478a14d1256346a9ac6336b8183ed6252106aa546dd092c0bbb464cdb44ae165d67d1be135877587de3bbbd02b5ef6473f125366f6dae0536ebbe18ab8de8ce2ef3d26d6dd400319e7d07ae276b081e94446e9a72877cf23e9ba52406b1842e3a0dcf7bbdc63a1336b894be475613cc917eb47724f64e621bfc3053d7423e3e2fb141a3368dc8881fa20e040e9a6bc2e7348e923e4c20e506566b8663bf7d557e792cbe4adffcf9c520d58565d77f6bf1c9ed5fa3209f8047765d01b9c264e97a3ef9ff90766ad69a4f508041e168bf0f7419e54ec88bdc4c858231cdba60774a27cc459cd65b46e26a620a43033788c6e2ee8916670568d6e6c700515f2cbca3eef62028ce75245cf8f99cd6e0ba7839a7b335c797a06ff80571950ebec2fccebb89265025b3250e4a5c9c3a62f471324556fc4db044cebe97f62c86913"
        )],
    },
    Vector {
        slug: "bitlocker",
        hashcat: &[hc!(
            22100,
            "$bitlocker$1$16$6f972989ddc209f1eccf07313a7266a2$1048576$12$3a33a8eaff5e6f81d907b591$60$316b0f6d4cb445fb056f0e3e0633c413526ff4481bbf588917b70a4e8f8075f5ceb45958a800b42cb7ff9b7f5e17c6145bf8561ea86f52d3592059fb"
        )],
        john: &[john!(
            "BitLocker",
            "$bitlocker$1$16$6f972989ddc209f1eccf07313a7266a2$1048576$12$3a33a8eaff5e6f81d907b591$60$316b0f6d4cb445fb056f0e3e0633c413526ff4481bbf588917b70a4e8f8075f5ceb45958a800b42cb7ff9b7f5e17c6145bf8561ea86f52d3592059fb"
        )],
    },
    Vector {
        slug: "blake2s-256",
        hashcat: &[hc_ambiguous!(
            31000,
            "$BLAKE2$2c719b484789ad5f6fc1739012182169b25484af156adc91d4f64f72400e574a"
        )],
        john: &[],
    },
    Vector {
        slug: "blake2b-256",
        hashcat: &[hc_ambiguous!(
            34800,
            "$BLAKE2$68b163391b3e779dcddba4e6d8fa03e962c29569b430efa5ba014303358557e1"
        )],
        john: &[],
    },
    Vector {
        slug: "sm3",
        hashcat: &[hc!(
            31100,
            "51227e48ea74827b77fc142c3ec21d25cc42c794e6ac422825cd47ad4ac7913d"
        )],
        john: &[john!(
            "Raw-SM3",
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        )],
    },
    Vector {
        slug: "as400-ssha1",
        hashcat: &[hc!(
            35200,
            "$as400$ssha1$*QTEST1*7ED7D3694D0A2E40A720D41031B456C09124966E"
        )],
        john: &[john!(
            "as400-ssha1",
            "$as400ssha1$4C106E52CA196986E1C52C7FCD02AF046B76C73C$ROB"
        )],
    },
    Vector {
        slug: "salted-blake2b-256",
        hashcat: &[
            hc!(
                34810,
                "$BLAKE2$2b51353016a512b60e587bea98d799c2de243468085ca6cd67f983b2e55bfb67:2353288289"
            ),
            hc!(
                34820,
                "$BLAKE2$a4cad0b026ed24adf13fb70ec31d35b02751dcb33354e2c9d20ef3f968748501:3601"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "werkzeug-md5",
        hashcat: &[hc!(30000, "md5$84143$7f51edecfa6fb401a0b5e63d33fc8c0e")],
        john: &[],
    },
    Vector {
        slug: "werkzeug-sha256",
        hashcat: &[hc!(
            30120,
            "sha256$70108387805$8b9472281c36c3a693703de0e0f1ffab8fc0ecdd3bc5ead04c76dd74ef431e49"
        )],
        john: &[],
    },
    Vector {
        slug: "anope-sha256",
        hashcat: &[hc!(
            30700,
            "sha256:ab67666e1f91cd38c0ab5bee9c8d2132eca7460354477109a739d4e735b14131:47bcfd0d573653943231df07445da774e5d06465c897ce40578b120bde187e26"
        )],
        john: &[],
    },
    Vector {
        slug: "dane-sha256",
        hashcat: &[hc!(
            30420,
            "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df"
        )],
        john: &[],
    },
    Vector {
        slug: "md5-sha1-md5-nested",
        hashcat: &[hc!(32800, "7b4f60b54472980e922280e225150dfa")],
        john: &[],
    },
    Vector {
        slug: "grub2",
        hashcat: &[hc!(
            40019,
            "grub.pbkdf2.sha512.1024.03510507805003756325721848020561235456073188241051876082416068104377357018503082587026352628170170411053726157658716047762755750.aac26b18c2b0c44bcf56514d46aabd52eea097d9c95122722087829982e9dd957b2b641cb1e015d4df16a84d0571e96cf6d3de6361431bdeed4ddb0940f2425b"
        )],
        john: &[],
    },
    Vector {
        slug: "oracle-t",
        hashcat: &[hc!(
            40036,
            "8F75FBD166AFDB6D7587DAB89C2F15672AAC031C5B0B5E65C0835FB130555F6FF4E0E5764976755558112246FFF306450C22F6B7746B9E9831ED97B373992F9157436180438417080374881414745255"
        )],
        john: &[],
    },
    Vector {
        slug: "azure-sync",
        hashcat: &[hc!(
            40037,
            "v1;PPH1_MD4,54188415275183448824,100,55b530f052a9af79a7ba9c466dddcb8b116f8babf6c3873a51a3898fb008e123"
        )],
        john: &[john!(
            "AzureAD",
            "v1;PPH1_MD4,724b754c4b6d30526f36,100,367ff0ac2a1cb334bb26609c8bfc8ae5f619d1eaf07568df040f407504a20241;"
        )],
    },
    Vector {
        slug: "shiro-sha512",
        hashcat: &[hc!(
            40035,
            "$shiro1$SHA-512$1024$WobJGSjbUhsMdaILomMOdw==$9uptGJ24vzZCqZI55F77N7xjUxGlVrK5aCmAwIrV1vwDmFM4akE6Hmd23Aj8ANLSUdIEkHLZ6SnoitZbOsoQNQ=="
        )],
        john: &[],
    },
    Vector {
        slug: "huawei-h6",
        hashcat: &[hc!(
            40002,
            "$h$6$4tWqOiqovcWddOKv$XyFMVgaE46fGiqsZEHbcr+BM/m9tDkvahDbqU7HoNrvmALk2u31z9c/tuUmX7IiQhWRwN5qoZquW82A8XYaDWA=="
        )],
        john: &[john!(
            "h3c",
            "$h$6$4tWqOiqovcWddOKv$XyFMVgaE46fGiqsZEHbcr+BM/m9tDkvahDbqU7HoNrvmALk2u31z9c/tuUmX7IiQhWRwN5qoZquW82A8XYaDWA=="
        )],
    },
    Vector {
        slug: "redhat-389ds",
        hashcat: &[hc!(
            40025,
            "{PBKDF2_SHA256}AAAgADkxMjM2NTIzMzgzMjQ3MjI4MDAwNTk5OTAyOTk4NDI2MjkyMzAzNjg0NjQwOTMxNjI3OTMzNjg0MDI0OTY5NTe5ULagRTYpLaUoeqJMg8x9W/DXu+9VTFaVhaYvebYrY+sOqn1ZMRnws22C1uAkiE2tFM8qN+xw5xe7OmCPZ203NuruK4oB33QlsKIEz4ppm0TR94JB9PJx7lIQwFHD3FUNUNryj4jk6UYyJ4+V1Z9Ug/Iy/ylQBJgfs5ihzgxHYZrfp1wUCXFzlZG9mxmziPm8VFnAhaX4+FBAZvLAx33jpbKOwEg7TmwP2VJ8BNFLQRqwYdlqIjQlAhncXH+dqIF9VdM4MonAA0hx76bMvFTP7LF5VO1IqVmcuYz7YG9v4KKRjnvoUUqOj6okUBQTay3EzsdFVnUW1FemYOccJd5q"
        )],
        john: &[],
    },
    Vector {
        slug: "xmpp-scram",
        hashcat: &[hc!(
            40052,
            "$xmpp-scram$0$4096$45$353835323736323530353932363531393630313632353634313335323434323038393931323138373138343134$6d5b543b985dc6c0645da3c83d114fce121aa51d"
        )],
        john: &[john!(
            "SCRAM-PBKDF2-SHA1",
            "$xmpp-scram$0$4096$36$37333536663261622d613666622d346333642d396232622d626432646237633338343064$38f79a6e3e64c07f731570d531ec05365aa05306"
        )],
    },
    Vector {
        slug: "mongodb-scram-sha256",
        hashcat: &[hc!(
            40053,
            "$mongodb-scram$*1*dXNlcg==*15000*qYaA1K1ZZSSpWfY+yqShlcTn0XVcrNipxiYCLQ==*QWVry9aTS/JW+y5CWCBr8lcEH9Kr/D4je60ncooPer8="
        )],
        john: &[],
    },
    Vector {
        slug: "oracle-otm",
        hashcat: &[hc!(
            40045,
            "otm_sha256:1000:1234567890:S5Q9Kc0ETY6ZPyQU+JYY60oFjaJuZZaSinggmzU8PC4="
        )],
        john: &[],
    },
    Vector {
        slug: "sap-codvn-h",
        hashcat: &[
            hc!(
                40023,
                "{x-issha, 1024}BnjXMqcNTwa3BzdnUOf1iAu6dw02NzU4MzE2MTA="
            ),
            hc!(
                40078,
                "{x-isSHA512, 15000}YZH/V2T7zlQMGeWLBarm5Oi3qV9Y8ByXQijD28+bjtLdo7YssXaUBkxMXbS3l4yVlYw97tvYj+vu/L37sg1reDEzODQ4MDY1NzQ1NjQ="
            ),
            hc!(
                40081,
                "{x-isSHA256, 3000}56SL4GZltN0YPoXeGfu6BzTjFYmY4QS723iBHVbRnXg1Njc4OTAxMjM0NTY="
            ),
            hc!(
                40082,
                "{x-isSHA384, 5000}Hp1DRs7iqAwvLqhfMRnPVpFulGAdRYnnnIo3ytnoexSU5dxas1MOglsYHp5J5XuYNTY3ODkwMTIzNDU2"
            ),
        ],
        john: &[john!(
            "saph",
            "{x-issha, 1024}hmiyJ2a/Z+HRpjQ37Osz+rYax9UxMjM0NTY3ODkwYWI="
        )],
    },
    Vector {
        slug: "krb5asrep-aes",
        hashcat: &[
            hc!(
                32100,
                "$krb5asrep$17$user$EXAMPLE.COM$a419c4030e555734b06c2629$c09a1421f96eb126c757a4b87830381f142477d9a85b2beb3093dbfd44f38ddb6016a479537fb7b36e046315869fe79187217971ff6a12c1e0a2df3f68045e03814b21f756d8981f781803d65e8572823c88979581d93cf7d768f2efced16f3719b8d1004d9e73d798de255383476bced47d1982f16be77d0feb55a1f44f58bd013fa4caee58ac614caf0f1cf9101ec9623c5b8c2a1491b73f134f074790088fdb360b5ebce0d32a8145ed00a81ddf77188e150b92d8e8ddd0285d27f1514253e5546e6bba864b362bb1e6483b26d08fa4cc268bfbefe0f690039bcc524b774599df3680c1c3431d891bfa99514a877f964e"
            ),
            hc!(
                32200,
                "$krb5asrep$18$user$EXAMPLE.COM$aa4c494f520b27873a4de8f7$ebc9976a77f62e8ccca02d43d68bafcc66a81fcbb44a336b00ce401982f32975a5f9bcdc752643252185866685b0a30aaf50e449e392a5994e6979f23aba25f7704c90b2efa03b703c3c2f9e3617cc588ed226d0417e7742d45407878fd946d046b4a9732b9a203cb857811714b009c195b7c96b9bccb7e48832b11a4e92ecf24c49e54de8d0d5d5351445b5126db90bb7eebc7861db1e61de1175824b0a45023a6fa06c2a9d3035fdcf863bea922648e3dc28b48e39b1dec0869e7fe4de399cb52dfcf2596599da54a4bb0169c72d9496de2e137a4594e0e8a69082fc558ac9ace65d32eae5e260a65ca3f2f5871aaeee7a3b090b50f39321d120c144421e0abe7d"
            ),
        ],
        john: &[john_fixture!(
            "krb5asrep-aes-opencl",
            "tests/fixtures/john/krb5asrep-aes-opencl.txt"
        )],
    },
    Vector {
        slug: "sm3crypt",
        hashcat: &[hc!(
            35100,
            "$sm3$KTTUB40dW4mRyRFd$ul2xLiIY3FJtbo8sv1R93sAYCkxQCH/6rmS1kD5vJYA"
        )],
        john: &[john!(
            "sm3crypt",
            "$sm3$short$25nyMuun660zbmb99lNsRuPcp8Xnnxo3DzAp6/PXLg8"
        )],
    },
    Vector {
        slug: "scryptcrypt",
        hashcat: &[hc!(
            36300,
            "$7$C6..../....nRiFmykMMn62$SxIhqyA0SkQFM1dimuhCTqWH4zlIFIvfF.1IzSL.Rb/"
        )],
        john: &[],
    },
    Vector {
        slug: "pbkdf2-sha512-utf16",
        hashcat: &[hc!(
            36600,
            "sha512utf16le:1000:NzY2:fFLtxyYSGqaQoUV6LPbVhRBLxzTJSLtHZgUD6Aj7R75dCfAI9OlV5Uqekezy1KW6TEipM7oLIPhjQVbPMsj0RQ=="
        )],
        john: &[],
    },
    Vector {
        slug: "mssql-2025",
        hashcat: &[hc!(
            36601,
            "0x03004DB403DDD3A508F81058E6AD92A6A20E5C72A06AD0B00C0A733EAD6582BE2443AFA70C9516C2DFDC60EA927B40BD732D7763477484FC014435AAC4D57EA88237B39806C1"
        )],
        john: &[],
    },
    Vector {
        slug: "murmurhash64a-zero",
        hashcat: &[hc!(34201, "73f8142b4326d36a"), hc!(34211, "73f8142b")],
        john: &[],
    },
    Vector {
        slug: "bisq",
        hashcat: &[hc!(
            29800,
            "$bisq$3*32768*8*6*31d838af87f99cb8*5cfb7bf3228d9e865881156e17b1866589ffa6b757011e25d1319083595236d2"
        )],
        john: &[],
    },
    Vector {
        slug: "metamask-mobile",
        hashcat: &[hc!(
            31900,
            "$metamaskMobile$JV4j2dUDl7n+sujyqW3Wvg==$398f9b04c822d36bfcbdd1e68c82d1e8$auj3J2TwOZ4ev3UIGmNa7VXLh0Nmzr3rDbpXRRrONr4="
        )],
        john: &[],
    },
    Vector {
        slug: "dogechain",
        hashcat: &[hc!(
            32500,
            "$dogechain$0*5000*EEmAkgiMlVrToRhu2suq91R5Frf+VQCvNzv9lj6OwRWIf/3IM31wqhJM7gGQpinXH9kqHkuQ2DMZxspgA7QFAddsUWvZxGdNAkaeKy90EAsTLIuDQnH3plfBQfmL6j5NPaH7Nr7kF1PdvM0pbUw6XHySBYkD/rPHNM6n58NRK4xfO4VVMykeX3+m2LaVyv5s269r/op38svRPT0YFGpRcanY6/U1BeSrvG2IXii1BKXXAcVEN4GFmyEQRWKI0uZE+3M0atf7UEPD4K9tmEKosqdsF4MFLiBtfI4eq0+926ijoezDmUPvHIiyQZ9CH2jZ*6jOgqW/GxL9He1afQiINIg=="
        )],
        john: &[],
    },
    Vector {
        slug: "kgb",
        hashcat: &[hc!(
            32700,
            "$kgb$0ab30cf7a52dad93$82a7c454246fc7570224e9f24279791aa2a63bf4"
        )],
        john: &[],
    },
    Vector {
        slug: "microsoft-online",
        hashcat: &[hc!(
            33700,
            "$MSONLINEACCOUNT$0$10000$91869d1d5d3a1df25dd3f0e57bbc226a43641bc03086dcb5b6672941fcabce01"
        )],
        john: &[],
    },
    Vector {
        slug: "wordpress-bcrypt",
        hashcat: &[hc!(
            35500,
            "$wp$2y$10$lzlQrRRhLSjz486bA9CKHuZRPoKz4uviT251Sq/r5OzKUBbrXwnQW"
        )],
        john: &[],
    },
    Vector {
        slug: "gost12512crypt",
        hashcat: &[hc!(
            35600,
            "$gost12512hash$salt$w0TCvk4n0JHA/kPNpHEyf3RR5YuUXReihlrize3NdcPCmtLk/ewG63OUWT.G4bvjegPTeMb/xQ2PK7apsCfC7/"
        )],
        john: &[john!(
            "streebog512crypt",
            "$gost12512hash$salt$nwv1Oqm2zL9523APlKI6Fpmlm56UzSe.J1wDzMk61S2zxa1nWY4U9d3oP5UyOpZQvTzVPEZWRnfRd/yJZeXp2."
        )],
    },
    Vector {
        slug: "rc4-dropn",
        hashcat: &[
            hc!(
                33500,
                "$rc4$40$0$e9a41693b759cf88929ca31203694f$0$48656c6c6f"
            ),
            hc!(33501, "$rc4$72$0$90eaa8d71c$0$48656c6c6f"),
            hc!(33502, "$rc4$104$0$a04245c3d7$0$48656c6c6f"),
        ],
        john: &[],
    },
    Vector {
        slug: "mega",
        hashcat: &[hc!(
            33400,
            "P!AgD________U2XVjJi1vxkJgMPf5rkQYUn1H_6WI_sKtiic69mqBKP_____________________O_PDG0Om7BSapL1QoRAgUrz9vzaZmrYnU8t-Au6hteg"
        )],
        john: &[],
    },
    Vector {
        slug: "racf-passphrase",
        hashcat: &[hc!(37400, "HASHCAT*0BB703A26E8B0BC7C4")],
        john: &[],
    },
    Vector {
        slug: "racf-kdfaes-passphrase",
        hashcat: &[hc!(
            37500,
            "$racf-kdfaes$*HASHCAT*E7D7E66D000140000008003200100010*00112233445566778899AABBCCDDEEFF*B0AA0E1CF87660F27154933C0D403044"
        )],
        john: &[],
    },
    Vector {
        slug: "geli",
        hashcat: &[hc!(
            38700,
            "$geli$0$7$22$128$0$1$1000000$6766eb29e48dacb779060e57047a40f5a652810f3c20dd0eb81dbe8cd86cc7c5c5da0fa4d0336a789719894708ce9feed9529d52d9e6be9e83f1b2a998d674e0$7ed5e5f9eedd2f78f9b8665db67caedf46c45fb55c0ee8069749cd92b6d48a4d8d4d7a8d4917af1d63d8c1d4d7e1d7dce5f530b3208edc31d32c4d7156575d59332261c24fcbb0252ac9c70a2c0ae274819263d216dd2b9a7281c40a852b090bccabea718c87f0cb926444783792607803893a1d9a3fdc689dd75978ead7bd2b2392b1378a24d3794c422fd22638cde2d15dcb5cca97f41355d0b07d0cd329dcdbf7009013559d64e91fa2c7d8589e9b8aec0caa99955d03e287040f1743ec0e5da9a8d67331c7261d0127f67ddae8af8c790da48bcb34f38bda537250b62acf6082d6adfda42157c67313bfabc59ec63c5ccd897f12386baab56294658f23b53dde1c63935ac959b2f9af295a156a879e0675e1094a2bc0307d2f5a5adbe99687d221bdaccc22f119e3a9c85598711bffb58c33d415dbbdea4f0589de6c4fa722e5348d7ae3b58b52c8319a949e6b6ce640cee254c6e3f5dc39f2c73ed53e932586b01b281c66f2a77d49f20a9d08506ad55821d1adefea40536c39e87c2a8a"
        )],
        john: &[john!(
            "geli",
            "$geli$0$7$22$128$0$1$256$31700bceaad80bc02f27644572288e765bd9356528f2a0eeef8144d8c1381a0da7ab32ec2570b254e57218924defaa0e233a55de818d8e97ae8c28cb85bc2842$a55f6782b63a048a3c39fec977e98c6387d6c64cf5be427cd450ecd9f5294834754f058edf3b62f64f3ba7b07ac1d769df17dcd6464330970e55f5c580885cde2d7bd544cd7946e3f9a47f3643f03687504f38ed7745024fd5039043e41a9f57cd238787c8dea0c32be72e82e6a20d3094a7a524d2cf36cc47b71bc663782e7891db3fb5c68ec4c29ac7cb19b2f9b157f69faceec4ed858b46d916a370f2b2c7fd5fb15bb45c72bd6da02de37094c59758ab9e3980f6f82ce178c5e050fd1737bf8bf8c00116d055e273b3ea7fa93aa96baade62815ca1e99639909059b5f09c34ddd7052b6a1384fc5908265dbda25c63efa473146674e39b765e1dcb4f85f6dea081f84f95b97897e1634e44120967808b2377f417befded2d4366c7ba1de28f973fb01d5627817b53a43f214ae82b1db1c3a5424fb8ae43118eb8446bc16d1f8f829ecd6165a4ad87ff715033a0d16ea8898c11705c06564012fb1e0bf4599989e65d203158e519b17fbff2df2ccc3455bbf29bdce8cae5b9399822243416"
        )],
    },
    Vector {
        slug: "fscrypt",
        hashcat: &[hc!(
            38900,
            "$fscrypt$3*16384*4*bd06956efc6c4367f8c2fb7e36674c7a*1f73cb6880c2f95c1fdca66d483669a0*b88c32fe656578d54a3d867bb9db0eaf50eab23c12ba60273dce90f68517ecdf*251e99b532b0d8a5eef1afcef71747bb508736d2059ceeecce875ebaab25921d"
        )],
        john: &[],
    },
    Vector {
        slug: "kwallet",
        hashcat: &[
            hc!(
                36400,
                "$kwallet$88$45975b748f882d01a9584f6bd2a564b3a0a3ceb0d9a192c7a1a335282a1b276c57d7a529016dd943bfa1cfffdd1387f029c9aaab41ba3ff4f07c07f71f222301$1$56$8f90f3b63faf4049373703f896d3511136696af6ce60b92010daa397c6eb8ea4c867288e61694002d3c152ef4d8e3119bf39cbcd6b65edb8$50000"
            ),
            hc!(
                36410,
                "$kwallet$88$45975b748f882d01c2bf498e329f20000810fcf38c4803e0985006270fabde065b41363475a9753a54687fae112c326915658aad6901b32dff0f62b96346dd4e"
            ),
        ],
        john: &[john!(
            "kwallet",
            "$kwallet$112$25be8c9cdaa53f5404d7809ff48a37752b325c8ccd296fbd537440dfcef9d66f72940e97141d21702b325c8ccd296fbd537440dfcef9d66fcd953cf1e41904b0c494ad1e718760e74c4487cc1449233d85525e7974da221774010bb9582b1d68b55ea9288f53a2be6bd15b93a5e1b33d"
        )],
    },
    Vector {
        slug: "openbsd-softraid",
        hashcat: &[
            hc!(
                38800,
                "$openbsd-softraid$8192$9106b090975d34311921d71bc2c87e6dcc430a32671a71cacb7f2f8ec08d650c35f2fe2460d41f1be32e6883463c23590637e9cc6a2f3399756158d023e21d597bfeb05ee9ee065f1d09ad4691b6f48ee2d0bbb903274cfcb86e02836bc03d33d1ec76972882dfb5fea15c7cc3fa5ee2856d3abdf49f6bac3331d9322d03a4b6$1dd92a43ff64f2ee013df59ae96eeab8bc793eccc0764bd5ffc141cea0f66054ab61c99804b6a047a7794605e971d9fb426bab2b36f6a23435857930b392365ed505fbaf1af1e706cdf2c0f0e0e7bdfb0046db938d97ea037c225740bb00f0bee608202d0dcc218d23f8a5d703c2ef6ca0a26558dc5906a151cddf8f2513722030cd91dbb6c0af7ea8d30c0789f8ff30e4ec216b1f43bad24409199b5c937d77f2885e72a6062b066c2f91889f72771ad9387c8b36c3d4cb2ed79a2c9b4bb5a9c36a32403d38aaa9cbcfd4df504606427ec6d6f20b910840f52725c39f9a0376f8a1f8e5f032444e9aaf421547f2daffa2dbacebe157ecc481af13eba04f983413d925434379754d10a152caf996c274cae5cdc528f71ee6af6abb5eb5319b9bd60ad3c5b387fa9c2ce00bca76c94f50c5f28724fdcbb2a39c76c116a4ecfc75902f11392c87387f6ecd3dfd7991525c933eb62eebc1ac32d47173bdf2b73083644343a2034fe9af5505470d0f74e70d190ffe60cb6ce4e0e3440ab59dece37eb1292ee1f25e8109a6253163fc45aff0184aae3b70ef50ba6c16fbfe449e8d47e7389e4c6aab5f5e27cfc468f460d90f75da36301d664b531202e9c07d9c2fd5785f88290c9c878b31c4f51918f2d9cfcaefd0a50d4b2619b2b45923dd612b4d9c89d8390badfcaf4f9adc29b830652a1e01aaa352d19034a8f49888209149739b06ef3e659a989e091957179e4eba7ea13eb486821f9d256851f033d7803a64088b346452ff986ebfbdcb68191a103b59b911a15e826557e69ba934c27ba8e005d5c17e58fecaa152f9cd8e22d28c5e84a3a7237a682b71a23dad3b0e38a270e5681a18843e3ba692c79ee55ec27c3bbc6fb384d472defd83055348ba5e39b37e880520fe942aaace7926dc0db3b3b8654b8d72aceaf757f54aec2b606dc4d2854480f9fbc73bdaee2fbb3fd55dc5a2327b45930f233e65619d5425f0e8c4dec34d927d26a137bc36c8a5bb30e3ac145808593f9058a09df5759614c1a165b00de169abdd02083bb580345683d2e5d3b51067e3ca3db0c90edfec9b2c288ea5bb8e82a6e9709c0212e476111353cd335da6f59c97bfc77d097712a7f16a43a72d089f24f006406afbd71beec6238011b27a4e45383568f300f7a19eb80dad51b519c5a3bcc8b8ded80c32124ae81799592c911ea5cb7cf4a4b180d3dc5ef3b5a5e4be5d89a2612310a9271b40ca7f1328de407de57e9f1a0b785af9304ac3e1a70fcceabe9253ce08a8080f99ab8c3e3efa6432d9f5b8d9193318159487ea87a770ac7886c2665a964745f53194b66901d1607bf227a466c60ac98344f264c4f8cc36ad299cdc1c1dcc0e4b86be034324c00ab9df9fa6ec7c557a294bd2b5971229866cd92a465335251526a70a7699f89a262e9f33d61635b41a85d735fb0e88f2c632eece92c8349be1ffdca59bd912e5a7eebe63588b6fabfcdc0685a8eb95789f41f8fdb6fe22d41b6ba3551d3f05332f3ea2718b442bb09d89566afd084a796cb08fb667f853173ac52729d3d9b0db909f692bfa92bf2a33227c1d5d4754efbab0c949fae0c55f2b4c51d69bf6e058f5c7e76dffbbbebd13c483bdce3b2aa61bd84bed485ccf85563a4bb7043da2c922c4830b2292511c585f59b0ea47aa3b783cadd229091d899c4ca275f95247e3edd16a94fa3e649bcdbd5a1a6e1ae8bee3c65a1ffb1c52a58aca9c0461c7444d0958b5fd3c3c6583816570e416d0bb714177b408c37d750903c2abef6ee84e649fe07b7298feb67385b79ac649c1e7dbf2bfe3bf789ee48e950329ef358167372a1acc88c4cf29b8277826a981030fd0e7516a78bdf4beb14de061fda0a2286a4e9a3884dc5be96f106ed2265761f936a1bb2a5c9e69130263c80618eff0cab349559b8ffe032fb6bc04cb6735b7f8d4710b38fd30b2c64e7f41609d3279a017d4950acdbda42df75198ebf060c78b8f3964f7595bc13b2d4bbf82c48988e29e4e89c5c4466039e1c9262a7757741fb01be9974a8077a458ff0a908f7987f7e86bc1193d8f4e059d1371973bc4ad36909aa0152eda5cc686e8c5ce1a85a371edfdeb3c7482849c7c8af07e94c0f6801087dd5e801a8436d08cfead47f935526a3851346f75b916d1b997383a2ab73fb4cbac8d4ad5ace108f2d3223c768e94212c5a05965dd78d30070f2e045d0e96b2f1e769f35e45c3209154ea2054eb7e0367b94e8669d348dc630e65d0946246eb96bc0eb4345a286dfca8d101965dac354a925cc3ae67140b17fcf9b8259e13fa573b7734517a778d1a86dea262fd6099829a16a73142d9889ee0a0ca13d4efea79b730e59cae2b29fdf8751df9eaa98aecf160a5a2adb1f52cc0cf99699b1b3fb031f0c1a2cce50108112c927fb45a08bbbd470f1c1d7ffc82ace4fa8b897da23a02c607aed185a3fcf83d510fb164b2b9c4fae20050e45d564e637bc5d592d0013ac33925ae43a010c510e43fc3c3bde231c69d36ef070d6de568f45f8830ede285d5a68d95fafd206e7b4d3956c1c8fca04c1794fe13dc489fb61d7b2c3eac6859e12f3120f3f07e99d94ac81630637f06e0cab4a38f2245851f45be18fc7b671139055c41e1ee266fdc4faa807ca0d6fbc109fe1646c2bb2f3dc77df3c883ce47735a39e3626c68060d44fe1ec13c89120f499faf74e3afffbcc4508d91e50119d8c4164a20451cee1b6e9a8db8c841a10326d2557a5152ccb7a4f84fd74df6101f552665a372b963936aefff336507c4052bacab3ca6fe88cffa9a0b14c283a4cb5207c59d054a11ce08f3602a339ae749141036ccaf7fb4974a8c7a93715f55398487bc516611210001ddeb5fed8596125f0fb2ae20ed6d4f1fb6e8$919e5722d6e670321cebf0a581b9d65eeec6feb4$1"
            ),
            hc!(
                38810,
                "$openbsd-softraid$16$178073496b872f79303905bdd4729a84152e0a0d8aa21e69961a1fc4c8154a8bc20b7fd2d2c2b39eb5576f7b5fcc6f8f683d5d59e323aac36a431b31b080b64c30a09303a6aadea7f5351c5e23fcf7aa9f9aa91c09a436e95e5f416e597c3eb6f34c97c0577ba3b3a6403e04ff952d49819d58471d95673982a8c05f50d11f29$441433c062f69de0755a58517bb530c54a6443646052c2bb3641cf1795c95560ccee996a3ea8bfe64db497e3f779c8c2c8446b6f7cb4f2d8d27e72f19474b491c2aeaf791ada3b6adbf04326d40ec6416e905b7fdb6d275a4b77f434bf6a5c590e81b02c00a335f56e47902458b4dd0a4c6a69b04e6c066f81615253093a5d48c253e5b7b1420fa5379be7f4f3e00a427bef64611c7ea1ca4fb2342c878a008a48fcf2ee9b66ea66ba10d4785e2d7cdabc0d475aea66477006851a778d70a1875b20fababd925cef2fe50b5cda0f583891f398cf21b2fc1981da769603b3ed4cd08d98e3dacf4541fb8d22a75c08f11b44875a6da711ed1ebe2454ec3d85f18649ba066578a350049a33f8f1a3e1236454952f22c2725a036d01884690d8c3d49ec3311bdf15d5aa0adb9d913ebf17384e3ff896f6bcdb923f9eed51208d4955df43c16301a1339a5bc8598ad0315984f1622383627e87eedcbfc57b9bb1c63f7b81a54574e47171ff93aeb3562cced6380396c195277513b6bd5ac6f75562ab8465035eabd56a6e7d4126c4581100b9ac7053fe31f8e7957be2a6e31b730d132b67b34137cf9bcd90cd6ff27bd3ccd16f024a94273233544705d7acabaf015ecb3d25efd41e9585da8c412876f6041ce6198a68d5c66c1b1198d2c8bf77edd2fa28997d34bd10768fce33b5fb3a1c228f87517928c64326a904d4e56b1b7fbbec3174f1e8a76000ea0f8fa1cefe78f55cb074decafd3692326305fba49b6d8ea2f38015995b8fee4de6f0522bb06413b6f07c0974a68bf61312e99be7879428c6bef8cca9261c74088a84443420e97f81184863b27a897b383b17d61ffb4b95e47fbd84ac63bf1ba874af3eb87c0b346ea32c56e0be477c69b428f8118fa08af8d10e816b499b6dbd0db5bcadae18e170ac7ecc2b17f9b3074b097ef439c2edc03526a02b601f2a0caac715a043ee7f6d6f07e8c59abe4e4443cfc48075249eba041c01a73fbca9734130a12dd008f64bf7454935eae4cde30894f117c7efcd8167052b7ee9f5ffcbccb02886963432cebe72f9170b1e44c2bc133eef769aa4817497b52d8ad23decf1c1728700d8a3e6cc034594b65b81438f0d6159e31479d1e77abf9fbd07b8bfe8d5fd1934969b456551be0780fe3677a4e1823880577aa7c0a78252e1b8b8fa40bece18f79d18bb8dc1c8501631f009276b451595e13b8dd3ec928a939e3d08c1c67a051dde3f5a9545b5b216849d6b26b6300c58f2332eae1fc01b390629c0d849b7fe41352e7c5406a855beec9b97044a59cad00f529d422d148178dc338469d8b162d312ce10b41627709f54c42e7aa23a1a424dd2eda725a90ca43f9cd18fe613f328f17faec5ee206cd66a8c063429a4e5148a84ebf6bca1ee6ab17fe1c6319f479084842d5a107766ae262205e96d1a229023dc3fafd6c4d0cf485aa63b6103314196dde95c21dd993fbe5dcfbfa58f59aff785ee8bc605529a5a367f2fa75428e57339fe948243e01287ed13375022eccb8bb58b61d7868c157225c7241ac69b00da6f2d239bf2fb73d2315cabc38e4c44402a17aaa8506e1b79cd0c3a1ad8de50a099dc5e17b060cb17008d822b3d18a4f2780b151dc16f3cda5b912d064ae8c1d53922a045e1097ce3ff4d1e8db4310e3d17049a23627ba4f72cd5bb225d96c3ce74f6d33f810973d7c5b95238c2b77117142c89de45fb8f1e914e95a55693a929abbfda089e0d495a0a468a99b5f2237a40d18c9f535b433e9bc981e0e738003f71b259ab53183471c2837209b5880204f5e9ada332903b43e90a7b876e0d0630a2198e2bc2d6d23407b88abb38129cc360e7ac840c038c3c02ae8262e579d2f4ae9160754463db595b02b84a01d2d94b64d62cd9a291df477a2efbfc39084f860ca20ca89326509371ddd60f4b201f6b88e5462b99359973ea2af78e43954a76f07f23997eb8828f2a6dcdf772db532aae0b0a0bfa08a95128774a4da31930ff6107c4fe1993f055bb35437577ccd48a8540cef2797b450b21cbd77ea6cacf0d5d4dd382f1c5c8d85af1879880e0f03a931645e57c20c19126fbe0998942228d19bb39fd7499295f1d2f2b3a0532b8e5f06a0444975f5d19f95cbe7cb755b86de197190a02c438cd68a28f6556545bea721444c538f26eaed9fad1c73a3a25c8a12b8987b1786204078256c7421e0f781f976f4e1b36132089f7d029e8608e6c69574793a23be80217aa24676cfe3c996073c33651d41ea1d780ee652584aed36f1e15e101a51fd7e760c84ef62e9f13e280ec13296581d5115f0c4cf8a15b19ab6c16dd8babf9e5bd6dea5e16826cad16ea99152ba5362765151493715af7f44ccbefcb6f0ec53e48265b4c8782e558e385b139d5c15878714d0ea263e0dc38fbf1612d73ba0eae33dd35b4768935023cee842ec1a396d3fc5f74ee7fdb650cfff737aeaa7c2a47016d914d28a42821c31c8bf391b25b4dc12ea4d8815253bf6cb1a181f547f9d2bbd132e15e54dc4310164c92e5315b2381ace534dbc8f04171ad50f3230fbcd08e7671d5f13947a8c1ed2135349f9604ec8157fb57b21fcc7115b35ea4f2e0c6a8e4644d135eecb05b085c69b14b3a731200d0640fd46af0936c352a37138a4bde0f79bc6a8b58dd9d3bc33c6bcf72d979fe95755e07ca54d0569558e8d57c14bfd75800a74e6180a2ca45e307995c684d6683b426839eff45815ed31608a43f4a2e95f2619eb6162b7fb9637e754b9d51df729ef51d00dce46e81042bea8a113ec4bb0ed203812890969108a278a0e143bfc0feb0b73868bdd35d925b16d5d856383e8913b2a11d44e073a563ed7d53e28f2de15abb63af799764125bc933f83e115a4a3253faaca3$e3d8de0fe5bd91e2ca7fcd3bfe009a3f4cc0aa27$3"
            ),
        ],
        john: &[john!(
            "OpenBSD-SoftRAID",
            "$openbsd-softraid$8192$c2891132ca5305d1189a7da94d32de29182abc2f56dc641d685e471935f2646e06b79f1d6c102c2f62f3757a20efb0a110b8ae207f9129f0dc5eea8ab05cc8280e0ba2460faf979dbac9f577c4a083349064364556b7ad15468c17c4d794c3da0ddf5990cc66751a6ded8d534531dd9aa9fce2f43e68d6a7200e135beb55e752$311c42d1d8daf1e47e0150c8d4a455a0567b062970c1838faaedcd3e43795545de64971c7598902a6e2c3fffcf8abe2ef78979164d0c9089fbb931c4c9dac8b86c85eeace11095e38487e41eb7b6094d96c339e86686121fbe1c32dbff3c00706926b22ec3a1329f346c599d132105b5d182a380161504d535f9836bb7286331adce1e47e4e251a0249612a94312bb309a6f4558568467731c1ae8c9b910d27102dca2a72228ffde7bfc60004c8ab33ca2b01aa476c4f42f99a3d1f904e3bbc56270edb314a62e92cf68185ace93731ef4ce08dff3c695c45e35b57ed8ab1552114635eb2ff531437ba5c3a08ebf3e73b6bbb7fe1ad98373da349f09284ae819b6a2f6fc5a10aec347f3c2331abc1d6617e77d68f314fdb683294f3ef351869491c4fb096969924215d711c15e5fce533dc5acaed4a473b14c595bababc178e62ef065770716520ecddc7cbf1cbed1250b7e004ab975bc29780c952087ec382bf6e77447720a10a8c2993262a2b21f8a3f47e35daa5b620573626b474d3e8abf8e73164664b041a18fe35c2a1905fad617bf6e6c380fdeeb680fa89b6c6dc7676ad93fde25076ecb8855d623b45af9a16a62a957d85c4c70896019be1827ad9320a69f18bdfc2674f04babdbfcd679c0ef22f7ab2a18818b9b425e61d8c06196a23babd0aefd5a00f1b297a66d973daae40f4dbd9be60d8953fafbd51f7745e2d04b5c80b63ad1f550cd939490b346d4fe7c1fc266d593bcafac0d8989994e174de6d1ef4ce78b3224ea4e68ccbf998654a067558537be332f5cae4b44c18664428d45b71cde5b53bedddf8a7daf47fce212578b727e420c91de0baa1108683dd5b5534e81f4fe945d27fd9d28934afc8d15d95932952c0be717d4d87bb8255bf658a083c3aed643f7a6cfb56fbcbdab9e0a7348b0a3a91e3d560d1ec96f5769551e64beb54a499f6d6dd37e4361d484fe4f7bac4dc26c8a1a2609592d527b134c8212d71b3578217e0ec1da317c69e7e8c39d2d5b2d4073fa9c618a01a092b61613f6f1e41e6ab43d8ca010f177947aeab2884e9a4dd28453ff5bdadb765680733e7af1463ec1b20b879ae01c9256da0207811f956b3950f6db743a9e34a6d8f0fdfa5c47b4f807f0017c2092d72dc19d111711e796ffc4035da3a4caa6a5301491d0473b0d47cd01b705ff11a10263867013a11c65462c311fa5ac9a2598142779b55f09dbec89ac18049c29e5baf3aa38696a3b92d08b02cb10af5389e06058b3ad8be09b121e4e320520413775b7c6fbb3f2b332e3ac0295a4a4dfb4a56ea1c32bc28c149ffaa3b426f5a17a11afe56426b38966c86734654fe05a611c8f025ee4092656c097bbf59743c31508fa9e80ff86a2ae33d401ec316e65eef251d173e9565ffc1672b8b341174427a851a6a4c42554848c637283d13d4ba5b5414b4e61ade6ec7ef7b77186a81adff381e6a79d3dac2c68bf386f100fef1c354221a2ba3d8a7a10460f637eaa152ab79027ab94e5965660de3ed66dac4a0f8e75b85d768e51c8e82a26cb81249ca8d249d8c5cdc8bd55289679d3915a397d31863334df18e2fe3ef9069b064c4ef6b418e5388817040ae9922e5e9f57a8bf3b3fe04748b9cf5068ac86f942b4068853602a6c6c794423569b665b359d5f947c2e5ff194d23d953b435b2b3834513fdfda2b66fcea22883690b1cc56c2fcaa5600895ff8d8ae9e3a6a2b6258ff873242d1128b20e7d1e843ade1bd206b541eba02a214a95cd83860865f947cb4adbd465957055060df05e53fa9ea4b29867c92b224be939d3715be0e61b7aa0e24a8f25bccfa3b7901a3f0a8cb25498d7c9899d435b409220723dcde1d38ab6d4e7cfb42d443c9b65a3753891f46adb9bc52574699a7b642955702ed662d04cbe21aeec7c15db7e325dcaa74c85c5e3ed54424642d5bd8d3109c2d4c0079b3d2c5f2da12ad5b25407ae48f6fe4fc653b23a7f2d56a93c898dd0bd59ba02295934c9f7ffb433ef611d51b7c203f374cf9e8b69d4952ccc44593447ad41540270b0e30c349401048cbce10a0e1bae373de15c878982b0af837fb5432cd2471516d1e218296ce462a59fd5412921bbd3f75cf65070f7bafe21105ba83f7ffe8ece71534863c0dd731a2f3c29fff97b8ce798890a1b158a8891bb6f2dd751e75c0cb0db7ea152d7cdc91663f46f85d12ce0015351dba5225b2a87b64cc30518b23e31b2bfbb0b2a5042eeaea1234a57549a3e55ddd708e3380df032e93071b10b3e6902152c90ffd99bda0177a197779341307c5d9f335e698259ade70564eab9d2856aa1aa814211e71ba2885ef9cd5f5bdd225af2f6eebf775cc0bbdb3e519edb7c49a9a1984cc0cc012679aca8fd1d002fa64b2df095b4a9e2b496e3f4b544955c817efb29562cf8b3d2eeccbe4d364ce71d2d12b504b11de4747139ef505bdd12f382eb02fa3f5272b710644a9c20660ca5b4fa74be60984240b555c1f34261ee1d72d9eb2cc680f32b4603865503addc3a1fdc49d2b158d3407a282edd72ef51ad021338fdebf413726e1778e3bc3909b670d3f40e824391c5525b162ea01c29205e12f8e62bdd8cd0f21f6f7b44af4521c2dd23a7f3508e5dc6fffa3365e4ca1cac33bb515a5c5495dc059a94396de7d802758b65bb4cecb90bf69ab4126eab85958cb8b64eedf3a0955ab42cdc98ef90620e10cc854b9c02bfaff60742494a0c3bb34ef6d6bb861b275d975bdc4a10ac922dc70c1b03a4c01943a704af36ec8d79cf2f9ce0f602f01bef4a32edeb8fbba863c945552efc814410ac6bb839349ea65879644003bdda35d40eabdc9dcfb2d67d945b7f111ab62591763a0dd2d338594eff004237e5acce69dd9d2cdbb9ce121bd$5337e4ba9d877a1e84559688386fbc844c5fe557"
        )],
    },
    Vector {
        slug: "veeam",
        hashcat: &[hc!(
            31200,
            "$vbk$*54731702769149752741495960625996207399688284541933702394775960978730695504382155223405444342855920150089170058956647576461877712*10000*78cf7df8f1ed8bb50bda1129ec8e6810"
        )],
        john: &[],
    },
    Vector {
        slug: "sntp-ms",
        hashcat: &[hc!(
            31300,
            "$sntp-ms$cfc7023381cf6bb474cdcbeb0a67bdb3$907733697536811342962140955567108526489624716566696971338784438986103976327367763739445744705380"
        )],
        john: &[john!(
            "timeroast",
            "$sntp-ms$55265c2d9510284b3ad62ab7d5cae532$1c0111e900000000000a24124c4f434ce6e13d4de4200050e1b8428bffbfcd0ae6e16cdc7817804fe6e16cdc7817f412"
        )],
    },
    Vector {
        slug: "argon2",
        hashcat: &[
            hc!(
                34000,
                "$argon2id$v=19$m=65536,t=3,p=1$FBMjI4RJBhIykCgol1KEJA$2ky5GAdhT1kH4kIgPN/oERE3Taiy43vNN70a3HpiKQU"
            ),
            hc!(
                70000,
                "$argon2id$v=19$m=65536,t=3,p=1$FBMjI4RJBhIykCgol1KEJA$2ky5GAdhT1kH4kIgPN/oERE3Taiy43vNN70a3HpiKQU"
            ),
        ],
        john: &[john!(
            "Argon2",
            "$argon2d$v=19$m=4096,t=3,p=1$ZGFtYWdlX2RvbmU$w9w3s5/zV8+PcAZlJhnTCOE+vBkZssmZf6jOq3dKv50"
        )],
    },
    Vector {
        slug: "securecrt",
        hashcat: &[hc!(
            31400,
            "S:\"Config Passphrase\"=02:ded7137400e0a1004a12f1708453968ccc270908ba02ab0345c83690d1de3d9937587be66ad2a7fe8cc6cb16ecff02e61ac05e09d4f49f284efd24f6b16d6ae3"
        )],
        john: &[],
    },
    Vector {
        slug: "encdv",
        hashcat: &[
            hc!(
                29910,
                "$encdv-pbkdf2$1$1$121f898edc51ffb2$14e6bf4e9256f9e4$32$1972489853882254644795101599063579097812661888813652597380052274$100000"
            ),
            hc!(
                29920,
                "$encdv-pbkdf2$3$1$c232aba45699c80b$473d5dd2e0833ac7$32$4454716926322493581114042616371582782202532493983541577898367049$100000$9a030124cecc2fef5ca44f83ef6e4c7944f8d7c5234b9000c982e209a92bb5535f4c15be6e9914729eb8a9bf870bd0535a231fa1d443d27c1fc4f78b441a7aa765fa0a3d181c485f77f59334ec68f27e66f227eb4be3579464d907ed8cf8bacc817cceb4496587898e43ce41921f66114051c007e1a54b7215b220aed6e33064"
            ),
            hc!(29930, "$encdv$1$1$3a427b9ee5851118$4f52176bb9a1b3b6"),
            hc!(
                29940,
                "$encdv$3$1$91b9babb3820c527$1ff4cb6657adad34$d9067c4d059879dfee2edeb3999871973d422ff5fa868c51b025d07f644187889dc5509ec75d4a120184d619d10d02b138d64ba82f9d0936162c9e64d97771de3e74d6e52e5ab9b900c25fb446e14cbe3ef1fa34328a13f9473c669f22d7020bc036d9e99194c959e4c5ba885d6f9ff9ccc2299d67b26e68b850a02363fb2646"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "postgres-scram-sha256",
        hashcat: &[hc!(
            40055,
            "SCRAM-SHA-256$4096:IKfxzJ8Nq4PkLJCfgKcPmA==$iRw3qwTp18uaBnsTOEExbtgWdKeBMbSSnZvqD4sdqLQ=:hPciC1CcnBna3szR8Mf3MVc8t0W7QPbIHoMMrh4zRV0="
        )],
        john: &[],
    },
    Vector {
        slug: "flask-session",
        hashcat: &[hc!(
            40056,
            "eyJ1c2VybmFtZSI6ImFkbWluIn0.YjdgRQ.1OTlf1PD0H9wXsu_qS0aywAJVD8"
        )],
        john: &[],
    },
    Vector {
        slug: "blockchain-second",
        hashcat: &[hc!(
            40040,
            "YnM6WYERjJfhxwepT7zV6odWoEUz1X4esYQb4bQ3KZ7bbZAyOTc1MDM3OTc1NjMyODA0ECcAAD3vFoc="
        )],
        john: &[],
    },
    Vector {
        slug: "krb5pa23",
        hashcat: &[hc!(
            7500,
            "$krb5pa$23$user$realm$salt$5cbb0c882a2b26956e81644edbdb746326f4f5f0e947144fb3095dffe4b4b03e854fc1d631323632303636373330383333353630"
        )],
        john: &[],
    },
    Vector {
        slug: "sip-digest",
        hashcat: &[hc!(
            11400,
            "$sip$*72087*1215344588738747***342210558720*737232616*1215344588738747*8867133055*65600****MD5*e9980869221f9d1182c83b0d5e56a7db"
        )],
        john: &[john!(
            "SIP",
            "$sip$*192.168.1.111*192.168.1.104*200*asterisk*REGISTER*sip*192.168.1.104**46cce857****MD5*4dfc7515936a667565228dbaa0293dfc"
        )],
    },
    Vector {
        slug: "bcrypt-sha256-hmac",
        hashcat: &[hc!(
            30601,
            "$bcrypt-sha256$v=2,t=2b,r=12$KSOjON/ciJR86a00N5q61.$AmWZucQuHk13FGkQWhgMeiFvBfm2GCy"
        )],
        john: &[],
    },
    Vector {
        slug: "cisco-ios14",
        hashcat: &[hc!(
            38200,
            "$14$ZeF0$Yh3cTZvrtSWBcT$6ImC5D6iNVvt4fwM14oDbj.Vd5KWkpl8WjUffnRdH5E"
        )],
        john: &[],
    },
    Vector {
        slug: "securezip",
        hashcat: &[
            hc!(
                23001,
                "$zip3$*0*1*128*0*b4630625c92b6e7848f6fd86*df2f62611b3d02d2c7e05a48dad57c7d93b0bac1362261ab533807afb69db856676aa6e350320130b5cbf27c55a48c0f75739654ac312f1cf5c37149557fc88a92c7e3dde8d23edd2b839036e88092a708b7e818bf1b6de92f0efb5cce184cceb11db6b3ca0527d0bdf1f1137ee6660d9890928cd80542ac1f439515519147c14d965b5ba107c6227f971e3e115170bf*0*0*0*file.txt"
            ),
            hc!(
                23002,
                "$zip3$*0*1*192*0*53ff2de8c280778e1e0ab997*603eb37dbab9ea109e2c405e37d8cae1ec89e1e0d0b9ce5bf55d1b571c343b6a3df35fe381c30249cb0738a9b956ba8e52dfc5552894296300446a771032776c811ff8a71d9bb3c4d6c37016c027e41fea2d157d5b0ce17804b1d7c1606b7c1121d37851bd705e001f2cd755bbf305966d129a17c1d48ff8e87cfa41f479090cd456527db7d1d43f9020ad8e73f851a5*0*0*0*file.txt"
            ),
            hc!(
                23003,
                "$zip3$*0*1*256*0*39bff47df6152a0214d7a967*65ff418ffb3b1198cccdef0327c03750f328d6dd5287e00e4c467f33b92a6ef40a74bb11b5afad61a6c3c9b279d8bd7961e96af7b470c36fc186fd3cfe059107021c9dea0cf206692f727eeca71f18f5b0b6ee1f702b648bba01aa21c7b7f3f0f7d547838aad46868155a04214f22feef7b31d7a15e1abe6dba5e569c62ee640783bb4a54054c2c69e93ece9f1a2af9d*0*0*0*file.txt"
            ),
        ],
        john: &[john!(
            "securezip",
            "$zip3$*0*1*256*0*edb47a990800000000000000*32f884f9fbb54360920a50ec37cc0651fe7b0d9892de44eed17696186139a09c1530e0522abfd9777d18441739cdc7107fdfd252ecd0c8dbbba8181bd09436e9a6a918e385cbab26bee49cd0e3182e67df3fe8c3cdc9e58d6166a0f550969cc456b4a881524e6e66a14e30196b972e260c509fce918736465aea1d00bd5871876e263635be4700ef081117ed896e1504*0*0*0*secret.txt"
        )],
    },
    Vector {
        slug: "xca",
        hashcat: &[hc!(
            40000,
            "Tcdf012ed7637ca3b9F579C6659725E28985A90E17E16072D4A371293F233323EAEB302C4A39575DEBDA03053860298920FBA3985F7E1A9B9045E56543B8D05A72BCFFB984FB3EF33"
        )],
        john: &[],
    },
    Vector {
        slug: "iclass",
        hashcat: &[
            hc!(
                36900,
                "$iclass$75e0cd15feff12e0$fcffffffffffffff00000000$adc8761a$fcffffffffffffff00000000$adc8761a"
            ),
            hc!(
                36901,
                "$iclass_leg$0003020102060301$feffffffffffffff00000000$1d49c9da$feffffffffffffff00000000$1d49c9da"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "mifare",
        hashcat: &[hc!(
            37000,
            "$mfulc$1$3$0$ec9c5cf763244367$2283bfe8debe1780$922327794d0706ef$48444c4a4044524200000000544e5846"
        )],
        john: &[],
    },
    Vector {
        slug: "cardano",
        hashcat: &[hc!(
            37700,
            "ETERNL:42391a067b83d88e429c63da8004599b1f8b0e94ed47f1acea9c274b55d8b311b38cc419fd3b63c12ed48cd8b307651fd4e4be4a400f19df778146d7e392d8bb5811e376cff1bd71810f4c92ac973d6eb3e390ade856febd97c067e5cf40e9fe23c3655c25dc406686679e601a544acda56a51553f57305c969a2eb58331db5b215023b0de63e7cc15fe1de0afdb9cc45e45d6e127c20c28c63ccb32c8d6346240e7b81dfe7367a0e3a2f6f9f20c4b6e75a8486d5c052e42a085be2f41817ccbc6c0be5e9518253f7e0a66d33fdea5966aca494d6230a92092349d8659d982e346"
        )],
        john: &[],
    },
    Vector {
        slug: "mikrotik",
        hashcat: &[hc!(
            38000,
            "$mikrotik$hashcat$3069ece5c30baced372fb3d64647d42f$25772ddb1fa2e0f13511d7d7dc8c611b6529dd915d10482243dfca38"
        )],
        john: &[],
    },
    Vector {
        slug: "totp",
        hashcat: &[hc!(
            18100,
            "597056:3600:613004:1234567890:322664:9876543210"
        )],
        john: &[],
    },
    Vector {
        slug: "bip39",
        hashcat: &[hc!(
            36000,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about:33747aCmUp8PkWmWWY8epR1Cph8Tf9Aozt:m/49'/0'/0'/0/0"
        )],
        john: &[],
    },
    Vector {
        slug: "onepassword-mobile",
        hashcat: &[hc!(
            31800,
            "$mobilekeychain$31800@hashcat.net$0226802599846590531367298686059042845608249051353268870564348733$fa53b7d424cdd36667dc12e585810729efc8ea9b2f8e5dd7a3ee72f7576a6788$100000$e1fea241e7b7c84535a0d53388bccbb9$dfd5f9ad6da1a72a47a3c04e03b02142b2fc301b3afff610669058527828a0e0388f5a2b0e6909813a5f9653c54f797adf0869107f4b875d4beb736cfbcec428ca19fc28346642fa32ec00f2ca4ad8dcf119af33cb247273e7b7427fd20eae8fb992779979a5e25aa465b3954794f62f4ea85355032efcd4e43ae3db6b14720d1dda963a384c37b521a92cef3494f77580edab210987ebcf2f0f7ed0220c0a4777be693e075b5f1e1302$995f3703b8ea4519f8cdc1cbded4d595"
        )],
        john: &[],
    },
    Vector {
        slug: "apple-dmg",
        hashcat: &[hc!(
            38300,
            "$dmg$3*20*20a528dfdc3dc653d5da26923cd7b07d03eda76e*192*64*17b5d1683f6cd8b076943f1397d96f2d7a966596bd4c816334f444b26c33b6dd1a2f309a375ed9c3a612b5877c75ea6c2f3053fdb4c2b9a477d6291573fcb7cd*384615"
        )],
        john: &[],
    },
    Vector {
        slug: "pkzip",
        hashcat: &[
            hc!(
                17200,
                "$pkzip2$1*1*2*0*e3*1c5*eda7a8de*0*28*8*e3*eda7*5096*a9fc1f4e951c8fb3031a6f903e5f4e3211c8fdc4671547bf77f6f682afbfcc7475d83898985621a7af9bccd1349d1976500a68c48f630b7f22d7a0955524d768e34868880461335417ddd149c65a917c0eb0a4bf7224e24a1e04cf4ace5eef52205f4452e66ded937db9545f843a68b1e84a2e933cc05fb36d3db90e6c5faf1bee2249fdd06a7307849902a8bb24ec7e8a0886a4544ca47979a9dfeefe034bdfc5bd593904cfe9a5309dd199d337d3183f307c2cb39622549a5b9b8b485b7949a4803f63f67ca427a0640ad3793a519b2476c52198488e3e2e04cac202d624fb7d13c2*$/pkzip2$"
            ),
            hc!(
                17210,
                "$pkzip2$1*1*2*0*1d1*1c5*eda7a8de*0*28*0*1d1*eda7*5096*1dea673da43d9fc7e2be1a1f4f664269fceb6cb88723a97408ae1fe07f774d31d1442ea8485081e63f919851ca0b7588d5e3442317fff19fe547a4ef97492ed75417c427eea3c4e146e16c100a2f8b6abd7e5988dc967e5a0e51f641401605d673630ea52ebb04da4b388489901656532c9aa474ca090dbac7cf8a21428d57b42a71da5f3d83fed927361e5d385ca8e480a6d42dea5b4bf497d3a24e79fc7be37c8d1721238cbe9e1ea3ae1eb91fc02aabdf33070d718d5105b70b3d7f3d2c28b3edd822e89a5abc0c8fee117c7fbfbfd4b4c8e130977b75cb0b1da080bfe1c0859e6483c42f459c8069d45a76220e046e6c2a2417392fd87e4aa4a2559eaab3baf78a77a1b94d8c8af16a977b4bb45e3da211838ad044f209428dba82666bf3d54d4eed82c64a9b3444a44746b9e398d0516a2596d84243b4a1d7e87d9843f38e45b6be67fd980107f3ad7b8453d87300e6c51ac9f5e3f6c3b702654440c543b1d808b62f7a313a83b31a6faaeedc2620de7057cd0df80f70346fe2d4dccc318f0b5ed128bcf0643e63d754bb05f53afb2b0fa90b34b538b2ad3648209dff587df4fa18698e4fa6d858ad44aa55d2bba3b08dfdedd3e28b8b7caf394d5d9d95e452c2ab1c836b9d74538c2f0d24b9b577*$/pkzip2$"
            ),
            hc!(
                17220,
                "$pkzip2$3*1*1*0*8*24*a425*8827*d1730095cd829e245df04ebba6c52c0573d49d3bbeab6cb385b7fa8a28dcccd3098bfdd7*1*0*8*24*2a74*882a*51281ac874a60baedc375ca645888d29780e20d4076edd1e7154a99bde982152a736311f*2*0*e3*1c5*eda7a8de*0*29*8*e3*eda7*5096*1455781b59707f5151139e018bdcfeebfc89bc37e372883a7ec0670a5eafc622feb338f9b021b6601a674094898a91beac70e41e675f77702834ca6156111a1bf7361bc9f3715d77dfcdd626634c68354c6f2e5e0a7b1e1ce84a44e632d0f6e36019feeab92fb7eac9dda8df436e287aafece95d042059a1b27d533c5eab62c1c559af220dc432f2eb1a38a70f29e8f3cb5a207704274d1e305d7402180fd47e026522792f5113c52a116d5bb25b67074ffd6f4926b221555234aabddc69775335d592d5c7d22462b75de1259e8342a9ba71cb06223d13c7f51f13be2ad76352c3b8ed*$/pkzip2$"
            ),
            hc!(
                17225,
                "$pkzip2$3*1*1*0*0*24*3e2c*3ef8*0619e9d17ff3f994065b99b1fa8aef41c056edf9fa4540919c109742dcb32f797fc90ce0*1*0*8*24*431a*3f26*18e2461c0dbad89bd9cc763067a020c89b5e16195b1ac5fa7fb13bd246d000b6833a2988*2*0*23*17*1e3c1a16*2e4*2f*0*23*1e3c*3f2d*54ea4dbc711026561485bbd191bf300ae24fa0997f3779b688cdad323985f8d3bb8b0c*$/pkzip2$"
            ),
            hc!(
                17230,
                "$pkzip2$8*1*1*0*8*24*a425*8827*3bd479d541019c2f32395046b8fbca7e1dca218b9b5414975be49942c3536298e9cc939e*1*0*8*24*2a74*882a*537af57c30fd9fd4b3eefa9ce55b6bff3bbfada237a7c1dace8ebf3bb0de107426211da3*1*0*8*24*2a74*882a*5f406b4858d3489fd4a6a6788798ac9b924b5d0ca8b8e5a6371739c9edcfd28c82f75316*1*0*8*24*2a74*882a*1843aca546b2ea68bd844d1e99d4f74d86417248eb48dd5e956270e42a331c18ea13f5ed*1*0*8*24*2a74*882a*aca3d16543bbfb2e5d2659f63802e0fa5b33e0a1f8ae47334019b4f0b6045d3d8eda3af1*1*0*8*24*2a74*882a*fbe0efc9e10ae1fc9b169bd060470bf3e39f09f8d83bebecd5216de02b81e35fe7e7b2f2*1*0*8*24*2a74*882a*537886dbabffbb7cac77deb01dc84760894524e6966183b4478a4ef56f0c657375a235a1*1*0*8*24*eda7*5096*40eb30ef1ddd9b77b894ed46abf199b480f1e5614fde510855f92ae7b8026a11f80e4d5f*$/pkzip2$"
            ),
        ],
        john: &[john!(
            "PKZIP",
            "$pkzip$1*1*2*0*e4*1c5*eda7a8de*0*4c*8*e4*eda7*194883130e4c7419bd735c53dec36f0c4b6de6daefea0f507d67ff7256a49b5ea93ccfd9b12f2ee99053ee0b1c9e1c2b88aeaeb6bd4e60094a1ea118785d4ded6dae94cade41199330f4f11b37cba7cda5d69529bdfa43e2700ba517bd2f7ff4a0d4b3d7f2559690ec044deb818c44844d6dd50adbebf02cec663ae8ebb0dde05d2abc31eaf6de36a2fc19fda65dd6a7e449f669d1f8c75e9daa0a3f7be8feaa43bf84762d6dbcc9424285a93cedfa3a75dadc11e969065f94fe3991bc23c9b09eaa5318aa29fa02e83b6bee26cafec0a5e189242ac9e562c7a5ed673f599cefcd398617*$/pkzip$"
        )],
    },
    Vector {
        slug: "yescrypt",
        hashcat: &[hc!(
            36100,
            "$y$j9T$oJqQoBLMgF5$77xERSZazujSxPgj6nYmzH5r0O2HelZJUyfW.ta7vxD"
        )],
        john: &[],
    },
    Vector {
        slug: "gost-yescrypt",
        hashcat: &[hc!(
            36200,
            "$gy$j9T$HtyOX9cwJ2Dh8LlJV8IJ30$ZCSJt69pE/HLXFfIuxukRc2PlNla.tbqJxUHCp/WHVD"
        )],
        john: &[],
    },
    Vector {
        slug: "john-hmac",
        hashcat: &[],
        john: &[
            john!(
                "HMAC-MD5",
                "what do ya want for nothing?#750c783e6ab0b503eaa86e310a5db738"
            ),
            john!(
                "HMAC-SHA1",
                "The quick brown fox jumps over the lazy dog#de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
            ),
            john!(
                "HMAC-SHA256",
                "The quick brown fox jumps over the lazy dog#f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
            ),
            john!(
                "HMAC-SHA512",
                "what do ya want for nothing?#164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            ),
        ],
    },
    Vector {
        slug: "adxcrypt",
        hashcat: &[],
        john: &[john!("adxcrypt", "$adxcrypt$54886955")],
    },
    Vector {
        slug: "afs",
        hashcat: &[],
        john: &[john!("AFS", "$K4$e35e9294ecef926d,0123")],
    },
    Vector {
        slug: "bfegg",
        hashcat: &[],
        john: &[john!("bfegg", "+9F93o1OxwgK1")],
    },
    Vector {
        slug: "cq",
        hashcat: &[],
        john: &[john!("cq", "$cq$admin$a9db7ca6")],
    },
    Vector {
        slug: "ipb2",
        hashcat: &[],
        john: &[john!(
            "ipb2",
            "$IPB2$2e75504633$d891f03a7327639bc632d62a7f302604"
        )],
    },
    Vector {
        slug: "iterated-sha1",
        hashcat: &[],
        john: &[john!(
            "Iterated-SHA1",
            "$sisha1$1024$6f77746f6f77746f5fa823ad3c2dc9b58893df73d52b2108b2efce45"
        )],
    },
    Vector {
        slug: "mscash",
        hashcat: &[],
        john: &[john!("mscash", "root:176a4c2bd45ac73687676c2f09045353")],
    },
    Vector {
        slug: "lastpass-john",
        hashcat: &[],
        john: &[john!(
            "LastPass",
            "$lastpass$hackme@mailinator.com$500$i+hJCwPOj5eQN4tvHcMguoejx4VEmiqzOXOdWIsZKlk="
        )],
    },
    Vector {
        slug: "lp",
        hashcat: &[],
        john: &[john!(
            "lp",
            "$lp$hackme@mailinator.com$6f5d8cec3615fc9ac7ba2e0569bce4f5"
        )],
    },
    Vector {
        slug: "lpcli",
        hashcat: &[],
        john: &[john!(
            "lpcli",
            "$lpcli$0$lulu@mailinator.com$1234$3fec6cd2d8c049cbafe9fa6a9343f42f$f21d8e60ad22db53033e431700fb5e0c"
        )],
    },
    Vector {
        slug: "mongodb-john",
        hashcat: &[],
        john: &[john!(
            "MongoDB",
            "$mongodb$0$sa$75692b1d11c072c6c79332e248c4f699"
        )],
    },
    Vector {
        slug: "money",
        hashcat: &[],
        john: &[john!("money", "$money$1*fdb51efac3f4e440*bdaa2deb")],
    },
    Vector {
        slug: "oracle-john",
        hashcat: &[],
        john: &[john!("oracle", "O$SYSTEM#9EEDFA0AD26C6D52")],
    },
    Vector {
        slug: "oracle11",
        hashcat: &[],
        john: &[john!(
            "oracle11",
            "5FDAB69F543563582BA57894FE1C1361FB8ED57B903603F2C52ED1B4D642"
        )],
    },
    Vector {
        slug: "oracle12c",
        hashcat: &[],
        john: &[john!(
            "Oracle12C",
            "$oracle12c$e3243b98974159cc24fd2c9a8b30ba62e0e83b6ca2fc7c55177c3a7f82602e3bdd17ceb9b9091cf9dad672b8be961a9eac4d344bdba878edc5dcb5899f689ebd8dd1be3f67bff9813a464382381ab36b"
        )],
    },
    Vector {
        slug: "osc",
        hashcat: &[],
        john: &[john!("osc", "$OSC$2020$05de5c963ee6234dc7d52f7589a1922b")],
    },
    Vector {
        slug: "pwsafe",
        hashcat: &[],
        john: &[john!(
            "pwsafe",
            "$pwsafe$*3*fefc1172093344c9d5577b25f5b4b6e5d2942c94f9fc24c21733e28ae6527521*2048*88cbaf7d8668c1a98263f5dce7cb39c3304c49a3e0d76a7ea475dc02ab2f97a7"
        )],
    },
    Vector {
        slug: "radius",
        hashcat: &[],
        john: &[john!(
            "radius",
            "$radius$1*0*Passw0rd2*acf627289be7e214c8e328d0d01fcea2*fe18a76eec4abeeea09eb90e99b359f7"
        )],
    },
    Vector {
        slug: "rvary",
        hashcat: &[],
        john: &[john!("RVARY", "$rvary$5AA70358A9C369E0")],
    },
    Vector {
        slug: "skey",
        hashcat: &[],
        john: &[john!("skey", "0096 luky451004  b519dcfe18eb7aab")],
    },
    Vector {
        slug: "strip",
        hashcat: &[],
        john: &[john!(
            "STRIP",
            "$strip$*66cd7a4ff7716f7b86cf587ce18eb39518e096eb152615ada8d007d9f035c20c711e62cbde96d8c3aad2a4658497a6119addc97ed3c970580cd666f301c63ce041a1748ee5c3861ada3cd6ee75b5d68891f731b3c2e3294b08e10ce3c23c2bfac158f8c45d0332791f64d1e3ad55e936d17a42fef5228e713b8188050c9a61c7f026af6203172cf2fc54c8b439e2260d7a00a4156713f92f8466de5c05cd8701e0d3d9cb3f392ae918e6900d5363886d4e1ed7e90da76b180ef9555c1cd358f6d1ee3755a208fee4d5aa1c776a0888200b21a3da6614d5fe2303e78c09563d862d19deecdc9f0ec7fbc015689a74f4eb477d9f22298b1b3f866ca4cb772d74821a1f8d03fd5fd0d020ffd41dd449b431ddf3bbfba3399311d9827be428202ee56e2c2a4e91f3415b4282c691f16cd447cf877b576ab963ea4ea3dc7d8c433febdc36607fd2372c4165abb59e3e75c28142f1f2575ecca6d97a9f782c3410151f8bbcbc65a42fdc59fdc4ecd8214a2bbd3a4562fac21c48f7fc69a4ecbcf664b4e435d7734fde5494e4d80019a0302e22565ed6a49b29cecf81077fd92f0105d18a421e04ee0deaca6389214abc7182db7003da7e267816531010b236eadfea20509718ff743ed5ad2828b6501dd84a371feed26f0514bbda69118a69048ebb71e3e2c54fb918422f1320724a353fe8d81a562197454d2c67443be8a4008a756aec0998386a5fd48e379befe966b42dfa6684ff049a61b51de5f874a12ab7d9ab33dc84738e036e294c22a07bebcc95be9999ab988a1fa1c944ab95be970045accb661249be8cc34fcc0680cb1aff8dfee21f586c571b1d09bf370c6fc131418201e0414acb2e4005b0b6fda1f3d73b7865823a008d1d3f45492a960dbdd6331d78d9e2e6a368f08ee3456b6d78df1d5630f825c536fff60bad23fb164d151d80a03b0c78edbfdee5c7183d7527e289428cf554ad05c9d75011f6b233744f12cd85fbb62f5d1ae22f43946f24a483a64377bf3fa16bf32cea1ab4363ef36206a5989e97ff847e5d645791571b9ecd1db194119b7663897b9175dd9cc123bcc7192eaf56d4a2779c502700e88c5c20b962943084bcdf024dc4f19ca649a860bdbd8f8f9b4a9d03027ae80f4a3168fc030859acb08a871950b024d27306cdc1a408b2b3799bb8c1f4b6ac3593aab42c962c979cd9e6f59d029f8d392315830cfcf4066bf03e0fc5c0f3630e9c796ddb38f51a2992b0a61d6ef115cb34d36c7d94b6c9d49dfe8d064d92b483f12c14fa10bf1170a575e4571836cef0a1fbf9f8b6968abda5e964bb16fd62fde1d1df0f5ee9c68ce568014f46f1717b6cd948b0da9a6f4128da338960dbbcbc9c9c3b486859c06e5e2338db3458646054ccd59bb940c7fc60cda34f633c26dde83bb717b75fefcbd09163f147d59a6524752a47cd94"
        )],
    },
    Vector {
        slug: "tcp-md5",
        hashcat: &[],
        john: &[john!(
            "tcp-md5",
            "$tcpmd5$c0a83814c0a838280006002800b3d10515f72762291b6878a010007300000000$eaf8d1f1da3f03c90b42709e9508fc73"
        )],
    },
    Vector {
        slug: "vnc",
        hashcat: &[],
        john: &[john!(
            "VNC",
            "$vnc$*2F7532B3EFD17EEA5DD3A0949FFDF1D8*0EB42D4D9AC1EF1B6EF6647B9594A621"
        )],
    },
    Vector {
        slug: "zed",
        hashcat: &[],
        john: &[john!(
            "zed",
            "$zed$2$22$200000$4d05362c7ac3f518$a649427303fae36e"
        )],
    },
    Vector {
        slug: "zipmonster",
        hashcat: &[],
        john: &[john!(
            "ZipMonster",
            "$zipmonster$e0f68d6f40c5f157c169e9ca0a6f09fe"
        )],
    },
    Vector {
        slug: "o3logon",
        hashcat: &[],
        john: &[john!(
            "o3logon",
            "$o3logon$PASSWORD9$8CF28B36E4F3D2095729CF59510003BF$3078D7DE44385654CC952A9C56E2659B"
        )],
    },
    Vector {
        slug: "o10glogon",
        hashcat: &[],
        john: &[john!(
            "o10glogon",
            "$o10glogon$jimf$6DA8BE6D9713B7F9190DC0F87F1BB1BDFFE44EB1892E40915592980ECCE60AA3$1C08586339E5806DD45CF8E6D83CC6EA2B8CDCDE7CC9F00ADF43DA0F07309090$E2F3D778138213BF01FD743F2092FC976FD60AB2C9F4A1B1D9B08439325421B1"
        )],
    },
    Vector {
        slug: "o5logon",
        hashcat: &[],
        john: &[john!(
            "o5logon",
            "$o5logon$566499330E8896301A1D2711EFB59E756D41AF7A550488D82FE7C8A418E5BE08B4052C0DC404A805C1D7D43FE3350873*4F739806EBC1D7742BC6"
        )],
    },
    Vector {
        slug: "nk",
        hashcat: &[],
        john: &[john!(
            "nk",
            "$nk$*379637b4fcde21b2c5fbc9a00af505e997443267*#17737d3661312121d5ae7d5c6156c0298"
        )],
    },
    Vector {
        slug: "mysql-sha1",
        hashcat: &[],
        john: &[john!(
            "mysql-sha1",
            "*5AD8F88516BD021DD43F171E2C785C69F8E54ADB"
        )],
    },
    Vector {
        slug: "pst",
        hashcat: &[],
        john: &[john!("PST", "$pst$a9290513")],
    },
    Vector {
        slug: "pgpdisk",
        hashcat: &[],
        john: &[john!(
            "pgpdisk",
            "$pgpdisk$0*5*16000*3a1bfe10b9d17cf7b446cd94564fc594*1a1ce4453d81117830934495a2516ebc"
        )],
    },
    Vector {
        slug: "pgpsda",
        hashcat: &[],
        john: &[john!(
            "pgpsda",
            "$pgpsda$0*16000*12ad24b8dd12b751*19504b5f4e85c760"
        )],
    },
    Vector {
        slug: "signal",
        hashcat: &[],
        john: &[john!(
            "Signal",
            "$signal$1$6024$011d9eedb6367df21532acc22dcbb9b2$c492a9906443732b82ba846a14fad1eb$3f53a1cdff7417f3e576d390986218fc5808ae3a1470ca6c13b1fb0ca18673f7718e7f18cf633cd42841c6305953dd43a243e7fc6bdc2c4483d018d24792b7507d34b01a$a243e7fc6bdc2c4483d018d24792b7507d34b01a"
        )],
    },
    Vector {
        slug: "sl3",
        hashcat: &[],
        john: &[john!(
            "SL3",
            "$sl3$35831503698405$d8f6b336a4df3336bf7de58a38b1189f6c5ce1e8"
        )],
    },
    Vector {
        slug: "vtp",
        hashcat: &[],
        john: &[john!(
            "vtp",
            "$vtp$2$196$14000107000105dc000186a164656661756c740014000105000505dc000186a56368656e6100000010000103000605dc000186a6666666001800020c03ea05dc00018a8a666464692d64656661756c743000030d03eb117800018a8b74726372662d64656661756c7400000001010ccc040103ed0701000208010007090100072000040f03ec05dc00018a8c666464696e65742d64656661756c7400030100012400050d03ed117800018a8d74726272662d64656661756c740000000201000f03010002$80$0201010c646f6d61696e313233343536000000000000000000000000000000000000000000000015000000003134313030393134333631376010913064949d6f47a53b2ad68ef06b0000000106010002$6010913064949d6f47a53b2ad68ef06b"
        )],
    },
    Vector {
        slug: "sappse",
        hashcat: &[],
        john: &[john!(
            "sappse",
            "$pse$1$2048$8$0000000000000000$0$$8$826a5c4189e18b67"
        )],
    },
    Vector {
        slug: "known-hosts",
        hashcat: &[],
        john: &[john!(
            "known_hosts",
            "$known_hosts$|1|yivSFSAv9mhGu/GPc14KpaPMSjE=|I9L3FH6RGefWIFb0Po74BVN3Fto="
        )],
    },
    Vector {
        slug: "krb5-18",
        hashcat: &[],
        john: &[john!(
            "krb5-18",
            "OLYMPE.OLtest$214bb89cf5b8330112d52189ab05d9d05b03b5a961fe6d06203335ad5f339b26"
        )],
    },
    Vector {
        slug: "leet",
        hashcat: &[],
        john: &[john!(
            "leet",
            "salt$f86036a85e3ff84e73bf10769011ecdbccbf5aaed9df0240310776b42f5bb8776e612ab15a78bbfc39e867448a08337d97427e182e72922bbaa903ee75b2bfd4"
        )],
    },
    Vector {
        slug: "md5ns",
        hashcat: &[],
        john: &[john!("md5ns", "admin$nMjFM0rdC9iOc+xIFsGEm3LtAeGZhn")],
    },
    Vector {
        slug: "monero",
        hashcat: &[],
        john: &[john!(
            "Monero",
            "$monero$0*e0b3e6cadcb68205dd0608b79576034e7a29000806fffb766a655714a4a822bcd1d93c5524b6ef91fd8ae94f0d3ffe1e55a78305c39e52892a7e34d4dfe6983d8492967fe3cd4ea611829c37fc5f65107e8c54b72a96fe63c20b71dda388e08114b88b15055953f182186c19fe9c1816819dc89d162ffffab552634515a8a5aec13300541e6e83d0227af34557b3cc2f64951af8890674a632d48385fe8fc6aca8ec286729793ebd7a85248aaa6c00cb8b530094d6316f9c92a50bea7eb201fbda5a62bcba0413fc3cedf07cf74c3b49a27dd0ed555b7a79d18ab58c89bfaf5c53eb25f01fa950b8afe18c3d4098ce794c2920cc834c915204f3003c37f0aab9f98810b0e3ecd7202a375e0f7e5d845b68abaf45df587756e7c058f6bde6a4cee8a7544efe1d2d71d272b22817dcca7f0969668c5b5bb28d472fc0c429ed25d8987c9537bc1fe309ff39a1dd652c9d618dc433cc4de93906565c44d5eade81b2afbd6fb835f6bea472c1bf949cff305e33252e7921875df833bc6cac040399f0f4445716de0c0fb61518589c570ee76483537b091fad80cfb34b3014740f3456eb2ff9a429004d1ca156ea904290d6edf76e0953ea0bfa6075e88f8bdb63350f317909beccdf7e764b64201d6005b00f33b40e9c1acc2f3e7b7f986340ad7ede0b9a246d9fac416b58937c0e788fdb0f92cdd50cad0a8cb6e926cc0bcfc066d5c5acf70732d58825e1ff2f77eba4697aab68deeb00ffe7b5dffd65436ccf4d6d7148901067628733fc5997b368076bff26424d46d5ba0966d730c6dbdabb2bd9882aed8055e58980ce1000ae6853763187368741a2a3da21efc95583f5705859ffb3c45e8cbef59cafbb76cac69f86e8fb1eea7768ff51ddc66065bac297ea82afbdf8bcfdd03fa4a89dbfc7055e73ab384d6b9fae3d142e9a8768f0f94f26030559da03bcc5df8734c4e3202921faa39aa0bd78ce7d4302143fadf7ac5c97f41dc87d006e241dc10aa22eec9e075d8557a93a6bc7725de06a7c213c47e6b24142131b3d9cb45516b8ef5c8d77103502ac77e53b402ea0d92d01663c7148d99d889d35f76d2177a38bc4caee131fa941aa56a0fe1007e0470306cfe4f8a3e9fc0c63eb983cc625e5716aad730d07bd2bd148516bd4667b2f56b4b3dec528367968db74347be4052a9dd2045d5660bb835d38ca909665048f8a89573729339598c6221b1d12c2f2"
        )],
    },
    Vector {
        slug: "net-ah",
        hashcat: &[],
        john: &[john!(
            "net-ah",
            "$net-ah$0$4500004000150000ff330000c0a87c01e000001270040000c0a87c01000000150000000000000000000000002133650102016c3e0a00018c0000000000000000$ad719a912d50a53935d9ad41"
        )],
    },
    Vector {
        slug: "net-md5",
        hashcat: &[],
        john: &[john!(
            "net-md5",
            "02020000ffff0003002c01145267d48d000000000000000000020000ac100100ffffff000000000000000001ffff0001$1e372a8a233c6556253a0909bc3dcce6"
        )],
    },
    Vector {
        slug: "net-sha1",
        hashcat: &[],
        john: &[john!(
            "net-sha1",
            "$netsha1$20440a340000000100000000000f4240000f424000000000051c010000000001$709d3307304d790f58bf0a3cefd783b438408996"
        )],
    },
    Vector {
        slug: "openssl-enc",
        hashcat: &[],
        john: &[john!(
            "openssl-enc",
            "$openssl$1$0$8$a1a5e529c8d92da5$8de763bf61377d365243993137ad9729$1$0"
        )],
    },
    Vector {
        slug: "openvms",
        hashcat: &[],
        john: &[john!("OpenVMS", "$V$9AYXUd5LfDy-aj48Vj54P-----")],
    },
    Vector {
        slug: "pgpwde",
        hashcat: &[],
        john: &[john!(
            "pgpwde",
            "$pgpwde$0*9*100*17*ecbf39c8978c4867568f2a58304ff00f*746dfc8106fc4e96a49543d2e1acdc31541dd7b341462289049038263b9f38cfebde0c004c87c664f2ad492311694bbe6ff3f940dac2b88c67054d8927a43fbd633659d1ba8d433dcfb1e824c344efecb6841690c05fec567068e022f04ece5e95220877d97503c352b86bf65bb1df14899b3b6eff9df38c50f2540c4fc2e242"
        )],
    },
    Vector {
        slug: "putty",
        hashcat: &[],
        john: &[john!(
            "PuTTY",
            "$putty$1*16*1*0*10c434c33cf160352b7a5b3a1ecd8434f1066cac*432*000000077373682d647373000000806bb7ed4d03163f5be550dba68e0f1af7dae4b49f736ab452552a1163210c1366fd1f65a31bb526b1d3028a31d30b3315c19dc02417db99336f00b1f9565431d02fc59cd756ab6fe506b959df3799e4a70fcbe54ad9ef34d338014add8ac1f57f2a6dce8403c93709cb23d3c379f5de4f9fc45a73b3f9a43e6c1cc220bd38274b0000001500b4bf70cda203027a13135d43e459872eed384a3d0000008049a7d8e8d1db1630f9a9f6b1bf275d01e4287a4c2f038707d8c07ab664dbd264f6b4676de93c1f003bb57146a82314ab6c426628498209fa33c68a881abfd90dc1e978d430c9ace78d6c9895938494e91e3ca50132c9bde8fae4381e6fe59d03a9feee39b10cb2fea4e4d5f5ef10e523d34925f105eff665db2ac35e6cf0a1ac000000800def6e4f7ed4af0f1f8ed9524595d3fecd0a191ea9a6402d4235ee59ff2000011e36b5936280a3b5dc0b8d8ea7747e04ad92e46be8cb374d931c1e78bbdafea4ac16aba2e4b3cbd0779d28a609e848fb54332a169f24fac5e4c736c3dae4f95afe0aacaffb2d4829956fbd17d514614a45f8eefdd0d7d4982d101d72002f05fd*32*b38180c482949f3b4f44a20fd599c2cb411c671b4b120663bef9a61b360e442a*ssh-dss*aes256-cbc*dsa-key-20120721"
        )],
    },
    Vector {
        slug: "sybase-prop",
        hashcat: &[],
        john: &[john!(
            "Sybase-PROP",
            "0x2905aeb3d00e3b80fb0695cb34c9fa9080f84ae1824b24cc51a3849dcb06"
        )],
    },
    Vector {
        slug: "tezos",
        hashcat: &[],
        john: &[john!(
            "tezos",
            "$tezos$1*2048*put guide flat machine express cave hello connect stay local spike ski romance express brass*jbzbdybr.vpbdbxnn@tezos.example.org*tz1eTjPtwYjdcBMStwVdEcwY2YE3th1bXyMR*a19fce77caa0729c68072dc3eb274c7626a71880d926"
        )],
    },
    Vector {
        slug: "vdi",
        hashcat: &[],
        john: &[john!(
            "vdi",
            "$vdi$aes-xts256$sha256$2000$2000$64$32$709f6df123f1ccb126ea1f3e565beb78d39cafdc98e0daa2e42cc43cef11f786$0340f137136ad54f59f4b24ef0bf35240e140dfd56bbc19ce70aee6575f0aabf$0a27e178f47a0b05a752d6e917b89ef4205c6ae76705c34858390f8afa6cf03a45d98fab53b76d8d1c68507e7810633db4b83501a2496b7e443eccb53dbc8473$7ac5f4ad6286406e84af31fd36881cf558d375ae29085b08e6f65ebfd15376ca"
        )],
    },
    Vector {
        slug: "keystore",
        hashcat: &[],
        john: &[john!(
            "keystore",
            "$keystore$0$2126$feedfeed000000020000000100000001000f616e64726f696464656275676b65790000013c3ea72ab000000501308204fd300e060a2b060104012a021101010500048204e9e76fea55eed58e4257c253b670948abb18093fbbb667f00807560242f17a4b3cd8b90d0e2a5c6c96f758f45e0e2320039c10af4ecc95e56930fd85713318da506bb48fa586b5caf7c286cf3b66134cb0e13dcdbc665680fb1214d9db2405ccb297acdefd4f5f7cb1c1babd5b77414223b45ae11ab0ec0a2ce5423a6ab69f372adb79a38973a0fde89f9b1e8ef62de04a5e6b35008ce3191c350f98a98ed917ccfc3524f9a4786a3ab055cee25efb118f67d73cacfdd5a3f0ca04399d2b31acfffc63ab6b47f371ff879768ef84bc8c58bcfaab1539e6343cf7b81d0446f57abbeb84fb20b540616aabbfd4c823acb2124ea25538c7531609b72b8da90327a8a3845bcfd69d659a1a77c35efb0d62651e4178459dfde9e165edc6d52cc3d8fee78e3132346588b09e3d27e1400421d33e88748ed1c01af1dc6064a71c991e0322e72c55ed5bcd8c232048bddfecd299d4d9c296639866dd21ad073a4993733b44bac4d6a77eec05cda65d5d9ad0a42a5aa9d443e3ba7ea5744e7fdc2617f527cd9cf480bce033bd5eec6746b2a58328aeed26757664109e1046c93e2377db18c58c35828916f4a42964aae2fe75ad944896bd321ae92cd5723735b37f85250a635a8d1875d3efb2ffbcabc3602ea3b6952da060ec1d1c0a961b1a50836dee911a166e09a33d036d6ef7dc988545b580841945a8718b178bb06ef8e78c6703a496cf66990d57b696b2117922ee1855dff439b2bda3201b145fdb4533b7d2cfa22291a79bac67bb6b3d963dd4137b6208931f02c3ee30bfd0731443edadd5bfffec0147f5f2bd13930deace26fec0ebf0c1befe1294875fb9d8a08919fdc1697ec78d1b86c03a0db4e61bd6a9db6803fdd8e2547ead44bd48cf223b964b0c6903ede0fc0e1b7d02b83ba18ed649bc0e40896ff7cde1d092a9f30314da8fc67d113c79fe7046da75bc090b08b3f31a5d0feb33abab2c608e3afaca1521f2809ae79c14e5ab16d7fa319ddc4dbae61cf41bd15829055970f26361fc1ae22a15e401b25eb500411e70a3cacca38e0d59a6add6513c02d0e6a766303e231d8adf8368b1579e7d58a7d3a5981542c9b8fec0b1780713031fefa60d93755215cbbc34f27634537b6c4fe391578be1a3547fc97d1eeb3e8b11444e8ad99902911fba55034a2796d791039bb29bd193406f05b942f69d47a4a236a64f610e7808387586f4a96a84059e93b11355ecd9125e7a805503e41f4097893b043c7d539d76933515c8fbde11f2a69a6f47aebbac3ed29b0231b3a74ecc9a5421ad61c995a039e44c0a8717dd6e5efbdc2f6ab8daefbc58867ca2e852780c66d1163a03662c34b5365983405093452bb004f78eb973a804edb1b4e8214ab982ed9c81992cc508d8852288fee4ced3af41cca7baaddb828830f3e7dd7c92610def60bbaf6a866e84ea81bd4e88a5b5a035b15b370f942af17f213706c681a59da20b150697c188edb4ac8b59b3babf9c895078f268940aa805c15a2712042c22ce5c44a62554d5f2efb6db179e1db29570b6b063d00349a0273277751e6adf32b6d36b02cb81025d80e620b61a418b0584441c087ce75ed03c871dfe8463a9a3641b036e849fd0fdc9b381ebe43e067353642f182d67ef6bef43463dc6b8d7abd035677b443440c7624d91baa11002e193d86a76974eef4f6fb44a8c440b73ddb323e9eb8f7fdd67aa368ce6aefdff1060e6a519d48b28718b1548e4665360f141d5e16027f0e7c41d07c582dd2a29fa55a00f000000010005582e353039000003113082030d308201f5a00302010202043e310348300d06092a864886f70d01010b05003037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f6964204465627567301e170d3133303131353134343030385a170d3133303431353134343030385a3037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f696420446562756730820122300d06092a864886f70d01010105000382010f003082010a02820101009116fccceb121c8951fb12992ef59393a8c2aeab4ec76a30a71d3aca40a277ab1500613c30bda5472bc15812bdbe9395b4a6009edaf94ca7427cd94ca840c0ac9d42ab8246a401628dbba7acb408738929b75f319d496e8594afd75423c07299ec195efce351b7f2b730ad5e61ab292a4783611cdad41139302ada3e239656c2ec842a59418efc711072e75193cfba1105a1980a631f4a513e4116a89806a47f8b308c03684e2ce83e03c40c438445143fa3fab756909e101f89410a35bb6e6a5cbdcef19d0359c8ed7862fe7ae7f81c32a9a75f72419f89eddbe4acc4373e45a390fd185ae3b28adb8445c4e38e30773acad396788428b0321936f241e905c50203010001a321301f301d0603551d0e041604148c2df598ae53bebe11c4e4696abc6cad6bce4286300d06092a864886f70d01010b05000382010100507e62f723154b2e818140fbc47547c8a600f97a580de244afdf6cdc02977aa7fb990c77a0d79d3ef53aadcf9d7705b385c365e3e06bf15de1a9d3f5c6b6b40fc4b629f763da8f12fc16a005b66026de2be8f1144d37ef14fc1c99dc13dd33fc750898a7ac9e2a12543402ba5021432a8453d38b4879a95736f65956d13d92d96b6f546b853c92f0cc51a98dcd233076ae285d5ed44601f1fe361974c74067eb263386fe8e085e8b20c3cd72768d4265bd9bf4937b2aeae3323c6289dfe75e820907ba38e85b3fc2ceb44e770b91babfdf1d003bbc56ed7066f97ba86e0648ff0874a31c1563d52f42f38005b3698f800be11257f405b185ca421113072f8531$a8ab7a46059faddb183f66d4aef78f47911c88aa$1$1281$308204fd300e060a2b060104012a021101010500048204e9e76fea55eed58e4257c253b670948abb18093fbbb667f00807560242f17a4b3cd8b90d0e2a5c6c96f758f45e0e2320039c10af4ecc95e56930fd85713318da506bb48fa586b5caf7c286cf3b66134cb0e13dcdbc665680fb1214d9db2405ccb297acdefd4f5f7cb1c1babd5b77414223b45ae11ab0ec0a2ce5423a6ab69f372adb79a38973a0fde89f9b1e8ef62de04a5e6b35008ce3191c350f98a98ed917ccfc3524f9a4786a3ab055cee25efb118f67d73cacfdd5a3f0ca04399d2b31acfffc63ab6b47f371ff879768ef84bc8c58bcfaab1539e6343cf7b81d0446f57abbeb84fb20b540616aabbfd4c823acb2124ea25538c7531609b72b8da90327a8a3845bcfd69d659a1a77c35efb0d62651e4178459dfde9e165edc6d52cc3d8fee78e3132346588b09e3d27e1400421d33e88748ed1c01af1dc6064a71c991e0322e72c55ed5bcd8c232048bddfecd299d4d9c296639866dd21ad073a4993733b44bac4d6a77eec05cda65d5d9ad0a42a5aa9d443e3ba7ea5744e7fdc2617f527cd9cf480bce033bd5eec6746b2a58328aeed26757664109e1046c93e2377db18c58c35828916f4a42964aae2fe75ad944896bd321ae92cd5723735b37f85250a635a8d1875d3efb2ffbcabc3602ea3b6952da060ec1d1c0a961b1a50836dee911a166e09a33d036d6ef7dc988545b580841945a8718b178bb06ef8e78c6703a496cf66990d57b696b2117922ee1855dff439b2bda3201b145fdb4533b7d2cfa22291a79bac67bb6b3d963dd4137b6208931f02c3ee30bfd0731443edadd5bfffec0147f5f2bd13930deace26fec0ebf0c1befe1294875fb9d8a08919fdc1697ec78d1b86c03a0db4e61bd6a9db6803fdd8e2547ead44bd48cf223b964b0c6903ede0fc0e1b7d02b83ba18ed649bc0e40896ff7cde1d092a9f30314da8fc67d113c79fe7046da75bc090b08b3f31a5d0feb33abab2c608e3afaca1521f2809ae79c14e5ab16d7fa319ddc4dbae61cf41bd15829055970f26361fc1ae22a15e401b25eb500411e70a3cacca38e0d59a6add6513c02d0e6a766303e231d8adf8368b1579e7d58a7d3a5981542c9b8fec0b1780713031fefa60d93755215cbbc34f27634537b6c4fe391578be1a3547fc97d1eeb3e8b11444e8ad99902911fba55034a2796d791039bb29bd193406f05b942f69d47a4a236a64f610e7808387586f4a96a84059e93b11355ecd9125e7a805503e41f4097893b043c7d539d76933515c8fbde11f2a69a6f47aebbac3ed29b0231b3a74ecc9a5421ad61c995a039e44c0a8717dd6e5efbdc2f6ab8daefbc58867ca2e852780c66d1163a03662c34b5365983405093452bb004f78eb973a804edb1b4e8214ab982ed9c81992cc508d8852288fee4ced3af41cca7baaddb828830f3e7dd7c92610def60bbaf6a866e84ea81bd4e88a5b5a035b15b370f942af17f213706c681a59da20b150697c188edb4ac8b59b3babf9c895078f268940aa805c15a2712042c22ce5c44a62554d5f2efb6db179e1db29570b6b063d00349a0273277751e6adf32b6d36b02cb81025d80e620b61a418b0584441c087ce75ed03c871dfe8463a9a3641b036e849fd0fdc9b381ebe43e067353642f182d67ef6bef43463dc6b8d7abd035677b443440c7624d91baa11002e193d86a76974eef4f6fb44a8c440b73ddb323e9eb8f7fdd67aa368ce6aefdff1060e6a519d48b28718b1548e4665360f141d5e16027f0e7c41d07c582dd2a29fa55a00f"
        )],
    },
    Vector {
        slug: "chap",
        hashcat: &[],
        john: &[john!(
            "chap",
            "$chap$0*cc7e5247514551acdcbf782c4027bfb1*fdfdad5277812ae40956a66f3db23308"
        )],
    },
    Vector {
        slug: "cardano-john",
        hashcat: &[],
        john: &[john!(
            "cardano",
            "$cardano$1$b57361ebe335fa171a260fea7d3277579c212dc74fc2a408d6cbd8a6e7a847cab3c44c5fb190705ddd2698f2d5390798893349b4321e7474b1ce06c9d410b3d6055b42d4a95f19cb34b516a160a306c0eaef398e70ea91da450ccb2a7819e95b0102030405060708091011121314151617181920212223242526272829303132"
        )],
    },
    Vector {
        slug: "dmd5",
        hashcat: &[],
        john: &[john!(
            "dmd5",
            "$DIGEST-MD5$chris$elwood.innosoft.com$OA6MG9tEQGm2hh$imap/elwood.innosoft.com$OA6MHXh6VqTrRk$00000001$auth$d388dad90d4bbd760a152321f2143af7"
        )],
    },
    Vector {
        slug: "eigrp",
        hashcat: &[],
        john: &[john!(
            "eigrp",
            "$eigrp$2$020500000000000000000000000000000000002a000200280002001000000001000000000000000000000000$0$x$1a42aaf8ebe2f766100ea1fa05a5fa55"
        )],
    },
    Vector {
        slug: "hdaa",
        hashcat: &[],
        john: &[john!(
            "hdaa",
            "$response$679066476e67b5c7c4e88f04be567f8b$user$myrealm$GET$/$8c12bd8f728afe56d45a0ce846b70e5a$00000001$4b61913cec32e2c9$auth"
        )],
    },
    Vector {
        slug: "hsrp",
        hashcat: &[],
        john: &[john!(
            "hsrp",
            "$hsrp$000004030a64010000000000000000000a000064041c010000000a0000140000000000000000000000000000000000000000$52e1db09d18d695b8fefb3730ff8d9d6"
        )],
    },
    Vector {
        slug: "ike-john",
        hashcat: &[],
        john: &[john!(
            "IKE",
            "$ike$*0*5c7916ddf8db4d233b3b36005bb3ccc115a73807e11a897be943fd4a2d0f942624cb00588d8b3a0a26502b73e639df217ef6c4cb90f96b0a3c3ef2f62ed025b4a705df9de65e33e380c1ba5fa23bf1f9911bbf388d0844256fa0131fc5cf8acb396936ba3295b4637b039d93f58db90a3a1cf1ef5051103bacf6e1a3334f9f89*fde8c68c5f324c7dbcbadde1d757af6962c63496c009f77cad647f2997fd4295e50821453a6dc2f6279fd7fef68768584d9cee0da6e68a534a097ce206bf77ecc798310206f3f82d92d02c885794e0a430ceb2d6b43c2aff45a6e14c6558382df0692ff65c2724eef750764ee456f31424a5ebd9e115d826bbb9722111aa4e01*b2a3c7aa4be95e85*756e3fa11c1b102c*00000001000000010000002c01010001000000240101000080010001800200018003000180040002800b0001000c000400007080*01000000ac100202*251d7ace920b17cb34f9d561bca46d037b337d19*e045819a64edbf022620bff3efdb935216584cc4*b9c594fa3fca6bb30a85c4208a8df348"
        )],
    },
    Vector {
        slug: "krb4",
        hashcat: &[],
        john: &[john!(
            "krb4",
            "$af$UMICH.EDU$bb46613c503ad92e649d99d038efddb2"
        )],
    },
    Vector {
        slug: "krb5-john",
        hashcat: &[],
        john: &[john!(
            "krb5",
            "$krb5$oskov$ACM.UIUC.EDU$4730d7249765615d6f3652321c4fb76d09fb9cd06faeb0c31b8737f9fdfcde4bd4259c31cb1dff25df39173b09abdff08373302d99ac09802a290915243d9f0ea0313fdedc7f8d1fae0d9df8f0ee6233818d317f03a72c2e77b480b2bc50d1ca14fba85133ea00e472c50dbc825291e2853bd60a969ddb69dae35b604b34ea2c2265a4ffc72e9fb811da17c7f2887ccb17e2f87cd1f6c28a9afc0c083a9356a9ee2a28d2e4a01fc7ea90cc8836b8e25650c3a1409b811d0bad42a59aa418143291d42d7b1e6cb5b1876a4cc758d721323a762e943f774630385c9faa68df6f3a94422f97"
        )],
    },
    Vector {
        slug: "wowsrp",
        hashcat: &[],
        john: &[john!(
            "WoWSRP",
            "SOLAR:$WoWSRP$6D00CD214C8473C7F4E9DC77AE8FC6B3944298C48C7454E6BB8296952DCFE78D$73616C74"
        )],
    },
    Vector {
        slug: "rakp",
        hashcat: &[],
        john: &[
            john!(
                "RAKP-MD5",
                "$rakp$000476044b237ebb4f2a415ce488ebc91996043c8011e26079633b706424119e09dcaad4acf21b10535000000000000000000000000000001404726f6f74$102546a8888f78d420fc48ba84108ee2"
            ),
            john!(
                "RAKP-SHA1",
                "$rakp$a4a3a2a03f0b000094272eb1ba576450b0d98ad10727a9fb0ab83616e099e8bf5f7366c9c03d36a3000000000000000000000000000000001404726f6f74$0ea27d6d5effaa996e5edc855b944e179a2f2434"
            ),
            john!(
                "RAKP-SHA256",
                "$rakp$1eaf72c001407792e65364f6100997e2946b8d9c2a57a4a8574b99694ca321f30401769c58cfbcd09cc2c43a2c74de030010debf6022a771140474657374$669c87a9a6871f77134f3159c9f421a571723f5493fdeec173309b362ee8b259"
            ),
        ],
    },
    Vector {
        slug: "andotp",
        hashcat: &[],
        john: &[john!(
            "andOTP",
            "$andotp$0*0fb35cdb85dc40cd30bb4a0a*2fa0*75e3406c9f3b6f534286ea892a6adcde"
        )],
    },
    Vector {
        slug: "bks",
        hashcat: &[],
        john: &[john!(
            "BKS",
            "$bks$0$1$20$2036$20$a2c6157bea089967ccfa13670ae992a1265ab7b5$01001a636861726c65732070726f78792073736c2070726f7879696e6700000140737320ac000000000005582e353039000004623082045e30820346a003020102020101300d06092a864886f70d01010505003081913123302106035504030c1a436861726c65732050726f78792053534c2050726f7879696e6731243022060355040b0c1b687474703a2f2f636861726c657370726f78792e636f6d2f73736c3111300f060355040a0c08584b3732204c74643111300f06035504070c084175636b6c616e643111300f06035504080c084175636b6c616e64310b3009060355040613024e5a3020180f31383939313233313132303030305a170d3338303932343033313930355a3081913123302106035504030c1a436861726c65732050726f78792053534c2050726f7879696e6731243022060355040b0c1b687474703a2f2f636861726c657370726f78792e636f6d2f73736c3111300f060355040a0c08584b3732204c74643111300f06035504070c084175636b6c616e643111300f06035504080c084175636b6c616e64310b3009060355040613024e5a30820122300d06092a864886f70d01010105000382010f003082010a02820101008349587455efb272e397a31d3b52d9b13115c93f320766d2d451117f45c40285506027079ed439cabb94d44f1ae136eb1e79bf77abe43345ad1d436809cf9e035c439272f3ca917dcadd7fbd0e3929f1a345f0b89096130bbd116f8d3ab5655789b7b0831325bd22903f198da6bdda30c08dfd17ce9ab51c48555264307bcf789a2b6c48df4ecaf3ea2c092ee737ad8f397900ac03303bfe2ae43549030a7866cb6fe9b04b9f6ec498b4e7369e99b45491bf093858a77c72f8adc818e018d413265e39446be514f78eb57a23aa88f630776f861a9163e04ad38ee8a5c9219d0fc23f6b9a6324455dea6f4a6a251eca1fa3d6288cb89fd12a2062a3a015a56f250203010001a381bc3081b9300f0603551d130101ff040530030101ff307706096086480186f842010d046a136853534c2050726f7879696e6720697320656e61626c656420696e20436861726c65732050726f78792e20506c6561736520766973697420687474703a2f2f636861726c657370726f78792e636f6d2f73736c20666f72206d6f726520696e666f726d6174696f6e2e300e0603551d0f0101ff040403020204301d0603551d0e04160414bb27f4cb2eb6dbb058101bbd803f38d208d76129300d06092a864886f70d010105050003820101000041f935f30b209e56360f7e3d9c30314a213323c47edcea1467600a50ffe4e8e39dfca8c8d34463c34745ff04c870f1df28bb772db0cf1bca677b70842c742bc6d5fb00559ad643c6bf2c95bd0b855a961d7d6a3eada9c642e9a789474c4ad838c6f732d8d859548d30829df7a32d098fe3f00147daf08c0b37dd597184c1e27a61ea42050c73994e809013cb21e37bf84bf923bcefea6164fd28ab9058ccc48f1f486fc1c47ebd8a9c933f542401b11f36a003e47b141a41c7b326d18d023e11edb445699aa44800254ea33f174fd5eb1ccce6a09365751ff905988c06315b5575067bf65ec24cad1a6a601846d1d2f51f1f420a2762990b044000619d1c8400$3b798574df20a2be48edb0b0c687cce2cf5c293c"
        )],
    },
    Vector {
        slug: "blackberry-es10",
        hashcat: &[],
        john: &[john!(
            "Blackberry-ES10",
            "$bbes10$76BDF6BE760FCF5DEE7B20E27632D1FEDD9D64E1BBCC941F42957E87CBFB96F176324B2E2C71976CEBE67CA6F400F33F001D7453D80F4AF5D80C8A93ED0BA0E6$DB1C19C0"
        )],
    },
    Vector {
        slug: "clipperz",
        hashcat: &[],
        john: &[john!(
            "Clipperz",
            "$clipperz$e8be8c8d9c1d5dc79ecc7b15d1787d5b5dc22e815ddb0b37f6145ca667421f1f$e0bc11ee4db80a3ecabd293f5201cb747856361192c68f4133ea707c7d4d2d32*hackme@mailinator.com"
        )],
    },
    Vector {
        slug: "cryptosafe",
        hashcat: &[],
        john: &[john!(
            "cryptoSafe",
            "$cryptosafe$1$RJ+YWtuyOoLnnOpOdmj43+hwO5cquMsSO3f/OiQfINofM+c0JVbIyUTQg3St+1Ue09QiZKlNnCAmlPHq2wuI31QoZQ/KNKZT/VMLd3qYbkOv873HT4wsYeavSwOqrdVdxpEimkqgdDkGP7XHfeFUCv6+jXFZioiR8jYrgxA8fDQQ5C+YReuvfiqLGaVrC9ih58X8Q7NLxAlQTGSQvHgsZI6DNfAsXw3Zt++fIJh9bdLzHDEBF/pLp47zj132UOYr6TuufnnA+HeUISdk+xH6/w=="
        )],
    },
    Vector {
        slug: "dashlane",
        hashcat: &[],
        john: &[john!(
            "dashlane",
            "$dashlane$1*523f57cffb40609f4a3b00288a1223cf8ec4b8c1610fe4afdea345a21563eae9*220*5e906e7dce3d12999bf7d627756e2267f3f5061e457a47736d1174959ed4f9e316a30fdee0a60493de83dd6f8b669ed420172ad9e2f1c1269aa9716d664cf2a005b44834f696c0473a8858647adc07d9b02ec3ece33eae250289bb1d2efbe9c4c181ae326dccabb552939f5fca72dc4b83c846e95a67eb3fbd04ca5fc216f4de16893bb434ba878e34e1870fb1814355e192488bb6bdab8e18f3c983e599800c458711a27ebeb595f6757a1393035b92bbc46bc9ccea75b77ea47b413e08b3aa9818ebf3369eb954d1fa44a202c2cd9e28d48b3dd5a185caa4674caf"
        )],
    },
    Vector {
        slug: "encfs",
        hashcat: &[],
        john: &[john!(
            "EncFS",
            "$encfs$192*181474*0*20*f1c413d9a20f7fdbc068c5a41524137a6e3fb231*44*9c0d4e2b990fac0fd78d62c3d2661272efa7d6c1744ee836a702a11525958f5f557b7a973aaad2fd14387b4f"
        )],
    },
    Vector {
        slug: "enpass",
        hashcat: &[],
        john: &[john!(
            "enpass",
            "$enpass$0$24000$700dfb6d83ae3b4b87935ed8246123363656de4273979a1365197a632c6b1ce68ca801d0bb50d93c9a0509fbb061bba2ad579ed0d48ee781508c853b9bd042d3275cc92781770a211ecd08a254db873e50664a14b394d63e3e443a82d69c7df84c592a60b5b620e241c9675f097f931093f6ebf67f56e5db0d82eb61ff9da3636bf7c79598e6ee1f34b7abd2b1e5e3ae9e9a219de50d9c079fb7fb21910139468619c6ac562a4157c0e8e85df08b54aff33ec2005e2214549ba04d794882051e8e245f63f822d469c6588ccd38c02154f21cdfd06acd5ed1b97cbe7e23648ce70c471560222cd8927b0567cd0a3c317b7a8add994dc8fcda89ae4afc33c1260192e3c8c3ca9d50347a91a82025c1cb127aede8334286cc26f86591d34483b90d86d1e1372f74d1b7eee5aa233ed9199a3de01e7d16b092b4c902a602a16edcf03005596abc5c24f249dbb48236dc27738e93949c383734f6e39bf199fcd3fd22ab9268d1678d7259f94ab2c012e924ff2d26772ebf2cccc0ffe795264cd7a035f52f258b5ce78b7f1353c120f1aa30cbe943832fa70d3762222365109521c1a70a7ace321ddda173fb731c1d6f65c8e4af8f7b62660bc70a2c9ece21f8cddbe65d047f92aa6ca55a90864cb12c757030a7755ec4601a6f28dc2e728ee3f84fc1d39c261c845335a9d19e3356192b257186ff606756e58df67c11d2886870c90b69f5b51630f72d79f51884528214e9987865debb6b23ce8deecfb67cd43450a73675b53fcd20b6ae1da13f69dd349045d0b9b7dded042020ad081143231c79778d01f91c6e6df823885860ea781dd07867222b438599d02a815a4c18409c5e97a3d8e870ce1401bce7c556f05ac77af2659ef9b13d0d4df32a54674ef451cc2ffef50d4ca31efe19644db389ae9f0ce97686e5e53f1d82b98136258708911641b3a251eea41e6433534eb2810df49e040901367ee42b12cf7f853bab46f5360da2429989d232c9f6897e44221a2a5e946563db10423cfb073b6abf1e977f746e1d9c0fb929bb0e2c9dd50c11c76e0219a0004aa747de0db075305d4582293727f16f215403a9ca3d99af1750343101162954daebd58358b21276346519b2c05942223ad8314073900169b222b0e24f79c76dc61b4701edba670bc07bd4fa3c5a2179c69560f23ed925594f3ca230ed780904e82c7f8f6ee737c059d1af79eef0c1f8e6a0fdace62e87d88ad3b345afb96ea7b26eb0426585ea064933c8b8ec9264d910dc1573363dbec0755de36221eb368c5b2703c254a4d3d29d1b247c46200f743fe5f04f4b8fec2f143ba1276cc4b2bd7802bfe6fa63a49eb7a77f3443db74e0c889441fc2154d85bdbc0bbdc80eca3852ff8c7d7738ff9ba9eaa18174f4f65c526940289717bb87d05fd4eeef1272065b4bfa4d6f31a1b23c50e1355988"
        )],
    },
    Vector {
        slug: "keplr",
        hashcat: &[],
        john: &[john!(
            "keplr",
            "$keplr$31aa4c50f62b54b4e4bf0a1f6ff38ef8bcc3902ab309533037e96ff60ecfd4a6*8a3b159e9fd7e104049aca4f432575b5bb95c7e3f6829e1549ca9066ed4fcf0a6ff4eb355923a28a4171af171bc36055a2631f10f35dd0b8a5872a51ca9c2c09e7f4e407ec614d546717e1a03c*8ed6786d2ea66ac9a2f8347b8c84ff7eb250c0d5a9aae616500f24e635a7ada7"
        )],
    },
    Vector {
        slug: "keyring",
        hashcat: &[],
        john: &[john!(
            "keyring",
            "$keyring$db1b562e453a0764*3221*16*0*02b5c084e4802369c42507300f2e5e56"
        )],
    },
    Vector {
        slug: "agilekeychain",
        hashcat: &[],
        john: &[john!(
            "agilekeychain",
            "$agilekeychain$2*1000*8*7146eaa1cca395e5*1040*e7eb81496717d35f12b83024bb055dec00ea82843886cbb8d0d77302a85d89b1d2c0b5b8275dca44c168cba310344be6eea3a79d559d0846a9501f4a012d32b655047673ef66215fc2eb4e944a9856130ee7cd44523017bbbe2957e6a81d1fd128434e7b83b49b8a014a3e413a1d76b109746468070f03f19d361a21c712ef88e05b04f8359f6dd96c1c4487ea2c9df22ea9029e9bc8406d37850a5ead03062283a42218c134d05ba40cddfe46799c931291ec238ee4c11dc71d2b7e018617d4a2bf95a0c3c1f98ea14f886d94ee2a65871418c7c237f1fe52d3e176f8ddab6dfd4bc039b6af36ab1bc9981689c391e71703e31979f732110b84d5fccccf59c918dfcf848fcd80c6da62ced6e231497b9cbef22d5edca439888556bae5e7b05571ac34ea54fafc03fb93e4bc17264e50a1d04b688fcc8bc715dd237086c2537c32de34bbb8a29de0208800af2a9b561551ae6561099beb61045f22dbe871fab5350e40577dd58b4c8fb1232f3f85b8d2e028e5535fd131988a5df4c0408929b8eac6d751dcc698aa1d79603251d90a216ae5e28bffc0610f61fefe0a23148dcc65ab88b117dd3b8d311157424867eb0261b8b8c5b11def85d434dd4c6dc7036822a279a77ec640b28da164bea7abf8b634ba0e4a13d9a31fdcfebbdbe53adcdf2564d656e64923f76bc2619428abdb0056ce20f47f3ece7d4d11dc55d2969684ca336725561cb27ce0504d57c88a2782daccefb7862b385d494ce70fef93d68e673b12a68ba5b8c93702be832d588ac935dbf0a7b332e42d1b6da5f87aed03498a37bb41fc78fcdbe8fe1f999fe756edf3a375beb54dd508ec45af07985f1430a105e552d9817106ae12d09906c4c28af575d270308a950d05c07da348f59571184088d46bbef3e7a2ad03713e90b435547b23f340f0f5d00149838d9919d40dac9b337920c7e577647fe4e2811f05b8e888e3211d9987cf922883aa6e53a756e579f7dff91c297fcc5cda7d10344545f64099cfd2f8fd59ee5c580ca97cf8b17e0222b764df25a2a52b81ee9db41b3c296fcea1203b367e55d321c3504aeda8913b0cae106ccf736991030088d581468264b8486968e868a44172ad904d97e3e52e8370aaf52732e6ee6cc46eb33a901afc6b7c687b8f6ce0b2b4cdfe19c7139615195a052051becf39383ab83699a383a26f8a36c78887fe27ea7588c0ea21a27357ff9923a3d23ca2fb04ad671b63f8a8ec9b7fc969d3bece0f5ff19a40bc327b9905a6de2193ffe3aa1997e9266205d083776e3b94869164abcdb88d64b8ee5465f7165b75e1632abd364a24bb1426889955b8f0354f75c6fb40e254f7de53d8ef7fee9644bf2ebccd934a72bb1cc9c19d354d66996acbddd60d1241657359d9074a4b313b21af2ee4f10cf20f4122a5fad4ee4f37a682ffb7234bea61985d1ad130bfb9f4714461fb574dbf851c*1000*8*c05f3bc3e7f3cad7*1040*f3e3d091b64da1529b04b2795898b717faad59f7dae4bda25e6e267c28a56a7702e51991b2a3fb034cdda2d9bfd531dfd2c3af00f39fdfe8bcbdde02ab790415bcf071d133b15f647f55ff512730ae4914ce20b72184c827f6350ac768b00c9eab0e3322e084bb3e9e9439a10030950f5504dcc4f7ba614b27fde99bd0d743a58341e90ec313395486eb8068df205b7bdf25134ed97dd2e2883d7eb3e63b659602ada765084a69d7ed8fc55b60aa67718cc9e5bf31ab8f3029b32a4b001071848d2b76b5f4b921d2169ca287e9e78ecd904d040c817c7c7cde4ba8510b462e139c16519962ca0adb7d5f89d431cd4541a9a7aaec8d799697f4d3947d87884bed32ada13db725c72ab6450ac8fe989a94917cca784bcf6ffbe756f19d4e8897e0f80d8c318e13e5b30fc356646aaf038a952b0781f12dfef1f4bd6922ae05a573eeff4dbb064cfbb0fd62962a6a53a8de308da2b8e83baebfe261cb127f874a5eff3f05cda123ab2ba559cf444ce33b6845f4c902733b8982044151a8aa1859769082ade5928f2d4f616ce972ae8dde1f2be37d496ad16057008dfe678c75cbdc53db25ed311edbcf8b2a73bcd2809f6bd1d389aaeed82a75fa15676d08aa5390efdc189c180be6a52ec5a7371304d26e477039197671377d1ea3d6ee41e68a42348a4fe9a1d2400eaeba8ed0a7419b9694d780456d96378c00318a5be0f41afa887476b3bebb7cf30d61ca8fc77de35671a3053a517aa39444e01e1752da3146dc97eec5849d6f025c3d4bc6e0499b901f629d8a081ad35ed33602cbef5e9a68f090170fcc1f285eb094e3dc619740a067fd2aeeb20abbb17926c3ad097f3f0bad4de540d1829a985cd7e700100622ec47da046071c11a1597e5f093268b4ed79ffcf2450b9ba2b649b932fbce912bdb4da010581bd9c731be792c8f75177f6c8c4e1756d63a1491a8aae4bb11beeca118e7d08073b500dd82b81e4bdbeb15625afca8f1c8e06b2360da972587516ef62e91d1d9aad90e62226d53363bff318f5af21f69c234731ac22b09506a1b807d2366e88905668d960c7963daa93046e9a56db1d7a437e9a37aa7a2945197265478b264ec14d383030ef73504fd26d4be9e72ebddb14a00bf6bd66a3adaa1d17cada378a2b0bc852f961af52333f7966f8a60738dfd47e79ce537082f187117ffd31f54f53356b671154dfa245671c4cd054c1a8d303a202fccfae6d3f9e3646838cef38703b5e660b5ce7679f5898d801908f90092dbec335c98e4002041287fe9bfa7d7828a29ab240ec2cedc9fa12cfd7c3ef7b61dad4fbf2ef9c0a904dbde1b3792fb5178607608dc9fc2fbc85addf89fa3df94317e729810b508356b5bb176cdb022afb0ec5eeff4d5081b66733d1be1b54cc4f080bfc33187663b5ab185472b35dc8812e201472e6af376c43ee23aa2db6cd04bddd79b99b0c28c48a5ae"
        )],
    },
    Vector {
        slug: "cloudkeychain",
        hashcat: &[],
        john: &[john!(
            "cloudkeychain",
            "$cloudkeychain$16$c1b981dd8e36340daf420badbfe38ca9$40000$1$00$256$16$237c26e13beb237a85b8eacc4bddd111$272$a7bb7bee7cf71f019df9268cb3751d563d1bebf0331e7def4c26eeb90e61d2c2339b3c2d23ce75e969f250a1be823732823687950be19722f2dc92f02e614352c082d04358c421c1ddc90d07d8c6c9fb46255846ef950f14547e5b72b32a0e64cf3d24646d41b7fdd57534a1dd808d15e8dfe4299ef7ee8a3e923dc28496504cacb0be647a4600797ade6cb41694c2eb4d41b674ce762d66e98895fde98dda862b84720874b09b080b50ef9514b4ea0e3a19f5d51ccb8850cd26623e56dadef2bcbc625194dd107f663a7548f991803075874ecc4fc98b785b4cd56c3ce9bcb23ccf70f1908fc85a5b9520cd20d9d26a3bfb29ac289c1262302c82f6b0877d566369b98fb551fb9d044434c4cb1c50dc$32$92407e964bb9a368e86bcd52273e3f6b86181ab1204a9ed709bbe97667e7f67c$304$991a0942a91889409a70b6622caf779a00ba472617477883394141bd6e23e38d8e2f5a69f5b30aa9dc28ebf6ecedcb679224e29af1123889a947576806536b831cc1d159a6d9135194671719adf86324ce6c6cbc64069c4210e748dde5400f7da738016a6b3c35c843f740008b0282581b52ea91d46a9600bfa8b79270d1ce8e4326f9fc9afa97082096eaf0ce1270eb030f53e98e3654d6fd38a313777b182051d95d582f67675628202dab60f120d4146250fa9ade4d0112aa873b5eb56425380e7b1220f6284ed1fa7d913a595aedfc0159ba2c95719d3c33646372098dc49037018885ed5d79e3479fee47fbe69076ea94852672f04f10e63fe3f53366fd61f7afd41831150cf24a49e837d72d656a1906943117252ab1f3889261ce09c3d832a4d583cfc82a049cee99cf62d4ec"
        )],
    },
    Vector {
        slug: "bestcrypt-john",
        hashcat: &[],
        john: &[john!(
            "BestCrypt",
            "$BestCrypt$1$5$3$16384$240$3154116612$128$32$51f7450dccbb1c947dd46138bf0d80d588b6938b02505642dde9e1ea61481485$1$a186f281fbbc68f3b27c7b4cc16b7916a2e19c2695b34ee4133a6ac6373db67b88fb54e3def1c0d288d3170dcb5860c2f190ab199fde7f1072a2a109441e608ae46890c5f18ab80803012a43d9cc595a45c5b9ed8b3ed3330cab1a29e5a96512e2f2e0e5927d6836c3a67c1cd13a61a8201a0a99be84c3e19e6d8a12330ae72c22179d37bb7d55034bb96b5cf9f73c11fa82be31d06bfe33305b616cc72079777a5f1f4a720b56470a83da08c17cbc86e34961c4f0bdb8556e2afa0b2b890780e03304725ce7cf8c592f037beb04b393f4f02e3bc9f6582082a39d31f2e643c5f7811f30eeee2ccc6c11496b7d70dc0d300e145408d28448ff5d929c42007dbe"
        )],
    },
    Vector {
        slug: "bitshares-john",
        hashcat: &[],
        john: &[john!(
            "bitshares",
            "$BitShares$0*ec415018f26e7182a273655aef7cec47966306c48956604462f5b9e1613b3b70ebaaed4d7600b24a424ddb7d4cd56e55"
        )],
    },
    Vector {
        slug: "bitwarden-john",
        hashcat: &[],
        john: &[john!(
            "Bitwarden",
            "$bitwarden$0*5000*lulu@mailinator.com*20d9c3c9daaed076026b6cb5887d3273*3bbcb4c7cec45d71c7238291573eb8a8a0f71e6191fb708b07f2cb43b26a56b533ba35a5906abdc08600baedb18fbc042a3b50f4549890210a254129b0ae749394c3c39b33ca183c605ee97b167329d3"
        )],
    },
    Vector {
        slug: "django-john",
        hashcat: &[],
        john: &[john!(
            "Django",
            "$django$*1*pbkdf2_sha256$10000$qPmFbibfAY06$x/geVEkdZSlJMqvIYJ7G6i5l/6KJ0UpvLUU6cfj83VM="
        )],
    },
    Vector {
        slug: "django-scrypt",
        hashcat: &[],
        john: &[john!(
            "django-scrypt",
            "scrypt$NBGmaGIXijJW$14$8$1$64$achPt01SbytSt+F3CcCFgEPr96+/j9iCTdejFdAARZ8mzfejrP64TJ5XBJa3gYwuCKOEGlw2E/lWCWS7LeS6CA=="
        )],
    },
    Vector {
        slug: "dmg-john",
        hashcat: &[],
        john: &[john!(
            "dmg",
            "$dmg$2*20*fd70ac1e078f01fce55a2e56145a2494446db32a*32*9110b1778f09b1a7000000000000000000000000000000000000000000000000*64*68a32866b0e67515f35dc67c4d6747a8561a9f4f6a6718a894b0a77a47c452471e04ecef9bf56f0d83d1201a509a374e00000000000000000000000000000000*14*8192*70ebe6f1d387e33e3d1093cca2e94c9a32e2c9ba47d461d737d49a7dc1b1f69407b7dbc16f7671689ea4a4641652b3f976b6f1c73c551a0a407d5a335caa169db4a6a25bbd27fbbc38fc71b29ee9b1eae349b0d8a21d57959ecca6bf74bc26ccaee69cfee4999b55374605491af6d0b9066c26995209cd1b71925bcb45a8ef5727a6c20338f08de4357d4cb42cb65ecdc2344a5d7387633c913258ba40699ea5f88804b5e562bf973096337b17b4fc1236d3c8a80b9b48aed63c5a0eae3ae924a883e948f374771bba46923658f225fd2795ce0e795269f589e0ffc81615585e1224cddde654d689a3260e69683c6198bdfcd87507c23cefe36d72f8878cb27bbe5dce868752a7cce067f5a3110f20ebd31ecd53840103e0b2d44385656398edc487bf6d1a5ec3a56af54f9d4254fd20988df41eb85e366f13da1270a3f42c6672ad5faf00fa21e9ba3691bde78ab2c267a142f275467d5b853a107dbf1d75839f0e87b3b4f1d2cec88cc02a26bc4a63aa6836b0c43c5dbb44a832050385a48d46968361ebb053c2416c02458b76c95e50970922556d40b100967340a32824e6b6e44c0c1e0da7ce989d9d5ad91560156ed39666cbfbea71f28797a5a7a40e77665612e977ecb8b7fe71d500eafc29d9a0ec1d0ff1723fea7c405bc181ea93c0df42f5bf886eace3cfeee8b0dba52ba8cd2ae009e75d8845264d12dd632ca3236bc1b643437881b270183d2e2bd20808ae73d32bfe88347e33bef4921fcfac9646b74f116be1f04fc353d2222499d5247fa842d0d0f00fc9642ea7524adb65c18fff87b6efd060ec850d7de6f59869387b3d4cc8e38014d52d94ead07d16b8d94327fe5533941497c9be2dd6c04142ba57e29daaeef96d0f2d109522651d797715f4bc5f4cc3fb69fa92623b5ea3e08ff78dc59913993c877f4e2c8964dffd2c8cde6c6b6738da2883505486df5b633aaa8c66acbc2886107f3dd61b1df29f54a13ef27a7d2785c02153375240885e5c54297d88827403320799e05213761549eedc1c159c922087983410d2abadf9ef8ae460d018c278a9ea724f52b866e3d7ff2374496103b5137297100c970d195fca8c1286a8f9d3859ee12c84bdaa4b56ca91e307580b61dbe435ce4021007e4a2a8085976549cf1d195f439bb6e642567f91a0224e98796614d9ea6bfab8f6d13f91b7a80a54e538a1a785cd07b5d7ed2b7e45a0658b5722b5f8844f5139cff3b33ce244946757c020c54c8b5e43324023ed11001201213ffe4829e37135686a8bec1837b35fb234049570868dc5ba9c84cef6890d9ec400a794b1723eb209a60758ba9ae9abd23a7ea9f94fc6b73d29a560e24973c9160f195fbe82376c81dfeec1a7f912a8c22c067a26786a22f0b7db2983631400f120010706c78acc36ddcc29c7055fe82105f770e2dadf131ab49af93539fb5186d32dbe4a4df6cb0fdf6840c0609c8769fe242cc60d87e04e6e3be1a7884a05d9fb96c3bc1bbc769d96bbcc0413492eefc5502e9c1ac7c3f237b9851dc453b5bfa899b7b68e5e3b92711e7c92945feb6f6e452d6216e154a952cc28a3740925554d9fd44acedc8a44b0c25bbb6aa637fe9560437c08b17992c74de38fe1fb8fd5f66c2933c2d573ddc914f68f42d6cb350f126a51f607a2dd23b63e6382ec1e6ae434f47cfcd1e7d96c8293ef2994f850a27ef2d8210a0df0c219eadd2376ce36a22db56827d92a90d5e2fa55a4154c39061bd5490ba29f8309cf3e2056f761762dff56803bbe0607faef510d023b249663368977fede0577944f2ff05ead4b432bbb07a7d90148ebd1e30bf1204cd9069725d9fdbb850d3d6fde5044da1b9ffa222d99061c8ae217bc5b249960db545e6fece3ea2faeefa7702f065764b326ae0e62f3b8745cb73f35bea1bb9f6ed4fcda591f4d84da0415a0552306f6691a64a1d0efc8ac93559a79e57e357b63df48506c12dde74f6ea8fc5eeb1846c394fb8fd0fd40df26a42e53692db51bb36403305c1aff797e20adb6f8f1721e316705dcf8fe6e6989a5c3da253fdc6cb5de426f1c018161d72e34e6791d73023c5df69c0f83d3ea1d097f3a7ff37720a66868f40d3b87755bdaf508086c7e478ac1efc0dc421987af6db9b2f096a7270de91f5b3b84ee6d1d268d581718d3c534eeffbe2889388e9930cb051b5752c1ab1faf1e367866af7d4b37ba25c15a030d9a5f32bb8912ce853fe7988dc62aa61264e3c5a29d18c5121a605558b15004c817cb0ab1646138cbf6375f1a179852bc22d80b83891edfd38e25efcc0dbb78062f479a9dc792e5822e09ba3e0b8ef71c62ad7747dba8cc97707f31383baa93108d5c7253dce2395fa24d77c42cbf3559b5dc0235c0ce49ef9e3cc816598698c8f8c5b32abfaeb44f3c35a01a4f47421a166d5aa893aaba80e57eb576b838c95ed6f9d5b3d389a8f86b97fe629408ec7c7ba7fd95d7625e950c7324fdd35989570b24f2e1e24d52b65ed6116e728dc3a1004d3d8fbfeeaea1c7dc5d3dc7a029f97f8dc7f740e2386eb27e9793680d959821031fda08c7146f46e8ee47ec28c7d25574eb690de09849725e490c39e524b74aecfc68ff0d760d115b4d0a126609cef83b6c80731dd17f4a307331464953c6b41875b6e5fea328fd59f275e2fabd25717781cf9d5cc52286246ebc92527eeac7acc6e2652c6fcff405e7b4a78b8f9475f46bb82a68a6e44037d61de0df58a8b7a81f407aaa260f3a49c4a2641776404fc15bfb77573dc8728573a1872e7e093663842d9368e74cbe3ae547355fa101daeaa0f97dc0a63927e54ae59fe13aac4f488e938fa67a12876d103b4a56b6eb88ff0104330e5cdc7c6886b46545d523bfbfc88f40f9654fcd0f8c4f443a225b50b44af9674166d3de36b6ac63a150fbcda2e2511ae2a42fbe51c08f7238366aada5c6be8eeb41963c6a5374a94b332012e860d6cfbc1b8a4d5a9825b88a90c9a5f5615ca503698ad00df2cd93467b66d9b15876bc49895a081959132bad2e63757aa4e5ff77c6f25dd2581a3e9bb8e213c9313ceca0fcf5f8416882849fbee576d8ffb9dc057eb96bf6b81db60a82b0e6f315a13dd31706c0e36f4f21b9ce977ff6700cd77db603120d59ad8088e121cc3c502e37774b098eee7c8244f9bbe0d4a9d0deba3ec22e5abfea69ab72cdb75a001bb53672fe12b4fdbdf7e82c0bb2608de5d8e1961fb4524dd1acc890361923fb691bc5ea436246428a70b5021f9eee2c637eeab574babde4c0d55f57925e511ff623af5c4224d3ccb9c8572179e2610b4b79817ca18ddcb5302151f9facffca96269ff5fbb11e48209e20145bdd70d72bae54f6fbb89a3396bdaaa3d45413e3c5bc672ab98dfbeb3274156096f641494c1c946baab7c388a16c71ce5009b32f45dbbe37998906570045027950bd758b7ab2f72c243eccf9551d539946a99779848b16cddf9f163fcefe1e1ebee3ba7d5240b92698ad56a036274ca798eae19b0dbcf39a1c0ea1a58b29dc0e3de89def08e6c5800c94db47b7eaef5514c002d687b4d99b00fbd44137f56557830d63156f43bf73db8b330bca0ebb4ea5d50941b758929722aaa5452cd4a4e00640165dfc35fd35daaf929997adeb4c4f7611d66befb80809dc7bc6c763879c3bcd8dd0fe6b621898717fd095fb7eb403b07591b931a8e16ab488b01acd636bf4f1e71d5460532b8a3b00d7353e84c071de5cfa25de685cb85b569e08d2f177727cda11f196b040d25c97ccb83e355db98c2bc148441ca95b5f612020bc53a81184ccd0c5f14bf6d9fd6318ec28bafe8d668cb3c98c56ad416007bef4a3ed9e12eafe8f9e7d87fbb02d1f557b497db1a2c0fe40ec3f23ea88332513c68f724cc8a8af6636c9f332a8e55c2d41fd81a23e92e9ffacd3ef14cda669e7dbe31ca08a5238c7fbfe7020933087bf2ce0a7489fd5a3becce5de09628234f60c833002aa8e9c9ec51f57c8e4ba095c1d054750d46d64041bb1f567a82d63bb5e88fb70bdddad0ed7572229e56b90e74dd88ca829f1ce8424bd24a0bbfe3dc3f77d244ee59f364b36a4b05fb511b5b0d7f876c65ab4233803543b0a68b9d2d6d45d292f91eb4700c2dbf431e40c77a4fcc3ac3fdf3a2bae3df35b6417b8f1eedfe84cc65a07c426780871d16ec5ed3201ea4eaa778b71f04cc1999587bb4645bbc43e365395e9188c85bd024f758304aee979f8e67d07636fea251423e920e2b7258580d1918fce772bf02ee66926fc5f9a3dd6a8c89e6ce7e4fc03d4784296df1a9152a1fc66050983a287e3520bf3e04d900d25316c8bd5ab489bf97a2f31f4061f895111caff9968ecb22d75cb9e5400ca1d0fb044acb4fb9cccaa4766cf6c63ae5a7a3f9af90d1b225067f671d85cdb4e2e21d2850f351d995d54520fdcbb8cb30bfa82190ab2071eb8bf350f984408b206597371736110114d12d79da4027f9a58c8fede63cf16fa552d2a956ae2a49c83b0afca3056f87f1e27bdeb9d14a7e5cf30550017a3233c4f386769021a853b971746aa28aa69ca980bb02979779c5bd29259c84911e2b25261b92be669e8a731dd74edce66b6f3ab5944695efd57c0004ff637eabfbc02ae346528fedbf2ae80d420580adc4d571a37fa1397fc2b85ec458d5262c15620c88f2dca0eb1bae4ec39d67fef56ecbdf89703919e5a6767d0f77bf6f0f60ba21003d033c9dc3057df18d855a5801110fa9a29a42ce10a44a39ed883df249ccddef8aaf832387e70048d9ad6014cc17f9a2bf7146696ee4eed388d06a45f7bd7696e57500ecfada9e9eb17926b16bbd90146e406e281141f0a918c320cacc9d1f045ac1bba87ce8d1d45cb6303988d5228da6ad33df6d2a5bd7f265b8f610078e9db5fa3db0e08286e500063f0fd6860a11d9985226ad382a95bc3c3941d43378ea1bf28fc85749f616092d77e7c292e311337168b52eba08ffc0f76582710a1a7d33c55162b3c7fbf227a324e1f4579e035ae0fa17fafb1ea964aa977490b5a3fc16c75e1fc50a6d17e193345b71369df804c61a71bf60be4281c3d1f945c690368c23caab006f9dfc913dbe6119d6fe8349cdd424db7074726e8bdd0ae99e2bfb9b800ddb965c06e0587cd10108c9b431cad4fd10d3654a22ceac73553a6b2b2218ed6526c362df46cfa776e2caea0de61b9d5c0c74e03e299ceb2221ed0f30ffc5876354d5607c3eafc77f78e4fce5e0c7f6ba7d417ac5f0511e2635b41b28dfb4f2fbb73d351a69fff920b76f5687386114b3d5ab9cad056c88840a023b7e2df73f007852763570d38a966c8258365b014a12a3497f506dbe55c073244333547223785438372884ecd8b66aa0a794ab5fb94b0a519bb3cbf01b43463c0c7fc6ebc67754ca25686002e13edad54c817b0aef64698637d18a4a8bba382add892f4918b720aa99b09ed2a6e02b7140f89e3e00680f37343d3e47412d04ef78005b8b9a23b92d145a8da9c5efafce374955727367a7f1a179b990868550cf960c6df6baf2cddda5fe3e689de8dfcf1474db419ecf88cbce9de7a58e9d8a15991fdf5361846273d195a2892fbc95ad079ca8153910984c4694edb4c790f430043c4019fbd96fe49d8afa5e7d1f6674e4a125bfbdc916b0d3819566898599443ebf2a87b1fdaf41378227d396d2d320dc5b860705bc87f45eba2b6473234fe054267698dba0913ab1234b46697c54e2b19526d1ad4b7e3eab40a413f86170fe9f2a71eae2fb959a021b0b43516f1c8a3e674f37ee235ade79ca296364b0cad5ebe8449e09b63a34e8711587f7f2fe6e181a787b1d3a8f30012ce9549abb834fb80c673c575a25d3c33bb6d846ac231f411dd6422c59215e0a267424c0c57e6c9bd5486e8b6327e9dd16b7065eb74ef91ec9204360b03d08654a4e418346ec2d4d21edd5608a76903494791546d430eac38178d158d61951de3c61fbe5d56c22cbda4a3d40297f7abd83913e8b483d9a80cf000810d90a921f453bcf9e35732d2579c1aaef4a6980c666e3b273a9f91d9918f850bd6e4475d8aa5cb616cec58d6ab6d70dbe2b0f7ad85618b6e60dd4ff5d0faf19dfdf27a9ee48cd7b2d6613e76f04ab6ef5f0af12966a90875816c27c4297a2bf622ddf66fbe7c211670d0c46c7295b93bd2f122568df3dc46e9294c7258a0b7e81b2d45979680edbb7ab323e4857d84306ccc16ca79c711144eab7b37e3437245d7b78ced1cfebfc45892791b9ac6cc1211f83e328ce3f57af3d89b5be89dd2efeac9d738330bd0d8d4a059bfac06d1ad73bf6d427541e559c3d16eb5adc4380c1b25c1b8a9097ce7eeeed1c5d6884dd1a32ee2bfaab8371593a0eef65f80e705b9b56adfc0db4c272024a71947755032a5ebc1bb346ee8a99b01b408cc0b1658a319ffa5ab2eb87e9aa8b3dd9d9d92ce3bc04e4ebcc011a280143927676360f249ccdaf7949bb23770a06ff5861661d36d761508f7e9ba149310d1347c3165e07997853d415abdacfae9579d1dc0b5990a05ae9e6dce8931ac2db9414546dc64f8161a64cf30b9ce8c50ef2a99775f03dfc2c611e780a5cbcc27cab920a87d940acd8b3fd42897ab6f51b29214275bd564c50eb7aab3ad19a2c903c84d2ed5a23c49c81d87cf3244505424332c917d7b671d4a90765b8953c26bb7ed5dfe3e93632610ab44296afee2b5c631fe643a0a78eb9af94d700250f5a82bc57d24825423f1ecfd8cc2bb0daa229670d0d9a4fb342ee8c9b7b16d86d29abc2a57633303b918ac78ea8d2672dfdd4a06ea0bbd756fbadfb0c09e2426a65e90ca829ea00ad66ca8c9e79b9aa5ddd02d435cb23014b1033da00381ddf2dcf408660d1eebd1f6c7bf5ae9fc3fe47e75ff7ca482716534a9f3365f5cdb48f3d59fb19d11bb8782ef96e394296594812e8a7da23a953f6117ce577e55f3d6cb1d3a4007dc7d252c7123a837be12884e54ad10757af405beffb5cff189133bb7df5fc009544b2d62ec44fdc0c1c8240d4413af5b36e031510b1f1537a690ba7049cce9df4bf4dd63f6987c513992fca78a1cb7e8d670fb43a52ea2ca2f49724e35397041e5c75a365b510f40fa9bd076377274d6a95af801981d71972da0a08b536b024f439c43d13902878798153ed825ddd7dee8937181823076f036caecec170edf1b5fbdd84e530bc50a7acc257bb9679d72de3f115602d18d2d12e6ecf4d3242ccbe9a71a1483e7fe40d2447ba028a76aa92c13516ebde90dc4d204095a554cbfad79d6efe4ec540c7b51593413465b929742b729ca688f67ee9d9fe76431fa81217fb135d0dd6ebc91904efcb0cb6dee22867e5ddd7453f530d04935f41575de9ca457da55b67791d2e8b83890b5be543366b92ba6579a6f19f8e82a0bd87e379967766e5b0a58305b984778c562ea03a8b8392e3160ea4532b6ce5de74bc8fa0e8ebe88fbd62a73d7106a309f5a5f5d7617664b015e166fcd87906caa80ab4eb3e62f73e527b5d951a0ed0340fe17bb7b2692e4a31d14798879788fed12413bac50e490ab93ed66311599a6c1362fc60da5319ad907c7ef7852985ce86246276a138379d2004772d4d9a989b83b3e780bdda9825ad06a4b3dcc9a9d4d8025cbdee7cb2e02ea1f77bc90bf4ae56903859025b7283ba6410aa91933466623b996e9ad07e3095e376b11a27ca451c246d5561501e69c6747013ecda44f8d1fa50a75572453c9ddecc07b1aaeebc04cc7e976915f5e68d1236ae2ffdea4b9fc4f8e91b03982801e2ba604b46ad80f966838ae09d2734c6482dd16d7738cadc1276593a336e2ce8cf7ce48d1535c7865f7b90445ff3ab9e56f58e254115bc07710de50d7953238d7ca419013d104d90fe79794995c28f219c963d716bf8942e0cc5cb432aafce4afb42f74596b847fde5d87fba9adce5c17fe590fe58e60379393e521ee194fe063211d72c29d58f7dde89addb6b0e20515ca7aa270df2ef2d77f92219781502c49292c6c4a985242b9447521cdef5a52b53b5eefcc43e8036ebe90b51a3565cbb180ea1b3e3d20f63b8f420c2a7f01c475428d5f63c66f122654af4edcbafebe34970c152767cf623eb4f1ee33931a79622cafc70cdd2bc7ccd55ecc1e0aafde3f66f5414315048d3c5c51638c35fa920cfcf7a18ada48a589c12e4da2c801cb8bf3b182463707a17891cf296ae8aae6a8a88ee3d602cc1bb7647861f65ec1a278433ae08d8c8e63727633425fda0b86d78378ac80b1bc1a48abf270dc2b5ea71691eeeb979950cbe0ddfdc451dcf8e3dc657060f4c3f96512b21bcb228a966381efa94bbf5ff4bbf38a803b6aafc719a545e4d0582a62e81e6468aa04eaf131f8d2f545c060651e115032f5b3579fdfb95a2328f5c9a0308874630e840ae1dcec1b9543c36267a9651c94c91cea42a93a91ba3a054ded4a8343864b449e46abec49474e218c8c541b00eb0f8997e710025631ac28be3f08126446dee0cf61bc69b85e4fc021f203c796cbd2ca16ebc8fa15f55510a08ed334155233c6459d2d428df31a3f376cd81a530700b3ef08631dc5b50f787d4efe2bf219bd17f0431803d9d946255716e8543bf77fc44a48abc70a97feae8398c2059938d39fb4ac5f7214d92bb89fb9c45b6d117fd51f6207935beb1a89963fb9d1aa020669bf809c21154c20e720aa1178ed2bc13fd548e0d7d01eb1d028aa48318a02dc7aa412e2ae01ff59a86dae40771ad3f48f0fa54b6e679854be00deb9938e37ab3a4c9a96f3b7849ac75b82619cbc806c42f4bc4feb1141f6a8391bf9335f643ce5cd2791590b28b19d03cca7b5cf702f10ffa0317327e828deb4791f71500f243be77a451e5759c6c711b38f8f62757c54d7fc6dc586a90df7777d8cf1c72f9c0947af005d770f4a74b6c9413738c3b5ab32306ff5b41a6446c2de3f59a27b79d877d3f05fe22d11afd69e49e59f35b3725a0ad126642f388602b7816abe397a9c9233cf7d1e12a00362306d2d9b81fddb279544f35e23a8c198930f75986f26e6f292ae8debe5da0a7a5b8add2be71efc78179eff7fa2a2dad35863b69e85e8172073f434f48fb03f7bd1bc78fc2badbda261a68f7bfa171c898897b3b0d4852920674b8d9ffdb37ce66c1b6aaf9b375253a0d74eba4d359737f7fddb42471969d81605e41f615399c5fd6cce1808e9b511ac54f75f774e84b00970474f5136447af04b4866ab6c54aabf7a247c6caf3ee891fecb14073f3cfdc7368ac00f6b1c9b23e301e49257840f949a57c28a95c5c490bca91bf979d40403f7b9458bd255df757e6eea0bf41d5175548aa46243d98f2f0f6c754d6e7e58fbea977d7e0af8b7d0a6bce07d0c483293868a914a50aaedfb9b239b4c3c472381535b287a4146fd52e7bf882c9c3eff7bb2fae15d5b96bb1222d81d26dba563ac550e716b6c08b062cad6702a33a9db4274fa2e81af815e8325101d5a9ce9b345e29619da9e45dcbcd7b0935d7dde07644edc6b049eee9371511bb2cac50ec1170c7aad835c54fa52c8e0a0e8446356488e09c2f07b17413a7ddb872d05016aba129cc36de609831863747310f0fa443480a47524dfc5e1f34eef3ba2fefa29e596e7fff86a924462781930fab55e71fc2f06271e62878e51e0db08ee5dea31f1d2afe9a4f548ad6a4f4763c9d0eecbcdc32323aba1c9c12554a5cfedb5310b4a03caf426a80d725fabd557493c46f2a174aac851d3d39529d5ad919fdb7fb0dc1e5b0ffdf706a9f5af36fcd2bdde28d68c5af4a1da4e67cd44f97b555b62b39cee1274b7c3dd3971ace3da6101c87f9b8f28c5e13d4066a3e63543825dd8bddc3e90b6dc75bac78931da98929a337817f68deec6065f6f7883d5bb10cab909c9945f71a672eb2cda9fadf4a8d9da906e2a5d1f589193b4e791772663f1bbe751498bda065f90244391169d80490208083de39bec984af73dc99b10d85958f372004a03962c45c531b347851dc5e26bf7bcdd68c9b129524d6734282bdd431f991170d6a5c67138a5405d8005b355ec7ce95496a8e98782f6d978c42c30a17db9c12671d82f2d3e257f66980f20bb6380303f1e89b10035ae7bdb3e55d31f2d1574784aed5c95aa09aaa9614989d957a65d893dbdabbfaaf30cae0cad575e39f5311aa00a6979fa52ec12dfb2f731a3ce5f8b6097a612c2ce98f5898eb2d1780d0cf9ad30ce5395ae871ba7ca6a0884a13c09732cefc5aed9d7a28c09041cdd62e75d7396432545f0c16496b7f5f516fb2cc603c0ec10a51ee952b7cd0593ec00dddf67e27dfe3f0cdc5bf737170243a8ed3c1f59733fb47bde4b6578d7ef11f95790d4c678d95ab2cbdb1673d2d516c189af00f996371077276e672f1223926fdcd6627ff86816906edad3aa97e3a9e7346562add05ec1a94c2dbb7f3b28ef537715a1d69761bfb8c2092e608311af2f79a4f8188665a48539944374437bcff6e59bdff4e4b9e4dce11307d892915071157698460b9e9fd68ee0d1acd21434810fc8ae702fb8dc794ad5364c79fdd74c8a70f390556930fc2a23064f36411c626179d1d745d4875f5c2b37292cb8ba37bb78d419f05e9a5d2245a38da20b6b14eba2d5ca3d58d23bb5ade1322cf337eb75a97ce98c167b6305907c3fe18038bee1e2450c3095480f99c9f12d2b543b33866e5546a39d539c6e2d639356bdbcbdb3b4e0935ac76e0fdaf54cfdf241d2c5ce135324885f8cd69e6562f48979352bbab357c6861c66b4ff7d9dd5d32a8ab8b6e759a2f5ddcee847fa439a5f9e3989039aa60751019eca6c7dfcc2464ca4a1ae12f079d200961797cb0e52cb046d1f0cb1d97c4699e07f019b48edd6f4a71b99ba26c2e5e72745cd9bb9a7e89d8eaba646461bb76818fcc447de2820196e32cdcf4a57c527c52f64d316b513f6a611c929890be5b03b3d3352cef23bf86d0e058b1cd9c4a10a9a01060aa9c9cc4bf42c7c6cbb677724db3f0c3736461c1828e67c9916e953057024371bb4ad8995672f760c47574bde9df9e73af90773cd46c9df8cb655f8c37eed8cbda40da06304471e32bc828a7dd9457fbe4d63a15633009c1a9f003f3db7f5b2b5e3b22c60f747d5627bce3eb4398a543cf24b18cf0a56728adcc253d7f5343245c1426b5bcd9daff94394499cb6d7ac2b4e63ec424c66f5dbceaf877fc13f47e744aca7d8b5d89c8d5621f4e13488b141062ee04c2312528a0a987a5d32ebc6ffae45657f4b2d1420890970e363a124b75374594dea0560320b36133e31d6a978f90ef079b81484503c7fc3edbceadfc9fcea06f271a60ea6c5d434b694ace1b506eaf013aca2c6103acfe6c565a5a24cdf638f8ee282ac812e32cc2662a8e2d4a31239952836c4896870d973bb65b280f0370f4c3a54c7f4723b2bef522ca4c233d7646da3fdb9743e273afa1e3bfcb947eea9f323ca908bb4961b214aa906cca1d2d56eff25d60952cc5897ee6390f9af4efd5d48b2aee8734cf6b8042f2de75b107f8d135d9a63148e88e43df815fe7871a354741f8863af4e114ed0369515bca104f8d3b24a2d740b8617de3e96a23*0"
        )],
    },
    Vector {
        slug: "dominosec",
        hashcat: &[],
        john: &[john!("dominosec", "(GVMroLzc50YK/Yd+L8KH)")],
    },
    Vector {
        slug: "dominosec8",
        hashcat: &[],
        john: &[john!(
            "dominosec8",
            "(HsjFebq0Kh9kH7aAZYc7kY30mC30mC3KmC30mCluagXrvWKj1)"
        )],
    },
    Vector {
        slug: "krb5asrep-john",
        hashcat: &[],
        john: &[john!(
            "krb5asrep",
            "$krb5asrep$17$EXAMPLE.COMhero$4e7c79214fd330b2e505a4c75e257e4686029136d54f92ce91bb69d5ffc064e64e925b3ae8bc1df431c74ccaf2075cb4a1a32151b0848964e147bf6f8e4a50caa7931faad50433991e016e312c70ad9007e38166f8df39eda3edd2445cce757e062d0919e663a67eb9fdb472b2a840cf521f18bd794947bcc0c0c6394cc5a60b860c963640867e623732206e7bf904d3b066a17b6f4ea3fd6d74f110ee80052e5297f7a19aaec22e22d582d183d43d6ca1792da187a3a182d1f479c5b4692841ccd701a63735d64584c4f8d199d67876dae5181f4eadfe75e454d0587d0953d7e16cb1b63265da6188b10c1746a2e83c41707bd03fcb2d460d1c6802826a0347b5ee7cdbe5384acad139b4395928bd$7ed0277ba9b853008cc62abe"
        )],
    },
    Vector {
        slug: "krb5pa-md5",
        hashcat: &[],
        john: &[john!(
            "krb5pa-md5",
            "$krb5pa$23$user$realm$salt$afcbe07c32c3450b37d0f2516354570fe7d3e78f829e77cdc1718adf612156507181f7daeb03b6fbcfe91f8346f3c0ae7e8abfe5"
        )],
    },
    Vector {
        slug: "krb5pa-sha1",
        hashcat: &[],
        john: &[john!(
            "krb5pa-sha1",
            "$krb5pa$17$user1$EXAMPLE.COM$$c5461873dc13665771b98ba80be53939e906d90ae1ba79cf2e21f0395e50ee56379fbef4d0298cfccfd6cf8f907329120048fd05e8ae5df4"
        )],
    },
    Vector {
        slug: "krb5tgs-john",
        hashcat: &[],
        john: &[john!(
            "krb5tgs",
            "$krb5tgs$23$74809c4c83c3c8279c6058d2f206ec2f$78b4bbd4d229487d5afc9a6050d4144ce10e9245cdfc0df542879814ce740cebb970ee820677041596d7e55836a18cc95c04169e7c74a4a22ae94e66f3d37150e26cc9cb99e189ef54feb7a40a8db2cb2c41db80d8927c74da7b33b52c58742d2109036b8ab27184609e7adff27b8f17b2f2a7b7d85e4ad532d8a70d48685a4390a9fc7a0ab47fd17334534d795abf83462f0db3de931c6a2d5988ab5bf3253facfff1381afb192ce385511c9052f2915ffdb7ea28a1bbad0573d9071e79dc15068527d50100de8813793a15c292f145fa3797ba86f373a4f0a05e5f2ec7dbfd8c8b5139cc7fbb098ea1dd91a7440134ffe2aff7174d0df13dcad82c81c680a70127a3ec8792bdecd74a878f97ff2b21277dc8c9a2f7bbcd9f72560dd933d85585259067d45a46a6f505d03f188b62c37edf03f117503a26743ebd674d5b07324c15fc8418881613b365402e0176da97d43cf85e8239b69aee07791233a959bcaf83a7f492fa718dd0a1747eaf5ce626eb11bda89e8235a056e2721f45c3b61442d893ef32a8c192ea0dadb853f3c6f3c75e92f23c744605c6f55578f696b0f33a9586b8aae3e12e38a097692cd9a31d780d973eaaf62ef23b2fc9ae59a38bfd8ea14d3289b46910f61a90aa733e66382bc27f40ba634e55ef1bec0ca7f71546b79566d85664b92f9fae495fcef5cde4c4399a6798569a7e81b9cc4bdde7104f3fe181401f82bba944e3b0a406c7093c00ff9d5984a82517b1a64a8aa561bc1f0cbafbdbbc5654d375c91d4e485e17bb06838109fbc1504147481c91652f545086a84daa423a6286ea6bb13460c5ff3d865a7b37b9ce4e7b07fbe2f6897c12c1e4df2e875c1ec9cfbf84097a7f48b270baf3481263b21849ab93c231490d06a23461a5e00c23df76bca8e5a19256d859304e1f5752bf055ac7f4843e1ad174f1cbbf5c142958f9310025ce439d5979982fb0b8c2ea95e1a22ee8dc63423d9d364cb0b95bcdf89ec4ed485b9005326d728757d77aa3e020a4a61d7deb782bc5264dca350173609772cd6d003ee8104dd24d310c9a18a44f78e27d65095f5bb54f6118c8f0d79ad5a850cec8d40a19bd0134144e904c9eb7fdcff3293696071fc1118f6b2f934281a25bcd5ca7d567714b1e43bd6d09bfcc8744c0ca273a75938394ac2fb31957287093346078577c94a71dfa6ad4a63211f54f00ef7a9064d070aaff84116ee891728915c938a8a32e87aaa00ec18e2b4e9ae88f7e53f08d855052a995f92351be32d8df934eab487103b0f089828e5fb5f73af3a8a05b9fffd25c43a392994743de3de1a2a9b8bba27e02ae2341f09d63aafab291759c41b9635521ca02f08e21e7e5c3ce75c8c3515eaa99aeb9bf8e204663e8b6b8507ecf87230a131687b4770e250ba0ef29fa3ca3b47b34971e17c6a3ef785acdd7c90da9d2"
        )],
    },
    Vector {
        slug: "mozilla-john",
        hashcat: &[],
        john: &[john!(
            "Mozilla",
            "$mozilla$*3*20*1*5199adfab24e85e3f308bacf692115f23dcd4f8f*11*2a864886f70d010c050103*16*9debdebd4596b278de029b2b2285ce2e*20*2c4d938ccb3f7f1551262185ccee947deae3b8ae"
        )],
    },
    Vector {
        slug: "mschapv2-naive",
        hashcat: &[],
        john: &[john!(
            "mschapv2-naive",
            "testuser1:::d07054459a1fdbc266a006f0220e6fac:33c8331a9b03b7e003f09dd253d740a2bead544143cc8bde:3545cb1d89b507a5de104435e81b14a4"
        )],
    },
    Vector {
        slug: "nethalflm",
        hashcat: &[],
        john: &[john!(
            "nethalflm",
            "domain\\username:::6E1EC36D3417CE9E09A4424309F116C4C991948DAEB4ADAD::1122334455667788"
        )],
    },
    Vector {
        slug: "netlmv2-john",
        hashcat: &[],
        john: &[john!(
            "netlmv2",
            "FOODOM\\Administrator:::1122334455667788:6F64C5C1E35F68DD80388C0F00F34406:F0F3FF27037AA69F"
        )],
    },
    Vector {
        slug: "netlm",
        hashcat: &[],
        john: &[john!(
            "netlm",
            "User:::6E1EC36D3417CE9E09A4424309F116C4C991948DAEB4ADAD:ntlm-hash:1122334455667788"
        )],
    },
    Vector {
        slug: "netntlm-naive",
        hashcat: &[],
        john: &[john!(
            "netntlm-naive",
            "User:::lm-hash:35B62750E1B9B3205C50D6BA351092C12A1B9B3CDC65D44A:1122334455667788"
        )],
    },
    Vector {
        slug: "nsec3-john",
        hashcat: &[],
        john: &[john!(
            "nsec3",
            "$NSEC3$100$4141414141414141$8c2d583acbe22616c69bb457e0c2111ced0a6e77$example.com."
        )],
    },
    Vector {
        slug: "ospf",
        hashcat: &[],
        john: &[john!(
            "ospf",
            "$ospf$1$02010030ac10001400000000000000020000011454ee4518ffffff00000a120100000028c0a86f14c0a86f0aac10000a$e59ba2c56a2c0429ebe72a194e4b54c250cac1a3"
        )],
    },
    Vector {
        slug: "padlock",
        hashcat: &[],
        john: &[john!(
            "Padlock",
            "$padlock$1$10000$64$16$bc5ce69b9b9dadafb4566f570cccd15d$6c0f57ec2a0a98974c567cc25a12fff1$16$226683e36d47dc8a3bf7c49fedfdae88$10$07ccbca4012cfa37997d"
        )],
    },
    Vector {
        slug: "palshop",
        hashcat: &[],
        john: &[john!(
            "Palshop",
            "$palshop$68b11ee90ed17ef14aa0f51af494c2c63ad7d281a9888cb593e"
        )],
    },
    Vector {
        slug: "pbkdf2-hmac-md4",
        hashcat: &[],
        john: &[john!(
            "PBKDF2-HMAC-MD4",
            "$pbkdf2-hmac-md4$1000$6d61676e756d$32ebfcea201e61cc498948916a213459c259c7b0a8ce9473368665f0808dcde1"
        )],
    },
    Vector {
        slug: "pbkdf2-hmac-md5-john",
        hashcat: &[],
        john: &[john!(
            "PBKDF2-HMAC-MD5",
            "$pbkdf2-hmac-md5$1000$38333335343433323338$f445d6d0ed5cbe9fc12c03ea9530c1c6f79e7886a6af1552b40f3704a8b87847"
        )],
    },
    Vector {
        slug: "pbkdf2-hmac-sha1-john",
        hashcat: &[],
        john: &[john!(
            "PBKDF2-HMAC-SHA1",
            "$pbkdf2-hmac-sha1$1000.fd11cde0.27de197171e6d49fc5f55c9ef06c0d8751cd7250"
        )],
    },
    Vector {
        slug: "pbkdf2-hmac-sha256-john",
        hashcat: &[],
        john: &[john!(
            "PBKDF2-HMAC-SHA256",
            "$pbkdf2-sha256$1000$b1dWS2dab3dKQWhPSUg3cg$UY9j5wlyxtsJqhDKTqua8Q3fMp0ojc2pOnErzr8ntLE"
        )],
    },
    Vector {
        slug: "pbkdf2-hmac-sha512-john",
        hashcat: &[],
        john: &[john!(
            "PBKDF2-HMAC-SHA512",
            "$pbkdf2-hmac-sha512$1000.6b635263736c70346869307a304b5276.80cf814855f2299103a6084366e41d7e14f9894b05ed77fa19881d28f06cde18da9ab44972cd00496843371ce922c70e64f3862b036b59b581fe32fc4408fe49"
        )],
    },
    Vector {
        slug: "pem-john",
        hashcat: &[],
        john: &[john!(
            "PEM",
            "$PEM$1$1$0c71e1c801194282$2048$87120f8c098437d0$640$c4bc6bc5447bed58e6f945cd1fde56d52aa794bd64b3c509fead910b1e7c1be9b6a89666c572c8ba5e469c5732ff105ecb97875efc2490ea9659082bdf0f3a2fd263ceb86bde4807bb85b01ca25efe25655fcdb9d54db94f7f48bb9b04af2bad5c2aaed87dc289da8b3fb891a9797f73adacb05b21717fe11d4ebdf8f1d39ecfcb8791447263572f487b087484c02e40a13a89c0613ebc4958a0853781eb1382c1f9ac1f1f97dd06e1a26d98088c5f262680a33dbf2e7742a436847cead5af15c538a5eb21b99e0c4ca30d08f5e805678bdbae6a3ee53623b7cebaeac6c7dd54834f6806112909d2d74da35ea907d35cfbd9cfcca4c302e9dc19b3017957747b4525e7832067d462f15451ca47be771add080da835dc177c26df3dd3fbf4b44d0ac7aea30a44469fe542abaf9bb2787b5694c7fdc1b9765167bf9ea5bf695e927bb98217491d7f1843a1e39e2a1a6a178b03e391031a80943f08b6dd7fa5104e38c4a4bad773775a71f5d076641a52a1100e701c14e5a15ac3dbaefad5f2ceb3ccded6689aef2bc9060c36599580f34324ecfa8cf2628da6475934bb53a8f7ef4a07fc1d0a4d41bfc9bac91859ce98f3f8876bbfba01bbe4491fa2d511b2f6eb5ae7ad4213a24c21fef676c8713de9c674d7a88d8844765732dbab43ee9faa5245ddb6fd6d66ab301b82dca829aeacaa5f178cd12aa0565c8a2d6c00b8c7f611ceedeee8ea68d99582fe9ba701c46d1ea78c88bb942ee3e30e83d9843cbda720bd2dcc07f2b4497e781cd54156e5e1022c4fb5827ab4e0469bb40500a6978eed0f27e0258e7304b0745e90eb36bb8d8e1c15c458313c547c3bfe54d75ac26405c40cfa0fecbf2a95e312870c08b13e6b36494c09c8a8ef12057e090a24e05fd3"
        )],
    },
    Vector {
        slug: "pfx",
        hashcat: &[],
        john: &[john!(
            "pfx",
            "$pfxng$1$20$2048$8$e861d3357729c35f$308206513082032f06092a864886f70d010706a08203203082031c0201003082031506092a864886f70d010701301c060a2a864886f70d010c0103300e04086c933ea5111fd24602020800808202e83c56ad18c45e54aaca4d170750cfbfb3059d6cf161e49d379eab15e722216cb479eee8da7b6e6ffc89e01fbf30f4eb5e1b88ca146c166c700a68473d25a0979344cc60d1e58230a12d24b8be6e9174d3afecdf111cd7d96527831ac9c8f4bf3817cda021f34b61899f2a75fe511e8dedfb70367fa9902d2d3e500f853cc5a99ec8672a44713d24ae49382a20db6349bc48b23ad8d4be3aa31ba7e6d720590b5e4f6b0b5d84b7789ae9da7a80bfa3c27e507fc87e7bc943cff967db6b76f904ac52c1db5cfe9915fa3493cd42b8db6deae62bc01593e34bc8598f27a24cdfd242701ff72d997f959f3a933ab5a2762df33849c116715b78cb0d83267aff913619cbbdf003e13318e4b188a8a4f851b9f59ae2c71ab215c565f7872e5d54c06f92d6f59eaf19d95f9b4526d52d289cd17bc0c2079f9f13c20a70a566773d90ca6d888386d909b6362cb79e15cf547dceab1fe793c577b70f72463969f7b416fb5a6228053363558df18588b53406343ab320a1bbf1757b67ef8e3075f44dee4521f4a461d37ea894c940bc87f9bd33276f2843ff5922fd8e61d22a8619ad23154880fd7d957c0f151458fc4f686d96695a823b08c1795daaf79e41118a3c57ee065a693853a9c4b2004440662f51d63bb9973dc4bb8c541d424416c57d01a825be4d31dab7c7f4b2b738e4bbfdda1e3d3b95e026dadee4dfe155c0f4a24991693f679b452516bc19eab7cf7eb41b476358583d46630e8cda55974b8fcbe25b93e91e73f584a913149137c1c20d13f38826d8dba9bcf5504b8cee77e20a19d6fb050e9213b8aeb11c26a871c600701aea352ba2dcea15d8010d25034f64aa488b580b8282d226f8203bba6aa424b0a25bcceb9c7c718b6c276022d988ca063d2e88350d68903f95aa3265b44d909c07fa9477a5dfcfe3b5ed49b789d6e1c13aca012630343021dbc0c0f17dae6688eae495b76d21be49ced2c2e98e1068d8725d8a581958fb2530871dff1b3f910ae8beb3bc07bfb4b1d2d73fc5d440dc9bcd32ba656c32e357051bef3082031a06092a864886f70d010701a082030b0482030730820303308202ff060b2a864886f70d010c0a0102a08202a6308202a2301c060a2a864886f70d010c0103300e0408749558ace83617660202080004820280ef790b9cd427ec99a350a6e3afb1727cf3dd859d5377897805a7093e1ca42ab8cccc6c52d2b86d61ed55b5bd743fb2a4ec556b438933a9d97a55e5ad1fb3f9967e550be3d708feb5c7287e31afed165a4a91bd5a80292a1e061f97a8c11339963843348badf3fd898e89fd92bda5ad0195d8d4f75e7bce9f0518eeb85365860cd32ad5cea0958efef02bfb74aec0af0765729dae079f5eb08b099d3b06a9b9c6cd6f1e1e4170208ebec3c61ae3421e90cef0f2b5cd2187e43cc4ceecf4aec06340f886efb94f517e578d13659392246a69505de3914b719fba74709ef0f03f010429f899dbddab950f6e58462b2fe2663986a5e0c8ff235e89bca3bb6e41fcd602a0277a83822ac1a14101c83fd1cafdc45c1980ecf54ef092deb2fea736b428158e0847256fc1211f94ea8075145be5a5fb26206e125d55f45500844f1a83f063d0be19b60427dadbd89109bb9ee31a1ac79c863204e8e80c044b8b6bc45c756c26be514e4270a293faf4608065a27b4a51253cb9f831614d5c7f25ec1d4e36063e68e4e405c1f4deb98a786c57a376609441f2dcbe6393487b884624570f6cbb02b53f58ea4acb0faedd2931293dc87664a0c589322480686f6613ffb794c3b3b1872cd7a418712a35666b53bd8383f2e7aa6e8a9e20dd3d46cc3aaaaf17841732dde708ba5611ebcc8777fb3f7b65f2cf95992fdf4f5a17ddf01f3ebe5fb6c9cd58cb74553865cbec3c9d391dcc3e96e654faf7be7fdc8d5fb5dff98799e740147d2ca4b6df47560a4a20bd8f30cf5b495f4e919c9efad3aa59491a3e2ba4e53606e2016ce13e8271e70ccd5b57eec99a8604caf5997e648f3eb541769267f9cdf76aa84917ebd8a1f60a973ed22cca9fa0d3589bb77dafed82ea4f8cd19d3146301f06092a864886f70d01091431121e10006f00700065006e00770061006c006c302306092a864886f70d01091531160414a38a6be4b090be5e29259879b75e0e482f4a4dd8$a790274918578289d80aa9fd0d526923f7b8f4d4"
        )],
    },
    Vector {
        slug: "racf-kdfaes-john",
        hashcat: &[],
        john: &[john!(
            "RACF-KDFAES",
            "$racf$*USER1*E7D7E66D00018000000900320010001054FDAABCDEF012345674A0F58EE6137D203D3CD649E9E52F80A1F1B7CD263EE2"
        )],
    },
    Vector {
        slug: "restic",
        hashcat: &[],
        john: &[john!(
            "restic",
            "$restic$scrypt*8192*8*1*ed29ad65948797a275f15b1da36fdd2b0247a7772d69ecfdf21141d837fb0780b6fb48cf7ccc3e4146a105dee0df4851256e204671d97c718c7e6b4a7a8cfb75*879acc157daa013218fcccf6b60be20f1e52baa893698a589f026165f51bbb1da03b0a5db42885d8bcffb34030b0bb26716e9f7c950cccb674494d63d104ee8808e713a7d483a6a0ef36b14aaac652eaa3a92b12f9d7a4cfead72ed0a216ccaeb0ddf9c6e94aa84c82590ae9a6ffc1b48b4fba163635ffb4e0633de668827e567e8c834539ae18d750be6f8f86f12101b04ab926fa570038eb6f78ef6021c1b1"
        )],
    },
    Vector {
        slug: "rsvp",
        hashcat: &[],
        john: &[john!(
            "rsvp",
            "$rsvp$1$10010000ff0000ac002404010100000000000001d7e95bfa0000003a00000000000000000000000000000000000c0101c0a8011406000017000c0301c0a8010a020004020008050100007530000c0b01c0a8010a0000000000240c0200000007010000067f00000545fa000046fa000045fa0000000000007fffffff00300d020000000a010000080400000100000001060000014998968008000001000000000a000001000005dc05000000$636d8e6db5351fbc9dad620c5ec16c0b"
        )],
    },
    Vector {
        slug: "scram-john",
        hashcat: &[],
        john: &[john!(
            "SCRAM-PBKDF2-SHA1-MongoDB",
            "$scram$someadmin$10000$wf42AF7JaU1NSeBaSmkKzw==$H6A5RF0qz6DrcWNNX4xe+wIeVEw="
        )],
    },
    Vector {
        slug: "scram-pbkdf2-sha256",
        hashcat: &[],
        john: &[john!(
            "SCRAM-PBKDF2-SHA256",
            "$scram-pbkdf2-sha256$15000$OxAPvANwV/ZQXqgiW6s6o2+wPM+gfZNthjpUjw==$MenSdE9VmSij4sIKMKfRs+bHy9vkareAopWM8MB+364="
        )],
    },
    Vector {
        slug: "siemens-s7",
        hashcat: &[],
        john: &[john!(
            "Siemens-S7",
            "$siemens-s7$1$599fe00cdb61f76cc6e949162f22c95943468acb$002e45951f62602b2f5d15df217f49da2f5379cb"
        )],
    },
    Vector {
        slug: "streebog256crypt",
        hashcat: &[],
        john: &[john!(
            "streebog256crypt",
            "$gost12256hash$password$awrQfwgXMa0BFMCtZu97GJKqeVszI/B2usmTf9cpOa/"
        )],
    },
    Vector {
        slug: "vmx-john",
        hashcat: &[],
        john: &[john!(
            "vmx",
            "$vmx$1$0$0$10000$514fb565d74db333352661023874f07d$81dc8986e299d55dee724198a572619b87de0b96501dd2285fbe928c831446fb92c056e02e6ca0119213e9cf094222c0e4d0df6f014615c915412cb0c892d4528070ead0d2443d0c457a7db445fd17b060899033a5c69d43315abd3d262ad3570379c12c97fc2490d7a42b04f99a24386f27aa56"
        )],
    },
    Vector {
        slug: "wbb3-john",
        hashcat: &[],
        john: &[john!(
            "wbb3",
            "$wbb3$*1*0b053db07dc02bc6f6e24e00462f17e3c550afa9*e2063f7c629d852302d3020599376016ff340399"
        )],
    },
    Vector {
        slug: "wpapsk",
        hashcat: &[],
        john: &[john!(
            "wpapsk",
            "$WPAPSK$Coherer#..l/Uf7J..qHUXMunTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosMyXdNxfBZUAYmgKqeb6GBPxLiIZr56NtWTGR/Cp5ldAk61.5I0.Ec.2...........nTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosM.................................................................3X.I.E..1uk0.E..1uk2.E..1uk0....................................................................................................................................................................................../t.....U...8FWdk8OpPckhewBwt4MXYI"
        )],
    },
    Vector {
        slug: "armory",
        hashcat: &[],
        john: &[john!(
            "armory",
            "YXI6DKXVcrlt7I85ct/qzlUSXX1MCs+wbXVpJdtrw9RuXZpMowuOXmfqMiuFKj0/g/G2sQScLr6+dsiNrh/OOlsDzP4T60QAAIAAAgAAAIZidMeJWIXezaAL+WpoA5nbs9eGf5syXhOnHYF65Ftmo4p+jw=="
        )],
    },
    Vector {
        slug: "formspring",
        hashcat: &[],
        john: &[john!(
            "FormSpring",
            "2a4fa0bf8c6a01dd625d3141746451ba51e07f99dc9143f1e25a37f65cb02eb4$RA"
        )],
    },
    Vector {
        slug: "gost94crypt",
        hashcat: &[],
        john: &[john!(
            "gost94crypt",
            "$gost94hash$salt$sG.6rfU0vKHX4eL00bUDqjXxaAcQHqpJQlM3ctfj013"
        )],
    },
    Vector {
        slug: "iterated-sha256",
        hashcat: &[],
        john: &[john!(
            "Iterated-SHA256",
            "465865d4226c4d9696e601f2c99b25ae2c194ec01806bafc93933331acfc1a60e8bdcca8be9fa245a5fa16029bb52480915746f47d1c539d01da7ec6f37468d1"
        )],
    },
    Vector {
        slug: "lotus85",
        hashcat: &[],
        john: &[john!(
            "lotus85",
            "0040B2B17C344C236953F955B28E4865014034D1F664489D7F42B35FB6928A94DCFFEF7750CE029F94C83A582A80B4662D49B3FA45816143"
        )],
    },
    Vector {
        slug: "po",
        hashcat: &[],
        john: &[john!(
            "po",
            "550c41c11bab48f9dbd8203ed313eef0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )],
    },
    Vector {
        slug: "wpapsk-pmk",
        hashcat: &[],
        john: &[john!(
            "wpapsk-pmk",
            "$WPAPSK$test#..qHuv0A..ZPYJBRzZwAKpEXUJwpza/b69itFaq4.OWoGHfonpc13zCAUsRIfQN2Zar6EXp2BYcRuSkWEJIWjEJJvb4DWZCspbZ51.21.3zy.EY.6........../zZwAKpEXUJwpza/b69itFaq4.OWoGHfonpc13zCAUsQ..................................................................BoK.31m.E2..31m.U2..31m.U2..31m.U................................................................................................................................................................................/X.....E...AkkDQmDg9837LBHG.dGlKA"
        )],
    },
    Vector {
        slug: "iphone-passcode",
        hashcat: &[hc!(
            26500,
            "$uido$77889b1bca161ce876d976a102c7bf82$3090545724551425617156367874312887832777$50000$2d4c86b71c0c04129a47c6468e2437d1fecd88e232a7b15112d5364682dc391dbbbb921cf6e02664"
        )],
        john: &[],
    },
    Vector {
        slug: "oubliette-blowfish",
        hashcat: &[],
        john: &[john!(
            "Oubliette-Blowfish",
            "$oubliette-blowfish$16c863009dbc7a89fa26520aeeae5543beda0bbf41622be472d7c7320c8ea66f"
        )],
    },
    Vector {
        slug: "oubliette-idea",
        hashcat: &[],
        john: &[john!(
            "Oubliette-IDEA",
            "$oubliette-idea$e82bb8b871ed9a2b7d77afce662325a2c522844e0e91bde104b8e4f68044e991"
        )],
    },
    Vector {
        slug: "truecrypt-legacy",
        hashcat: &[
            hc_binary!(
                6211,
                "87914967f14737a67fb460f27b8aeb81de2b41bf2740b3dd78784e02763951daa47c7ca235e75c22ec8d959d6b67f7eedefad61e6a0d038079d3721a8e7215e415671e8c7b3dbed6453a114e6db89a52be9a9c1698a9c698f1e37f80d7afaf0efba82b6e5f5df32bd289b95343c6775e2c7f025ef1d8bfae84042a92546e15b635b5fade3aef6ee52a7a5ab018d33ea98bc115dfc62af606187fbab8cbda6e8417402c722ca8c2b07e6ca6a33bf94b2ce2a819a9f8cfaa5af70e3af6e5350d3a306f036f13ff5ba97d5728d5f6413b482c74f528211ae77b6c169215c5487d5a3ce23736b16996b86c71b12d120df28ef322f5143d9a258d0ae7aaa8c193a6dcb5bf18e3c57b5474d24b843f8dd4e83a74109396ddb4f0c50d3657a7eacc8828568e51202de48cd2dfe5acbe3d8840ade1ce44b716d5c0008f2b21b9981353cb12b8af2592a5ab744ae83623349f551acf371c81f86d17a8422654989f078179b2386e2aa8375853a1802cd8bc5d41ce45795f78b80e69fcfa3d14cf9127c3a33fa2dc76ad73960fb7bce15dd489e0b6eca7beed3733887cd5e6f3939a015d4d449185060b2f3bbad46e46d417b8f0830e91edd5ebc17cd5a99316792a36afd83fa1edc55da25518c8e7ff61e201976fa2c5fc9969e05cbee0dce7a0ef876b7340bbe8937c9d9c8248f0e0eae705fe7e1d2da48902f4f3e27d2cf532b7021e18"
            ),
            hc_binary!(
                6212,
                "d6e1644acd373e6fdb8ccaaeab0c400d22eaa0b02e2a6649e065ad50f91e2f81fc5e1600d1cdf3b4ee72a7326a9a28d336ec65adf2d54661e1a609dd9941279fd64a9c513dfb0192734fc1e1014cdd0a399e89a0860c4077463c18609f5218254edd998adb11a02271723d1aa094550df385dd8e080cb42ed1349f69c0a6bad4b37e6dab1effbe0095471a8d640679422fe1533a21f10cb6d15e5ee8cde78e677acf3d09d008e9fbf57f09c1c57f19e51ff54631e0e2adc2ee2832425c1ec718d96a17df7e55aceffb7b23a1872f32795d4491c739e21b01e19a1b7dfcb22709c9d9302154462664a668ea635664df65804bf680ff07026d6f5b225762a3a270df832d47e7feb6277a228454a3ba9b5bbade23ecaec0eaf31ad1dbac31754c970a212bd44c9278bc6076f096a2eed602e04a70c6f7fa94ef4e75299692e5dcc6f1a7e6032b9b765e9e61faeed3f9efacc0a15b1817e74d48ec11a13d15811c7e2c4d12f36d35a04131d02f14184fc15bc20e79115dc7c980b681a19a225964469787df481b68a8f722f2bd3115dbbcb3c8ac1b07d742f78f30635dea29dfb1db83e89fc85a30b0379fc8aa69a4ea94c99052685d38c9559a1246284cdc32c5110eb8c6741352cd42e09e6389d4765c58aa84d51867cf86fba69d29eac1cd7fac2f36603d2fb2af146c5d4c2bedb4f6c6d0f387f0a8d635e33384df60f8d2415b"
            ),
            hc_binary!(
                6213,
                "3916e924d246e5ceb17b140211fff57b67150b3dee53fa475261d465b0ee3e56ee820e6ba3958d84c61508f028b2a112e9005877784e07deddcf310d01ba81710b620533790456d20d17c8fda84f9d93bbfe41509b931a417b82d68ed9b0bc9641b79a5bf8f71bcdbba979dfb7566a5b8ccc221f80722c1ce7ec81be4a8c880b1b057e681c187504eabf4eea32f7b81383defd4616618a99852d1678a6520883c8f3564e6dcf874150a060b9a44748d97f95b223b089ac847e31fb5a2db3656d7b57decff65e2c5c9af5bdece7a1845caa9df805fc1f7e56bf545d854beec27a9640bf1697c195e5f95b82c20d76c5a56ff4283219caa5a618e8caace9d0fcde0df6ee6e043ccbc78fd06a602cc638f7ae4675063b840ee08ffa9e143553bffd20126fa30f95e013aabf103f12c3ceeb284c80dc335fe2e78580d6ddfa80511aba9db7c93838cae0db40b9dbeccbf9d160032d334a9c35156721c746b51131baf6855fdfc1edee3099b8e4abc619e1c60e3ce68615e1eb42bd8d338046f7c854a60defe395e0d7168786a3035c9735cd42433dd0c46dcf8b5cb2c28905df80476561e55d6310b25f74d78b651ccd3484332c59a6ad490e29ea267db5ce4a47c9dcde39f420ba0755ea7e5583a3a562925acaa125d5056795b98135825232aa543a460137cc84235b85dd44d65e01e6eb1ade1b970f3ffe2b9762f5a7f261037e"
            ),
            hc_binary!(
                6221,
                "5ebff6b4050aaa3374f9946166a9c4134dd3ec0df1176da2fb103909d20e8b3c9b95cbbd6d1a7ad05411a1443ad6254e059e924d78bab6a0463e71cf7c3109b7ef4e837bf6d7a548dd8333c451b59d1132098f44c6ff19c6cb921b1de3bd0aa675e0478a05f90204d46a5d6ff598bfa40370ac8795928a6d2e0f1347696e3cfa329738170fe54298981d84f40c63d1a338c5db62679338e849124a28a79a8e505bb89a4673f0457b2737a00b908116310281b5b2eb66c6fda5599196b313d51ef26201335d715c18f6b128454a5601671e619bdcce8e54acb47d498c4161614a05063bff5497a4a3d99bff1fce2a163727af2fe9ae7512461b9dcebf3a4f1031d6235d8ce09b734294d0cedc04eafc6295f212b1b080e7b9745580d0dd18e99cfd95afef982762d5aabeaa2d3a928dcf36322cc06b07fd719c88e0b9a2625a94a77502d4bd40a85ba138cbd0cf9561aa395dc552801f68cce16e5484a672aa5b78665dc531ab1e3e728185929dc443b7f4c8a5cb687c6589bb3f4ddc2a8639d959b839b0813d50e7711b761622c3693a92e540e4f932c6c89bf4e1bff1d69151848c3d01b2f6aba52b58e5b393f6cd58ff0d2e040b1205b042b5a28d5b12cb0cc95fa32f1bcdebd4c82d889a5d87c45dcfd34e80b19bf7be35696e0fa0cbd9338b314de24c1ee7bbc0a3b6824f86af2aa5d127d21444985ff566e921431938f6"
            ),
            hc_binary!(
                6222,
                "9f207bec0eded18a1b2e324d4f05d2f33f0bd1aeb43db65d33242fa48ac960fad4c14d04c553e06ad47e7e394d16e0a6544d35fb0b2415bd060bc5f537e42a58b1681e991e2ec0b5773f6e8e5766e5fcc7335b19dd068d1f20260085ecda8eba366ff1521997c5654630ef09ba421b871a3dc66aa0dd5eba8a3bc7052398a7ad779506d86cbf687e76cd9dc50969e222820d2f905c0550995a9c068725bb6c8b04358c965ab77221fdfd829e57ce54cac6e2fa62db15043d720b72fa8962dd718a0b42c34577af9cb4a5ed04c1ae17b7af470c0d8b77987dc9e2d2593a52458c4acb83b628b1488371de85f78a2e25aeaebc18d20a8c3007d08949e93b80087707afd1fe4e07a0afee4244e5270f768e234b86852aa1556c53ffc0d6f60661369a484d55d063119e71e70af1ec775908466cac7b12bc22e1a9525c2bfa9f83f7901c8e0a1d56387ef65040b750656b0b75791738b5b7e453f24167eae56c057c94e1e4cf1a0d08894225f11b45bc31827cad1dfe62e148549385953aa16a0410dba231aace3a7b9fd9b1c2b930f01193377b59736d8a8959ca5b449655f79a4dbec0da566083f90caa2490b01a10c0a86dd4aaa719bdc1e4233db17217f03509cc20dab7246730e3f964944990690b6dcc84936e1dd487bd154ceefe58a838a0488cc93b854a112ea67f6802d2f409915e648ee5cf5fdc3c12e41acbfab7caa9"
            ),
            hc_binary!(
                6223,
                "721a7f40d2b88de8e11f1a203b04ffa97a1f5671623c6783f984cc7c55e04665f95a7f3fd52f402898aaaed68d048cc4c4fabf81c26832b589687dad082f3e4e0f23c7caba28118f21a4cbb8f32b25914ff4022e7c4c8cdd45411801c7c6bde4033badbdcb82f96c77b42025d13fa71415b3278138100ea58ee4476c81ce66f78e89c59ac22cf454684ea7e8c3900374662f23c9491891b60ed7ce8231a7ac5710ee87b51a3f7bd9566a60dc6e7e701c41f3810d7977314b321e8194349909f2ca458a976851d854eaeb934c8df2b5e063d416d3d7c464e28173a0bbba88ec75cf8fe68f21067739b2473bd804fd710de1e4d3ae9451b374edcfd8e3cd613b23aeae272e0923007482dac26a7532ab09af8aad57cd7f1c451bc260cc912d5830cb0d5332f792519e009ed5450171434e5f0f2ba9e003676933a86d83c766419fac98a7ee232eeb593d1686528fab576d5f393d82f9602bcd65975153df205b6d1bc50dacad2ea5bb184696f978efd2b1c1656bf87e03a28a536c48320c430d407ff6c2fc6e7d4ae7b115e79fd0a88df08eca4743178c7c216f35035596a90b0f0fe9c173c7d0e3d76c33a8fce1f5b9b37674bd12e93fb714c9cbba6768c101b5db8f8fd137144453f00dccc7b66911a0a8d87b198807f30be6619400331c5746d481df7ad47a1f867c07f7b8cd296a0c5e03a121c1a7a60b4f768bea49799d2f"
            ),
            hc_binary!(
                6231,
                "cf53d4153414b63285e701e52c2d99e148c6ccc4508132f82cb41862d0a0ac9ea16274285ac261c339c1508eec9fea54c33e382458662913678f2a88a84959a678e238973985ec670d50252677430587ee28b72bfa5edfb2f79c40b734ba8a54a3662642a6ab067e75f41154688ad4adb5d6decd891462dd537188195a51e06fa5baf22b69d0f472cfeeae77ab9a90091731863af1d8b5b380da179fa7d5227ef031732b1ae06e0fe34c0b28b7a64eac34e5a08e09d7001394b3afc804ac69bf819cdd2d383fe96a721f7c683628da8e529d84bdaa68d702573d8f7ef26f75d1bd5c91efa88cb33b1e9c006b87981c55ed3b8063ab7068f8e99b128bc56ea3e883efa55d6f340b2681e50405d91f5f6d76cdbeac404944164d329d3ee01311de0bc6547310f126b5a4c0e9fb74825f91faefa60b7ac828819d4544c1872ff5041e61d5cf093553f427358b2181046376d7b876e1bccf0774d5d251b7c922c214bb5c70c715165d028e1dca73e7adeca3396d77f6e597a10dd4c58f37fdbbdc1d04cd8890ba4c5025776a88a349bb925add13193becf1ca10fe32536db0c0b06a1ef799fb692e304b3716ca5a8a80859c4012ca3e06701b46b5a32f4d10e285a0cdaf6c24e0d98139e7f306e52503c9b503aa28f1fbbb236284907068074fcb3e267e3c4aab2bd3b79b24a7a08106bb55850fa2bb8e2f6d9919a6743cb822c164"
            ),
            hc_binary!(
                6232,
                "e9e503972b72dee996b0bfced2df003a54b42399e3586520cf1f69475ba32aff564e40e604a505af95ce15220f558ae815e94ce4953882a8299ee3fffb12e9bd62bf8e2c41c0a8337ce20d45715440cc83e394200d351c5b04be5b70fa11b8467320a091a1d703c88cc7b26fd114795c04a973b3266ba97f55d4b4e4771bb1b4a6aabc9d57e03f0ae7c8a77dfc3d37078efba45031e7d63bb514726e2f2dc6da8cce167a17e36b32c326a5bcaa2c4b445f6e10e1f899a9adcc2a698769f900b7909f7aec52fc9862d75286ffda67933f9c52e5c681d590ad0329b85f8db0f6bb6daa3b2d55b62c65da37e3e7fcb99954e0abe20c39724e8fb2c7f839ec67d35f151dfd8c4dd4bc8dc4393fab291efa08cc0099277d219a0ba4c6272af3684d8043ed3f502b98e196dc7aa0291627613179199976f28eff08649acf70aa0c0dc5896ed13eb18ea28fdd6c460a9c7cfedeab5ac80a3c195226cfca094a7590fa2ae5ed2133ba09b5466b2049b6291f8dcf345e5718a4c0ef3f9c8d8e07d0e5dddd07452b533fbf243ef063fb6d26759ae725d8ca430f8cf17b86665d23bdff1c9dbdfe601b88e87cb7c89f23abc4a8bb1f0b7375cc29b1d81c950ffe92e16e2080e1d6270bbb3ba753322d2b623caed87213e552c33e699d4010f0f61df2b7f460d7cd82e70a711388f1c0b591d424259d3de8b3628daf62c6c5b71864eb0e7d31"
            ),
            hc_binary!(
                6233,
                "de7d6725cc4c910a7e96307df69d41335e64d17b4425ca5bf1730f27820f92df9f20f3e855d8566eb5255927153f987348789666c8e563e366a09e68a8126b11c25ac817b2706dde5cec3946e64332b21b41b928985c1a637559ead5b4fecac74ff0d625ef6d8be93dea3eaca05394f23ee9e079d3504a77b4c0b22d3cfcafa9c670966bfa3a5f30539250d97267a9e56b5a1437b1fd2ce58f4ab78b52ba61d01c28d7a6b726d92c8819711c70f820690cf2b9bbef75f196ba87fb5f72a29e213096a8be3b6e6d0ff3dc22563dc9e7d95be68ad169c233289fccfdc2f5528c658cb178b4e78d54e96cb452859b01dd756ca0245bdd586fb450e84988071428c80af0a6dc5f16dea8094da3acb51ac5d2a710414256b2423e0333584437ea9a65a07f06bd241103a478d137e9a274a78a19d3ca121f1bc10e4c9e5fc277d23107db1fb447f71ba0f92b20e3ead77cffaca25f772182705a75e500d9aab3996bfda042f4bdfe35a3a477e355c76a711ad0f64848d6144073ce6ec4152c87973fc3e69626523463812061c51f51fc08487e8a4dbae1ca7965c11f222c607688b3384c5c29d4fe91d14d2cc940a6a9d94486d1823261928d88f56fe00e206d7a31734de0217afd38afa3d2cf3499c2dcff13332a369c4b1f39867f6dfc83ec32d19b931b082f07acac7e70bdd537e8432245c11662d89ec3cc97e582de5d2cc6bde7"
            ),
            hc_binary!(
                6241,
                "2b5da9924119fde5270f712ba3c3e4974460416e8465f222149499908c2fca0a4753b581f26625d11c4d3f49bdeb1c95bc3e17629d7e19ffb66175e5feab90a4fd670194f95d578266f3f54e61b82dc00efc2bb4438e19c3f6d7a92825a7625d88ec6286ab4e1761749edc83dad4340fd167544f09913fd6b03775013ff232fc4dad6f726ef82ad4bd1c5227a7796d7db35a912beeda5b0cdd798bc34d3ac24403c87dc672a983687dd64f920c991840a56105a6311797eed9976014909700366420673f6455242c71151ac75903a353538ec24b4feb967e2b46886395cf3e934e83a6a58ef2c0180273a0c33ba2bd870b1d84afb03d5558dc17bc7fb586404ad9a7e506ed859540110c6ad73f0f1d2be47829bc666e1838ec3f1dc1f610206241ce07fbf2542ecef9348b37aa460815794ca582709697cbf0c90c3dae4cb9dd97b29d3c7d82bd8d0c81d708e74c7007468c6c55a40fd4f803a4f5a75818d7da0d1ef333b8622e7de516fa62a6fa2b8d6d5d23653dfcedffec771456ee204e5c85ee88defbe195462fbe8ce0e2a5a455dab66478b877ec37dfa66f19ab5201c56cd707ba7bee1b10360965d3868c1fdf91dda124b1b0994fee75848083d19369735905bd2864b496c6e35ecf96f6dd4728570a45746bcf8d7d0ec0b9b0b112b28fdc53efcfa7d0558c132cd683a742d62b34304d9f991029c8aedc3d8767da8c"
            ),
            hc_binary!(
                6242,
                "debcc3e74a7b2acb4c7eaa4ac86fd6431da1d9579f4f76f0b31f07b3d36e65099daca9e4ae569114b3cb6e64d707b6206a2ab6b31ab0c17b356da3719d0e2fa4058f0349763970855d4c83b02a967bb2969f1b6f3e4fdbce37c6df203efbe87bfdb5ffd8fe376e9ad61862a8f659ef0db39e06ed34c4f80aa856df2219ac6a37ebb0244445db7e412b773f4e28846c5e65129cd4f4ce76979c083f08a7c4e2be30469b8363eaf8579baa870cdcb2bdca6b60e64559cb0def242576b80722bf36eb6d94640d2937b49edf9c9af67f0172f27319448425f86831c35ae35e764b9e69fcc47a42ba7a565d682366023291b1b4cbcd1b7ba6fba75c214e5849a9ba26197f7f010f01301dcbffaa7311f2ab32c2810470d3fe873334ca578adbfd04c5a39cbd53b09755e4d868dbf8a44d76cc91031f4710b8a985c70738b443572b4745ed10e6120852870b0fdb258f0a804d679eec85b5290235c9c526165b961f17ff0fe32d9f597c8f2ab9b84f3d22fef71fec67987e687590de6ab11b33f1b06f23c38ead94c3de419061b6568612c27517b0a3395e401a2c6058fc5f41f0e084e8f2157b6486624314b1f341f74cfdec9deaed7abf89ccf97b47441493e5086f1351f42a5c0929f6431753baadcd2fb347b8835d08250743bb45aaf1c6bb30eed98e911a273074b7e8ebad2174b527b1b84e1961967bf358711346482d9db1c7"
            ),
            hc_binary!(
                6243,
                "5e6628907291b0b74a4f43a23fb0693acb71c4379c3a3cc0eafbab40036bbdadfede179e04484aca0f5b6ecf7c7e8abe61d6836be6590838b8f9027da93ba77d076b9a557c958159c5dcddfb70823b7e324bd99b40a8f39410f6afd279df3493b58b9ffce41b65f3afd2fc467f4553a946b85e6ffc74b91c9c38c689d98419339a84d3c6d116274e34482d546407006ee04af03b594998127b2a9716ca4278b1f3050d015af10a9bb11db0465373f3a786c148bb20473377d8e97264b1c4d7ec4179829ce929573b26e5987b59da8591e2dc8e3934830dd0b5ac521c8637e9bb31e4bc084d53bc6a8dc6875e857a4c8c32a577eed3c6cea5beef514160982be2c7d7e2f4d65efa3f4a0e11ac1860ff3160e7cd968e18019abfd0395080a9f8e860c627fc32c63c8b7ef46b203c63cf0f12c05ea65b1f83a5f1fc6ad6cc200a9527151c2b8016a38f1e87be9c960088eaaa98a01d9db8cdacaae26c446a846042a6c0248b666eea7a1be44dc3fc35ce100c3a3eb377e898deb097cfba9246685d7ec8527cdc5e1983c154169178e3d86cd4017606ccc42d25cbdea0aca2b1ac422372cfbb1ad2b7d465449a2c1fbbae35c8e7fdaadd683a7dc991b76aaba08b8706916924407392a2aef458c2e833290dc1ff116f3f49f918e6a133b60728ac7c464e4f3521784cf32866be32877534bb014312c4301d1740781221a5e8758ea4"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "veracrypt-legacy",
        hashcat: &[
            hc_binary!(
                13711,
                "531aca1fa6db5118506320114cb11a9f00dade61720533fc12982b28ec71a1a3856ac6ee44b4acc207c8230352208d5f0dc37bf755bd98830279d6befcb6001cdf025f816a0aa1baf3b9b51be00fadb451ffbe9bdfc381115eeceeef778e29a8761f853b7c99e0ea9ec452ba77677f888ea40a39cf65db74d87147690684e273313dea15ff2039797e112006e5f80f2c5baf2c11eb62cb63cfb45883f8885fc7cd5bdb74ef57ec4fe3cec5c2025364582380366169d9419ac41b6f6e878429239e52538f9698e73700b920e7b58c56a4563f5aa512e334ddc56909ac2a0ad4146833f050edd78b7954e6549d0fa2e3b26ed2a769a6c029bfa4de62d49575acce078ef035e366ec13b6092cb205e481bc822f87972bfbe4a3915fad620c4b8645e96bcc468d5804208ae251a560068a09455657f4539dc7e80637fa85fbce058ffee421a98d85b2ae1118d9bd4f24e1e810627cc9893b7166e199dc91fd7f79740530a472df0948f285293478042b28cd2caef086a6ce9d5f656f97adde7d68924ef477fdf2a0c0b107671a1f94b2906d8fb58114836982e4e130e6944df8b42288512376553a1fa6526f9e46dc19b99bb568b30269d9f5d7db2d70a9aa85371b0ac71a6f6f564aaef26a0508c16bf03934973504a5188de37b18a689a020bc37a54d2863879e12902b43bc71c057fa47cbaac1e0100696af365e8226daeba346"
            ),
            hc_binary!(
                13712,
                "531aca1fa6db5118506320114cb11a9f00dade61720533fc12982b28ec71a1a3856ac6ee44b4acc207c8230352208d5f0dc37bf755bd98830279d6befcb6001cdf025f816a0aa1baf3b9b51be00fadb451ffbe9bdfc381115eeceeef778e29a8761f853b7c99e0ea9ec452ba77677f888ea40a39cf65db74d87147690684e273313dea15ff2039797e112006e5f80f2c5baf2c11eb62cb63cfb45883f8885fc7cd5bdb74ef57ec4fe3cec5c2025364582380366169d9419ac41b6f6e878429239e52538f9698e73700b920e7b58c56a4563f5aa512e334ddc56909ac2a0ad4146833f050edd78b7954e6549d0fa2e3b26ed2a769a6c029bfa4de62d49575acce078ef035e366ec13b6092cb205e481bc822f87972bfbe4a3915fad620c4b8645e96bcc468d5804208ae251a560068a09455657f4539dc7e80637fa85fbce058ffee421a98d85b2ae1118d9bd4f24e1e810627cc9893b7166e199dc91fd7f79740530a472df0948f285293478042b28cd2caef086a6ce9d5f656f97adde7d68924ef477fdf2a0c0b107671a1f94b2906d8fb58114836982e4e130e6944df8b42288512376553a1fa6526f9e46dc19b99bb568b30269d9f5d7db2d70a9aa85371b0ac71a6f6f564aaef26a0508c16bf03934973504a5188de37b18a689a020bc37a54d2863879e12902b43bc71c057fa47cbaac1e0100696af365e8226daeba346"
            ),
            hc_binary!(
                13713,
                "531aca1fa6db5118506320114cb11a9f00dade61720533fc12982b28ec71a1a3856ac6ee44b4acc207c8230352208d5f0dc37bf755bd98830279d6befcb6001cdf025f816a0aa1baf3b9b51be00fadb451ffbe9bdfc381115eeceeef778e29a8761f853b7c99e0ea9ec452ba77677f888ea40a39cf65db74d87147690684e273313dea15ff2039797e112006e5f80f2c5baf2c11eb62cb63cfb45883f8885fc7cd5bdb74ef57ec4fe3cec5c2025364582380366169d9419ac41b6f6e878429239e52538f9698e73700b920e7b58c56a4563f5aa512e334ddc56909ac2a0ad4146833f050edd78b7954e6549d0fa2e3b26ed2a769a6c029bfa4de62d49575acce078ef035e366ec13b6092cb205e481bc822f87972bfbe4a3915fad620c4b8645e96bcc468d5804208ae251a560068a09455657f4539dc7e80637fa85fbce058ffee421a98d85b2ae1118d9bd4f24e1e810627cc9893b7166e199dc91fd7f79740530a472df0948f285293478042b28cd2caef086a6ce9d5f656f97adde7d68924ef477fdf2a0c0b107671a1f94b2906d8fb58114836982e4e130e6944df8b42288512376553a1fa6526f9e46dc19b99bb568b30269d9f5d7db2d70a9aa85371b0ac71a6f6f564aaef26a0508c16bf03934973504a5188de37b18a689a020bc37a54d2863879e12902b43bc71c057fa47cbaac1e0100696af365e8226daeba346"
            ),
            hc_binary!(
                13721,
                "2be25b279d8d2694e0ad1e5049902e717f1bdf741bbd678bf307d510741b649d78c54dca46fb2c92723afd9a40769b295e66d445ec232af5bddf91481ee41256e56b77839e8bf55265077bab405901218ac7933f74073f1208f1de72aace5da4e07d5f83ca580c0216d36c200b54570a1d58e9d8e5c98a597dec23b74a465aeac572a99af70e1a1e20fd29c7c296099e4eed5b715cb470617ea4f20140b62ec4694af67d9158deac3ce846718e10518875ce8cea0286a487a295979e67159d06e871789bf5535b75c809b340f8627e18679e3dab839a1c9823ea14a07d5cc4251b777dddb408da147c70e7cc788a01c27b0ba4f4700d3248f59fa8217874ae4958ea4518522b44f7191ec19459faef7678422adecd58777487ef54a5305ff2caaa545dcb82f7e7a3eb30bd9f7ebab542d0964a367f9c710cf26bbd704e841d591428da3486db31c57f91c6167bf99e31839363cb93bc60d755031f96f2d2c964e1d85b7eaa104985ef801a21d99352c025d7415d5b2f1aa37dc513345d0ff6a1bca92ad7b8c265f322d04f2992895de32636c9b03318cf7154632d547debc1c5e0c8f8730a045efcf3d16ff956cf803716eee22168bc5a5ab72ddb5087436722cb0f59a5b7b03bc557ffb50e8757d1a5639e2bcddd8060de4ee5535fb614b4fc159c6a39040dcbe83889b9c6fac1c9364a7bea930d916ea23fafa0fde07ef609"
            ),
            hc_binary!(
                13722,
                "37e6db10454a5d74c1e75eca0bc8a70e67ac032357e4bd6a4315c0174cf9780f92210dfc0a3e977969f2890828d446aecc317dc40fb3162915998cc703e49257a950a1603342913900052011a7fa85fb0b1fd4489f17237ac1a8bbfd644e871ab95a4019f14b2b938d627646b9958b530dd0739760024ad323d36962b60ba92908e55a876fc392ac2dce6a2410bcdd30a01cba90427f02ccb96e222ab1381266a6f626aa00b0f59e743c1a77433cbb28648f04c91853bdf9b8b29917b2341bf7deb013131ad228ea0c7f9435985318431dae59faff46db3726341b97a956da4ad11766124cd06644c1ba1083b36d3f380f20c272e460b958841fc23be1820ad2e0e6db66eaf4ea171035add0ab543ce8e853e3119ceb9d7f32c0948b81604b81075bcb33efe747fec300a7c68ec383d28d560cccce713c0acf51d74c0db718ba93a9e720b657dda2409adf1ce35aa7e1c0d7ed3df98dd0b6d455a355ce02bda8bea8afc0a8341ac78214efd4372b4430270009ec65badf186e5f0d815dcf597b4703af95e3bfc03313125d2a88b9bb3788b6bbc3c7212713cd584a226b155a2e6872b33730af6fba29aa3dccdb0ec35b5d6e3d981faf39c8dd35fdcff502d14736bc6a47af6e4d7f3518f8ef5e0a4e5d521589a761757f86e2bef471d9867e9b532903c479e4966dcc99189fcdfa3d676f50ccd33fb7cc0aa3e85542ff2648c9"
            ),
            hc_binary!(
                13723,
                "d44f26d1742260f88023d825729cc5a64cf8475d887632a2fb4a84af27af138cfadc4bcbb122f6ba68339ae8427d1f72c0c4aeef041291492ae0a7d8677d8da43227ae2a26d9a433076b44458b14f52766cf0e4baeb473a789180660d62e42bbea7c042379a5a74e259463e1c18381fa13aee27141264be381de71c12f8f704913f211c45fda0295e963d90fc35272e907858c0522601f6e7a73b43ff222663f149a485fc6c464e5f3b7cc0b6508f30621385365ca8a4e0bff4061f64f5fbdb11f70f19d77e56fa6ff015ad76ecaaccd759d30da05d2a6fbf00ac9673ac3c23efd339313c2a99511e928f976bf9b2664d97685498d5931af2d453edc6fb1129e324eaba64264711fbe21d0d202b3659106e8100634f09c38cd15b1b3acba79d7f31d31fe23c166392e300db09f10550c83187566dc0fdf768b872555851b34e3c15ad7e7438a72e6126c895cf1204987df4b42cb7bc2fe03c5777867d269378c6e496df2a1a3457b907f7143a139d800868ad95e2901723c6ebb991054b4e991c67fe4c17702d9829d9dc1fe8bf4a956460721c858e31dbcbe56850a4ed31558c6ee89ba2cba2ef4bde77fed11848f9f92e0add54964a683c3686dbab4695ebc42554da922a08c6fff32cac936ea447e771aa74a689eb269ffef677294ef297600dfd73bbbb734d2968e38a98b4a8a77ff0eec8246d93b542e3521a3eb636101"
            ),
            hc_binary!(
                13731,
                "48f79476aa0aa8327a8a9056e61450f4e2883c9e9669142f2e2f022c2f85303b897d088dea03d64329f6c402a56fed05b3919715929090a25c8ae84c67dbdb364ebfa3e9ccc0b391c130a4c3dd6495a1d6eb5d2eab72f8009096f7475ecb736bb3225b6da144e1596d859dad159fae5a739beea88ea074771e9d0b2d7c48ae302606a60d7cff6db54f3e460c548c06a4f47dc1ac203a8c8349fbff6a652219a63f27bc76327543e22be4f8dab8e4f90a4283fbf1552119fe24114ce8869eb20ce87dd72300f7aad3f7b4a26a355f16517725449151cf0373dbd0b281f6ac753485a14a5361cc75d40928e241a6b4684658801774843238048cf8c7f2fd88950abac040e12b0c41fdcaca3702907e951ec11c061a91b3050a4855abe6f3b50b4bd0b17c4be1f5b50b873eadc2d8446cd72c4fcac576bbce3acea769f740c5322ee8c927ffd4dd11c8a9e66f06e58df2e5d4d85c13b44c412bab839c9512b7a0acdd97b37dcccc4b70854eda0f36de12d62dd10cc13bc6154103d083bf6540bc78e5d0aad5d063cc74dad4cbe6e060febda2a9fd79c238f99dcb0766ff4addcfd0c03e619c765f65b1c75d5d22c6536958bcda78077ff44b64c4da741bf50154df310d4e0724238a777b524237b9478277e400ad8146dc3ca1da83e3d2f1c5115a4b7fcdc71dd7d56ba86a2f9b721c9a4137aabb07c3c5fedcf5342c4fae4898c9"
            ),
            hc_binary!(
                13732,
                "1b721942019ebe8cedddbed7744a0702c0e053281a467e0ed69bf875c7406407d72eb8f2aea21270e41898c0a2c14382f86e04c15e7bc019d1d9dd813eabee0ae5173e3cb1d927859d3e6de1006335a5184ae12b4c8dc2db2b1cd785063152a776f4dc5cacc1856a919b880d704b7450f5a0e0c9521bc9b4d67213c36a50e6664a1cbcea33f997b858e654111c7e9fca74f361528e85a28880381ec2600e3c1cd508c3833dd21cc91978185cba53caefd7b3c82d219d49f0b41e536d32e8d3ce194ad7923ca742213e19dcebdbd9687979d5a594654a5c611e8b829c4019e90a3cfb14e5fd7f8ed91e0fc79eed182399f02a3e3e202d4becaa6730e1f05f99ce06ce16dba7777ccddac72e85f2d3be5ecc9c808ac273f10ceb71cad666166abc327c4061a5f47424a5b6d9d093782f34b49924342a2e8cea663446ed4232a9a415ee2dfde988fa827b06d7438fec20ad0689543c3ee4602ce3ec3806fc7d668ef7e34330edd1e077b329a7627fa3ae5c89308258a17ecefbee114c80c2ab06f8271f14de8f2d13d1d6e5a119b71a6bae88ab151f76cdb2442284bc481d0df7e2163c3acfe763d3968195450d275af9034a00184a30cefed163e636626bffe6a35df3472508a49cb2b9b4c4a95d11c5d17e4e0539e9f13112125515778bcd1c2813c62a02673663062ad60583ec6a02c8a572865829e5b8c767b285728bea4907"
            ),
            hc_binary!(
                13733,
                "5eb128daef63eff7e6db6aa10a8858f89964f47844acca68df82ebb2e73866fa75e3b7a53f9d2ff1ecdd1f4dc90e9c0fdf51f60d11b1992cd2971b4889edfc8920bbf346fd7693f675b617cb9e4e9a43e6f445021068fc13453b130f2eb1d753ee83ecc61dabec293e88b62110cf6a8fab670e171f6aba2226550b54893263f5fa086b3cc41dd3db2eae07b585e5162c7a0d9723a426d408d83266c4d6018dc1b8b456d28a224033a30bfe62b1e58c2ddf596e07f7ff31849a6f5cfcc1c977b82d8484c270d44ededb0afdb781295e92968fc8cc69766af0ce1e72f02d6b4e124ba4b1af71519dcaade857bb3f371f93a350da6e65ee46c2ac782f134c75c10fe9d653fccc08c614dc362871911af8b83bdfc479f770dfe4b3c86b5d895842c53852fe4912738f848bf7c3e10b8189d25faceab9ef30b6fa0284edaa471752ac2b65335179b8d605417709f64fded7d94383618a921660d4cdb190bbb3769a8e56d2cd1ee07078ebc3b68ebeb016893f7099018e40cb326e32b29a62806eaf1a3fd382f4f876bf721eadfc019c5545813e81fd7168995f743663b136762b07910a63b6eec5b728a4ad07a689cceecb14c2802f334401a0a4fd2ec49e2da7f3cb24d6181f01ceed93ee73dedc3378133c83c9a71155c86785ff20dd5a64323d2fd4bf076bab3c17a1bb45edf81c30a7bd7dbbb097ece0dca83fff9138d56ae668"
            ),
            hc_binary!(
                13741,
                "528c2997054ce1d22cbc5233463df8119a0318ab94aa715e6e686c898f36690b443221a18f578fb893e0db1e4b875cc711eab542e70e13b55d6aa26134e1a8d34f5ae6caaea7390a5e2f50130e85f9e551216dd0895f4fb0bcdec219246c249236771e1f2a1f447054d363c398ab367ed7f9574eb0611211e742f429cd53b56fcdb42d2eb183c134847dc6efc7c8293d6481aa53406f0446398591956f79ca3ce76e80208fd409d0f6f14c68312fc119ab4292972338b1457c73585ae2fc863bf202f141495de50253799cbc27010fba6de6b0a36888d12f4e3964aaaf43a830097aee7d40c5e79e5e80e7b0228a67a95bb4969dd8afa0d51d6fff340f82e824547c708b5aa59274009d7d847c53a8019e73c068c6e96a4c3c6c27d0e9f4a8c3a9c52c964eebc00128e9a539f4f569606c92bfc2d4662494a1a6aca239d73399645c86bd66b8985b5bf217b29eeba0507a388aeec85fe94f6b42a1b805ecb90a08b2c8081fe51e76bc1d97f73ae10c72a9b2db694304e04807820c088f91bb97d4585493f3e6cc392a7e56a64a66b8e11b51898b4f956d1b5fe8cf55772fd6f8c0f2a2bb2d9fef05ab2bb90f251ff2e6aa0dfffeac9e045be2ec44ebc8dd4d260748e308205475dcc2cef369e869bfc1e6d7335620c694f524260770838c768346d83af7b467cdc80814d8f55a535dbac35fc278d0d1f6101db95019cee097bb"
            ),
            hc_binary!(
                13742,
                "a3c0fa44ec59bf7a3eed64bf70b8a60623664503eeb972eb51fa25ee921d813f8e45d3e1ab1c0088a62482bb78c6e07308d2308d3d66831505b0cb02fe214fbac8a51cf9be2ada3c46045afa7df810f2e7b57792150de63b111a9aa78d70e25d832b3d6901aa455b32da240ff68380d66da27f4f7ccc5fadc6b3ff68e27b6d5c48e6512865e3b9fbe2a64a55454cfc333d7850603ecf8e1cf19abaaf8c1581a6fa14c5091ebe70e6338081d72d6a95b542764f3865946edc8e626e166cc2e0f6260032f8decdd98f9a82aa2b065a41e9b42ce8c33d3f935706431d19888bd5b2bd4d34d9bceb8596b15994f247169ee7f8cd34b6955362b60f37a4167c7b63bab8af65e7c592e9ba4535c255b4b3d93b302aa017ea335af20f9d9696f1eb37770ca87b0245d29887cc4611a3a43d11170219c509814eb1fc122a189c08394f22309dd48a996cbfc70cf67f76b6b19e46407a12ef001b2c360501dbd63d1c9f85132204709204992078318920b32aac917bb98d8eeefb60abef47571404d069a6df7881f8e7815c18789f23561d7d33f47e1aa97fb4a60bac0332b0e742a9b0498e5641401567615fd6dbd0fcfff07aebce0d543f2c498486f15f38dcf1dd55d7144d3fc51bf1f491798b183a84f3f49a72944c8054cdab915e19dc376ae3fa681d4afcd7b13f425e96340a696a4f11929b2e769ba207c5bf2c2976a3834c499d"
            ),
            hc_binary!(
                13743,
                "1a8c0135fa94567aa866740cb27c5b9763c95be3ac0b7b5c744a36e48c08ae38d6d06ae5db926c64d05295cef134fb4d8eaa96a7b5673a1439f55c8ab829390ea945babc464e63f3aa33dcfed72c1bcf4051af13da96a2601a060d8c8be0343a7a4f0394b2bdd419b019bd10c3d39f0b6d9afd833816ee9ee5a8afada52db174a85ee029c46b706f8f96e937bb71569b65c2339a3ac8d831733888717fe08029013931ebed1fe932ceb16e52a5d54204e181057584d06991b8e9b16ba557d38f00e7c2be5ea864473e5e35d00a58b7ef8888c78d52ac1933011ca6c447bd16751024186657d1e314540e2c847115b70a51a23e61426ae09e646d715f807eed85e5c14ab2130da0ba86ddc40d3cdce035b454fceb969094d8d1b66e69f34e24d642dc244a81d163c395837d4cd9e2d581f4bb470ad4e5a2037068947f14676796f4adf208621c3db4629b3fec9a24edebfc37f97ea657295a2efbdd18fc44a0cc04f429d4da374db3ba2f3fc7dece70b64ac2c2a94ce5334b20b4251534f9ff3f60b1b252019d2617379bba68a4bc621cbd070881301beb0300bee243d113347d2f0a52fa79fb9fb349eba0056678618c006287e9730a0af32daa17841d88b99e25a9afcedd292a0592565f0ba533f1022ed4d6e51e64b98bab390fee3646133a0e02a5724bb14203fd50006e4be86544b62a9cb64188fbbf4ccd90a32022aa7c"
            ),
            hc_binary!(
                13751,
                "b8a19a544414e540172595aef79e6616f504799b40a407edfb69d40534e93f0bdb3187876f0b7a21739b3a9bb02bd4752eac4d2021e65a2a9413cc389964fad46e2cd37f337eb3fe3c75909fe9911609d084fb8c09543f949e738fc2fcfa4825ca5f1e08678e711142553f95b19ba720fa6c8ae5d325be0b36b93c1b2683b0944d2ad4e858c1d83f21a302ef721b9a570233219b9fcf95919fef9ca353af32d7ceb0b3058986c4ed9580b8058325403d45048e43d9e94a1e8fbaa0658f82f81940ea821e1bd526829ee6478a32da4095ab9e7c04dac3b6cc08f99348467a5bf068ba54d0aededdf6005c18ee37e21ee8d980cabe470be49d332661761934f5c07126001c290002587ba4b49982fefaac41b62f7e74ce943bb40a2d78094f734d1bc2aa3dedff43ee2a7b8f3525743c76194637da9ebc2794bac14601e03aa98e9118023a184970b6b8f84f546af88b81e2fde836e286b57cbcbdd7d39334860571a5cc612b77f0c51c741854abeb320bf961aea99b88798199bf826970f2b1b8027499955f68e15328080289d8cf0569057e1ed887f956ce72b14dd13a1f61134e1195d13c68d9c298ae0183107e3a93dd13ee0730f1fabe3935ee70f4c6a1923abb3e0d0c8ecf45260c1444e7e73386acf29d3239d0160e097e6193099e10cc98f61bfda49df6b0635e73a9ccc7bdcc543306b40dd12b91023f61b21418af91"
            ),
            hc_binary!(
                13752,
                "1c3197f32dc5b72b4d60474a7a43afefb0d2e856a8fc4957c3fb1188b62cb0ca002f585c125bb33c5a5e85a665afae9fce15cb127c2fd9b5ee074a48fd95b3a58364dfd645968187d546443ba234f5cc40e78c4bdcd1e0c6d0a1208dd892442bc1dfe2a45bc4821e843bb6d9f4adf742c48c432daf0d4a51d42cafdfca281f0fab0caabde8005405840383bbfd8dbf227384891ffa501531549e0b9562c2dd77f0e6552d253acb20cbee9a75d17ec283a46006ee89cd53e3b538e054952ae6db7aac9f2f190590e697a2a8e22d080e88c32f4d27b5afe100647da2a5c80cfcb69e5a3db67cb2fcd86d89c1c53fab1bf3a287bb9002d092e75eb1fe6269a1603545dbf97b9d7fcc9485b6400f7b0abaccc31642cefd83f037e7314c6990c51af24ae894cc1c49a09d18f3ad91b3ef37ae5414fef280ec776d9c0bf84b2eb312c8cb0046bedf6f29b4aab30cdb34333f613000a39bf650341cbf33bdd47ba7bd9be8108a1254390b045d82b208d21aa45de7ca399f8e91845b9ffb47d9e6eeb506965622a2e842ec6897277388cbb6ca2a50117e228e84bebd98f9aba40f38dc3bce3b576cb08596836e50ef276ee3a76b8ce76735fd172e9bae284aa83e2677dac56e4624e66604a90e2e3ae704c64a0f27b51ce9e472891bbc212b4a6055e4482b2e6963507f9ffb477224372289fcfee5764a5f4bc7307a509e7c37c69b4857"
            ),
            hc_binary!(
                13753,
                "f421bdc1087b8319c12d84a680ceab0102e8e41c9ccffe76dbe0215dcfcb7b543f3e1bbedd099e88646823dae5bad8468b72436961ea8e0449a6b92b8bda7b9ba1fe215e997ec3be2ee5eb3b4d47c41d50998df2f883404fb66270f72b5ce666e7d5ca7847c4a8b2762723da1ad088b0ad75c4fd2ccbbfa4e3adf091b6af4f44f5484ce0c89a5b0db0cbe99b3a9d43d7ff6c4ddbc9636cacfedb26b59340c6eb3e8c587db41fc01f10da2974af96531b2bee5f0b9818c3b86a3cac4ba20e08c49be84af65eb40d51626161f4eef187bf5776a89e791f3f5cbcfaa510df201fb2bf35ff03e81d0572af9abbed3cac82681925a3d1954440a6037df78f7a1e63bea81c852571a21fb550f9fe114b82bf7b94290e362cef233186f17396488c0f259c83c50ac4f8cc27d3a134ddc98f14c2fe0dd6e7d6f5eec63848314dc5984979eeb79df326f80ee0e7f671072117903cb72bbbce4f750fca3f008dadf532241e05913704df6ca03edb9641775c3b6e3e328fd078c6d70298512118312cab8316bb6ddc0b860952c621b2bb4cec1b3c7da9b1cb4c494fec382fe85aefdc56570b54845a14651535d261db519be0e860a4e20c30c86cff6f9de6e16b68d09a0e9593d271df2740950e65f1fb16e3fee034183e540e2a3b0f76156f06946b5d1bfc62fe0cab3daa14603a8d21eb03a4d266e965b010c265c9a0e093084d262a8c03"
            ),
            hc_binary!(
                13761,
                "c8a5f07efc320ecd797ac2c5b911b0f7ee688f859890dd3fa39b4808eb3113219e2bf1517f46a20feba286a3f3e997c80361132262bc0dacb6e9f7088bec9f5689a0b989ad9d4cc847170422ecd3384c9ee5ccf813fa8fe8ba4d2e6a993c99032337032b83471e9e0aa2531d85481c6d66f3a0d24688e1a17b5e81b3f68736ed05279ac05bcb83bea0c813d807e8c5547f11774c93a0e9de280c1ac5b5f170c0a4b5234f7d0d35a8ec7ec69454607cd35be24428a7be1799beed0ccd6a2af49b920446ebb0cb0bebda4a86c386fcffbb61cb93894ad74819a288c6e5b2e12111011e9f149d165b91f79897f71a96bc17c2b7a5e184147a90e9289d143b597ea98797c560e91b454461d03182f1a6c0bfd2b332829f30f0f18c8253d3194aac7996d4c401a3c1de7b266962a7dd8bc0b071a357121f00bafda835584a119f8fa23306545c413856ad3b2784b8de8ce9377f180baeb0f41590eb603110ff0a82f67349711d6f1b5d707f9c655318af88530962b9127fcf3c73b4d26319a9760cd795cd5ecba203dade9e1c79af14a9e06b9b56ce0af024e6ac582bd3ced1051fb865b55b4b6eaa65789a0c31c04cc4f2fc7b458fda188907f16810f4ce6e12a264cdcb264f1c26533758b92f585a3bbc2cac84731d74e9603d1c43b321ca36b01e5724e0e5558bcba56b57c8d59ded93c12d2664350cf6a048bcfc5d62aa85c590"
            ),
            hc_binary!(
                13762,
                "6bb6eef1af55eb2b2849e1fc9c90c08f705010efa6443581111216b3e145201374bb8e626e4d94a4ce7ecabb11aa57610063fceed38ca9873b0e1194bd12121d2f6b8a71994c5982049c4517ca7178a55b68cee773e06532b46d68810ede1b18783d7bca98bebf1778d14ecc18e0791190402c6a82bf3ec93e715e65997812363cc6e6bcad4f751fce16f37bbc1d6ac1d0a24c5685e85501a7c46d1cd5b04c55c605357906e5957b99230e2e9834a206e6ff48270ddf3c08c39e5c8390b2a7b7e6064719dbac29ef7513ea78c0edf420eb7ac6db684e890c5fcacfb230996f335f48f4472eaa33f3abe59943a8e3bc27ff4c24fd42015fdacd5e2eaf448049b4aa5ef1c038ca853871fc7f2573aace0874cdd1f3e01140803c1ad036b801cc1a54d619064b9b31e70e7e2601fd7b40f67814320c56721e86ddb3c62ec8cb9680ca7d2504b9decf360e32497ace8171dd9602f01db3be1541f659643e1bdc5139815acdf4debf0186707569c9b57c0fd0031ce03a5091d7937bca8f37015fa35af5f44968176164c0b9194f895a2346dacc51f5e3e7be5682ea7860c4b4302a0f22edecc7ccaebb1c824c5ca4ed4c5e674e742a1d55a7d3e732e40f0107ffad1e3876ec909fac58f1ee21ac99de2c8c29272b1df9dd7f724ff497925898506c4f6e2ae81e285239e5260b119af959338340876b5b8fdd6fede67ae37d3c750265"
            ),
            hc_binary!(
                13763,
                "f95b222552195378a228d932f7df38ca459b6d812899be43944ba2e9bf47967ba35da17bf69cc3f424521983989a66fd3c7865af6dd8ac2aeb82e10c92cae66f62c89b7053d2ba18ee5adcebcf426cc7720f029f7ea5409b3b7182593afbee99f6a3828887d9da6438fafd766589c35c210de60b013d9f816f9a1c8e7e76159347611c3dba00f433aa419dcb9eaf59af6886fccd7d12ae09c2b3d7a8a6102c511e8a34b4c39df8b1938dd5fe037d7087cf2a33b5410df9a6d83d218819b32bc13999c2dd7e96eb740902699ffe5fbaa47270cf1a7e3488198495059e1520ad4ad8beec0c63827286c300555a30febfe29a359d7e364c0b52613d9cff9348152f6871b6210681ab8cfdf24b96c4793c546083197d6e5377a59d7fcab9aa679fddf550ac1ab04249d0d679e8a39ddcca26f9b8b21f7f8b71d64a0ad3d9e3ed9e2e41abd6a9b4ff4d4a7ab29c27882487909fb1118a91de8e2e2d0dea7501a63b7553fd4ff26a5f64964031c9aa3fabbc09e3f58b09ce42bbf3f05afe0f9ea18331c7ba1a887afe307fedc2be93568fe80def12e97d5e129c373814a560573ee6350f59b329352e28137aa31688c499ae1c20b25c91506c520cae56c969790204de1ba46773197fb6a72fd4742712375e89cb5ee41f3ec8b64f3322ba389c947e671b0414e981fe582898af8a5bab09e094f03cb4cab047e7547313a7d1ddba7b70"
            ),
            hc_binary!(
                13771,
                "444ec71554f0a2989b34bd8a5750ae7b5ed8b1ccdead29120fc030bd5186f312a7fa18ab4f4389d7798e43c073afd1e71dda2052db38dec04a700e8d6b488802ead0cf95d6e6cecc8eaf6464baf94a64acbbd1a86f826333115b6380bda18cf936150efd6ffc2a344bb78b0b4875781a8c5079772429ef50ddf148f35895496d2e39f32ffaf68a007b070b0beaad316c4b3adf43c0c58ad24430a34abf168ed455b64958ca5465cae0684adadc00f7b9c13fc7671b4520892d23aebff49ea92bc15e804cc650dc3bbd5b8f5122051636f0c576977d4b64ba355bf6e6a8e042fc5165f2a8affa51aa12ff718cee4c543976bf565997b4b57c74e79584e317f4bdb3920f2937c4251af87f432bb8ce78dcb30675246f0303db4aaea913c93be5a26d16dbf8d4d20773aa2a4608d2151491ca6593b51965baeaf9b58f78905df522bf88976fe9436a916c8de38d5a6ca7ca7f436e7982a36335a404298304322ebe194bb34e91e8f7ee7c6541679bb0ce9d80bf4431d1c475b1a785e943e57f8e27a4e665940389b6da2771bd27d943955185379f83ca6a124ec55b2b63d4ef2e2ad6ee27de25f959708f3a64facfe07f06e29459a14f02699751d530f258d0c744a759c188de4f9423f2bd21d3d999ea28df4f3a93a2c47a7e788fe43ccbfbe267277b048002da1ef8c1e7b26690230285675a3a8fdc0f2acf46a4cb24141b3ad1"
            ),
            hc_binary!(
                13772,
                "0f5da0b17c60edcd392058752ec29c389b140b54cd1f94de43dccea703b1fd37936e75a500b7f9d4e94e7f214c4696c051be9697792a856ebf9c0f5a598cf8ba5621e49c7505eba3b4738acdc860b6ed648f52e5b673ae06bb04616de438a090ab19abea11c30984ead06859de9b7aec8e436c40816f67a56cb53d5f125e58c42225315a4bf494da8128f0df924bcf6ad4b91c9efc5cb0be67cb0cd753c392388d780f57aba39197513a191cc684e9ebee41bc901dd99e9a625141cf98e55e8f74d838baea3bf8f411b85c14eff8cddd1720c2539eef7a38a72c4ed9745a05476b6a16bcda2a5391c94b6f499e3bea64ff412d03d060741e938ed3dc905d8bd6dbb2420e9277251ebe3421be389ea8b02782baeb258b9ec7e0732b3817ee6da58209871aee4e16d57a132c6215782364570238157d8a7fdcd29f54ab2295f68d027dc9f2e0c951afad7500cafe3219e6530699918ac55f4fa1141bc3596155b05bae2fdc8b0a5438edeb5bb0cfac592565b20645be90b406a1fd59846957e7539fd8423bfd4c7ae7d608aacb084ae887baa1a83b14afff8d2063565086c66e293234a8667af39642b90a38c3a5bd4fa8a787c60f73882535c9b34cb7b243465dcc32aff29cee0e741ff059c6acd8ddcbdb3cfafecdcd0f45c84dd871be4fbffd5ac2ab9e01898009adcf7d932c37d6568ad875e4d6ea15db29a1e8ba5a4e86bd"
            ),
            hc_binary!(
                13773,
                "18d2e8314961850f8fc26d2bc6f896db9c4eee301b5fa7295615166552b2422042c6cf6212187ec9c0234908e7934009c23ceed0c4858a7a4deecbc59b50a303afdc7d583cde1b0c06f0bf56162ef1d6d8df8f194aadcbe395780b3d1d7127faf39910eb10f4805abdd1c3ef7a66972603124a475e2b9224699e60a9e12f4096597f20c5fb0528f590d7bd317e41dc6a2128cf5e58a99803a28c213feb8286350b1d7ab56d43bb52e511f3c860e5002472a4454a549509c8ce0c34f17ece23d5b61aa7c63389c8ca44ed10c2caae03e7ed30b3ef98565926d7e4f3a2a9abf03b278083bed7aaadd78d5bffb7cd45ffae92990c06d9e9f375a77a94226035d1f90e177c46a04dab416dfb7ed7c4ed9ee7e84580bed65c5fee9f4b1545b9a7cf6af533870d393eced609aebe308ec1eee3729da09eb7df7a8d1282b15c4a1b8266a456c06b4ea20c209c549d5d6b58a861f8e15cca3b6cef114accbf470ec76d717f6d7d416d7a32f064ab560c1167f9ef4e93310fbd927b088bffbb0cf5d5c2e271c9cad4c604e489e9983a990b23e1a2f973682fdfe38df385474f73ecdc9bce701d01d627192d3051240f4b96bbdcf2346b275e05aa75add4acb97b286cc00e830fee95d0f86a8b1e315ccb6f3f8642180392b3baac01ed2c97c200489b5e5ca4dcb0a6417e622b6196482a10e640b2b6b08e3f62acac3d45dfc6b88c666205"
            ),
            hc_binary!(
                13781,
                "2bfe4a72e13388a9ce074bbe0711a48d62f123df85b09e0350771edc4a0e4f397038a49b900275c9158145a96b52f95e92f927b3f963c7eadb71a07518d643231041c457d2794d0aa505f794153b52b24441271185d386833fbabf0e880c51b544f583d0db2ab6a926ddd3cdd0b68a61d7f5fe3f0ac6aa06ca676a868f373d35073605cf9d521ff55862b5005213a881a7b9025afc3409fa34dc86496620835df072fecd5b501f15e08113835c510d9f0bfd09d2ef1ac0e7bd01f0523d74a54fe984eb497cb960cce5bb154e024dc0c6c61a61e20a45a8f8ef319c63ca9646fbe00930302a5910891a1bc84bd936c926ca535b3b40c9e0ab255363b24a28bb8216d3d32244a725774e6ebbd73d6d3f2a2adcbc28d5341679cbb747efd56db1a09ce80b24640583ffc6f7ca5bd60d59114afcc78601184ba8feadb8d472f86c32bebf70e8158aa56f9db3b3200ef432aa7b370aa4ba408ef11b70d6806f1a21aaa3b629fa06f71dac0ae3e0ce95c7e5b550fc8c46017e151cbbcdf64b3b62b1b846a08925a217227286acfdad35b28407d589bec9578c2a4e9a4320f4a78e1e590fdf53c0a20fe0a1bb6c7d693abcd0e991c449e569477980d4b8972d21e4abc917d897e48ca427c954c3a3e0c8465ef40de51ffc9188047c043224c4a18638f1d91cd88c36623a1d880f18fd0d6ca0b3bbfa7d5d795acfb63576e2c2d83772e8"
            ),
            hc_binary!(
                13782,
                "af7a64c7c81f608527552532cc7049b0d369e2ce20202d7a41ffb94300cbc9c7ce2130247f49ace4c1512fc3d1b4289ca965e8eb065b35faee5b8479a4e43c4a269f4ee7f6d20f22fe61b2570d46df07b4307f44ba6926f3b44524f0a47be2a0d677d225e2c50ff618b2e5078a19f0613a856bb3145d765cc4c1726aef27b5f03648dcf421b040e7b4fde3193ad9f8a0ae6d91c079610f826e3d556776753d8ca11320632c16a2e49a4eec6e8371681b39be2d7bb826d81dea19eb1dda2e6c71c520a2ad9128b3209a7caf10c196a16ac6f4267ffea8e7be7ddb856976438e0e997773dab75e3dfe0c047f82e4ed0b6e107261b891c4b161fa3c29017428afaaabee5c2dc727fa23b4195265716d92d06e7b828535a77521113077e6f219d7ca721eb5dab66524a530ca3ceba52e3703ec3f435ad1dfee092b090174f4acd1546107db5b403a0ba4fa90c0b4ec19af92a54ebedfd28783dcd83c78499bd33baf3ed10af229ff29634110e2970b6c04232dc95120a365947688abe011f0c8de0e651d9bd112ce0bdf80c4e37c77b962d92f1418272e7484df5217f5f2f3ba1e9b965773ed2727c5d03938516dd789236479b5ff340335c92260b1ad82a313ffa568f912fac799f93b857aaff7b4d76cb525f120a0a9efc376d39c8e27866eff689be01f5adf693ae63ad4b2a77ca96ea985ab7931457f4d8d1afaeb7e423dd752"
            ),
            hc_binary!(
                13783,
                "0c9d7444e9e64a833e857163787b2f6349224bdb4bbf788ce25156c870514226674725be3eebc3f2a2c2ee8adbf8bb3ec1405a333e8e091cec0c5aa77fa9b65048ca01d954912bf3a3b1c38c00297a33ea0e014156ce08d9526150c085e5e2776a1faeb272c6e9539f466f4f93ffe6497c77d3aed54ffcdf1a3e6171cffac7b2ad96bd9e7cc553058894058def68beea05891b0ce734b6a166b8a5f24b4052fc7014b424bd6c33c9d710fb409cdf1a6c7567c1ba6a3010b03f9bda8aa2ef6733542d198a316da0c83106a6c31043f11ac191169db3db994493168ea996737355ccff84f27f6792b3dc87025d3594edb9e759ba3885980df17bc8c751ce3aba0df67aa7997906348729e81c4893cc654dc6b1da3ff7c588a327f45b8acff976d0593cc607dad48a25468d7c3ebc6dd49aa32fc526dd513852cdec4b36f3683b4998800afa25bb968c242d4c66b9b0c77b20d7bd40ffb403e9e087990d59c94ee7d36e9ebfa35a310bab963c253596e6bc89f67d5307823851c526ac789d0628a3eb81f2cdfd7d7612d8be1dade1b17f30aa2bb5d02eb8534caca0c334a269085939a5041c4ad112d325b1bfe3e9851bfdcad80bbc05ecbddc3f2ac09e2ad7182daf6ca5ccc510a100514f5d2dce1ff5046e0c8e7edf0bdc27f8fcdf4e9b3bce786c24bfa28dacee65ee8c913fc18eee5df61b8a43224f3a9c4e1b5de7b600d9e0"
            ),
        ],
        john: &[],
    },
    Vector {
        slug: "pwsafe-v2",
        hashcat: &[hc_binary_only!(
            9000,
            "0a3f352686e5eb5be173e668a4fff5cd5df420927e1da2d5d4052340160637e3e6a5a92841a188ed240e13b919f3d91694bd4c0acba79271e9c08a83ea5ad387cbb74d5884066a1cb5a8caa80d847079168f84823847c631dbe3a834f1bc496acfebac3bff1608bf1c857717f8f428e07b5e2cb12aaeddfa83d7dcb6d840234d08b84f8ca6c6e562af73eea13148f7902bcaf0220d3e36eeeff1d37283dc421483a2791182614ebb"
        )],
        john: &[],
    },
    Vector {
        slug: "pwsafe-v3",
        hashcat: &[hc_binary!(
            40011,
            "50575333e4e2a590a5e5c8269f57ec04a8a1c0c03da55b311c51236dab8c6b96b0afca02000800005eaeee20c6cc10d5caa6522b3ca545c41d9133d630ca08f467b7aae8a2bbef51aa2df968d10b9c4cfb17a182c0add7acb8c153794f51337e12f472f451d10e6dcac664ed760606aabdbb6b794a80d6ce2a330100c76de0ff961a45cca21576b893d826c52f272b97cdf48aca6fbe6c74b039f81c61b7d632fb6fddd9f96162ab1effd69a4598a331e855e38792e5365272d4791bf991d248e1585a9ad20ea3d77b5d2ef9a711ef90a70ec6991cb578f1b8bdaa9efa7b0039e9ea96f777491713047bdd99fa1d78f06f23406a66046b387d3034e46b1f84129bba853cc18fa49f107dc0290547258d30566a4b1b363ff4c1c16cb2f5f400059833d4b651bfa508200cbdc7a75fc57ef90eb1d90b0deea8505753332d454f46505753332d454f466236710e2e2477878e738b60d0aa2834a96b01e97764fe980243a06ad16939d1"
        )],
        john: &[],
    },
    Vector {
        slug: "luks-v1",
        hashcat: &[
            hc_fixture!(29511, "tests/fixtures/hashcat/luks/29511.txt"),
            hc_fixture!(29512, "tests/fixtures/hashcat/luks/29512.txt"),
            hc_fixture!(29513, "tests/fixtures/hashcat/luks/29513.txt"),
            hc_fixture!(29521, "tests/fixtures/hashcat/luks/29521.txt"),
            hc_fixture!(29522, "tests/fixtures/hashcat/luks/29522.txt"),
            hc_fixture!(29523, "tests/fixtures/hashcat/luks/29523.txt"),
            hc_fixture!(29531, "tests/fixtures/hashcat/luks/29531.txt"),
            hc_fixture!(29532, "tests/fixtures/hashcat/luks/29532.txt"),
            hc_fixture!(29533, "tests/fixtures/hashcat/luks/29533.txt"),
            hc_fixture!(29541, "tests/fixtures/hashcat/luks/29541.txt"),
            hc_fixture!(29542, "tests/fixtures/hashcat/luks/29542.txt"),
            hc_fixture!(29543, "tests/fixtures/hashcat/luks/29543.txt"),
        ],
        john: &[],
    },
    Vector {
        slug: "luks-v2",
        hashcat: &[hc_fixture!(34100, "tests/fixtures/hashcat/luks/34100.txt")],
        john: &[],
    },
    Vector {
        slug: "luks-john",
        hashcat: &[],
        john: &[john_fixture!("LUKS", "tests/fixtures/john/LUKS.txt")],
    },
    Vector {
        slug: "truecrypt-john",
        hashcat: &[],
        john: &[john_fixture!(
            "TrueCrypt-opencl",
            "tests/fixtures/john/TrueCrypt-opencl.txt"
        )],
    },
];

pub fn vector_for(descriptor: &HashTypeDescriptor) -> Option<&'static Vector> {
    VECTORS.iter().find(|vector| vector.slug == descriptor.slug)
}

pub fn vector_modes(vector: &Vector) -> Vec<Mode> {
    vector
        .hashcat
        .iter()
        .map(|entry| Mode::Hashcat(entry.mode))
        .chain(vector.john.iter().map(|entry| Mode::John(entry.format)))
        .collect()
}

/// Returns the path to a reference binary, or `None` when the run may skip.
///
/// `OMNIEX_ALLOW_MISSING_REFERENCE=1` turns a missing tool into a skipped test
/// with a printed warning. Without it, a missing tool is a test failure.
pub fn reference(var: &str, name: &str) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(var) {
        let path = PathBuf::from(path);
        assert!(
            is_executable(&path),
            "{var} points to a missing or non-executable path: {}",
            path.display()
        );
        return Some(path);
    }

    if let Some(path) = find_on_path(name) {
        return Some(path);
    }

    if std::env::var("OMNIEX_ALLOW_MISSING_REFERENCE").as_deref() == Ok("1") {
        eprintln!("warning: `{name}` not found; skipping conformance test");
        return None;
    }

    panic!(
        "`{name}` not found; set {var}, add it to PATH, or set \
         OMNIEX_ALLOW_MISSING_REFERENCE=1 to skip"
    );
}

/// Scratch directory for one conformance run. It stays under Cargo's target
/// directory, never the system temporary directory.
pub fn work_dir(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&path).expect("create conformance work directory");
    path
}

/// Restricts conformance runs to the labels in `OMNIEX_CONFORMANCE_MODES`.
///
/// An unset or empty variable means every vector is checked.
pub fn selected_modes() -> Option<Vec<String>> {
    let value = std::env::var("OMNIEX_CONFORMANCE_MODES").ok()?;
    let labels = value
        .split(',')
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    if labels.is_empty() {
        None
    } else {
        Some(labels)
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|directory| directory.join(name))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}
