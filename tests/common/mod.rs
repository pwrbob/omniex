//! Shared vectors and reference-tool discovery for conformance tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use omniex::{HashTypeDescriptor, Mode};

pub struct HashcatVector {
    pub mode: u32,
    pub hash: &'static str,
}

pub struct JohnVector {
    pub format: &'static str,
    pub hash: &'static str,
}

pub struct Vector {
    pub slug: &'static str,
    pub hashcat: &'static [HashcatVector],
    pub john: &'static [JohnVector],
}

macro_rules! hc {
    ($mode:literal, $hash:literal) => {
        HashcatVector {
            mode: $mode,
            hash: $hash,
        }
    };
}

macro_rules! john {
    ($format:literal, $hash:literal) => {
        JohnVector {
            format: $format,
            hash: $hash,
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
        ],
        john: &[john!("Raw-MD5", "8743b52063cd84097a65d1633f5c74f5")],
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
        ],
        john: &[],
    },
    Vector {
        slug: "hmac-md5",
        hashcat: &[
            hc!(50, "e28e4e37e972a945e464b5226053bac0:40"),
            hc!(60, "7f51edecfa6fb401a0b5e63d33fc8c0e:84143"),
        ],
        john: &[],
    },
    Vector {
        slug: "sha1",
        hashcat: &[
            hc!(100, "b89eaac7e61417341b710b727768294d0e6a277b"),
            hc!(170, "b9798556b741befdbddcbf640d1dd59d19b1e193"),
            hc!(300, "fcf7c1b8749cf99d88e5f34271d636178fb5d130"),
        ],
        john: &[john!(
            "Raw-SHA1",
            "b89eaac7e61417341b710b727768294d0e6a277b"
        )],
    },
    Vector {
        slug: "salted-sha1",
        hashcat: &[
            hc!(110, "848952984db93bdd2d0151d4ecca6ea44fcf49e3:30007548152"),
            hc!(120, "a428863972744b16afef28e0087fc094b44bb7b1:465727565"),
            hc!(121, "d27c0a627a45db487af161fcc3a4005d88eb8a1f:25551135"),
            hc!(130, "0a9e4591f539a77cd3af67bae207d250bc86bac6:23240710432"),
            hc!(140, "03b83421e2aa6d872d1f8dee001dc226ef01722b:818436"),
        ],
        john: &[],
    },
    Vector {
        slug: "hmac-sha1",
        hashcat: &[
            hc!(150, "02b256705348a28b1d6c0f063907979f7e0c82f8:10323"),
            hc!(160, "8d7cb4d4a27a438059bb83a34d1e6cc439669168:2134817"),
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
        john: &[],
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
        john: &[],
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
        john: &[john!("md5crypt", "$1$38652870$DUjsu4TTlTsOe/xxZ05uf/")],
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
        john: &[john!("NT", "b4b9b02e6f09a9bd760f388b67351e2b")],
    },
    Vector {
        slug: "dcc",
        hashcat: &[hc!(1100, "c896b3c6963e03c86ade3a38370bbb09:54161084332")],
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
        slug: "hmac-sha256",
        hashcat: &[
            hc!(
                1450,
                "b435ffbacea34d5eb0dbc4d69a92f0152f2cf4cd364d34c2ece322ca22d8b334:21217"
            ),
            hc!(
                1460,
                "8b9472281c36c3a693703de0e0f1ffab8fc0ecdd3bc5ead04c76dd74ef431e49:70108387805"
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
        slug: "hmac-sha512",
        hashcat: &[
            hc!(
                1750,
                "138c00f17a1a0363f274817c91118f019aff09f937bfdaea844280a0c0e7811267cc4735d967d8640eed1218268c1c4a76fec8f7aa551491b353829f3a654270:885142"
            ),
            hc!(
                1760,
                "7d02921299935179d509e6dd4f3d0f2944e3451ea9de3af16baead6a7297e5653577d2473a0fff743d9fe78a89bd49296114319989dc7e7870fc7f62bc96accb:114"
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
        john: &[john!("descrypt", "24leDr0hHfb3A")],
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
        john: &[],
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
        hashcat: &[hc!(
            2100,
            "$DCC2$10240#6848#e2829c8af2232fa53797e2f0e35e4626"
        )],
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
        john: &[],
    },
    Vector {
        slug: "phps",
        hashcat: &[hc!(
            2612,
            "$PHPS$30353031383437363132$f02b0b2f25e5754edb04522c346ba243"
        )],
        john: &[],
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
        hashcat: &[hc!(
            3200,
            "$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou"
        )],
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
        hashcat: &[hc!(
            3730,
            "0e1484eb061b8e9cfd81868bba1dc4a0:229381927:182719643"
        )],
        john: &[],
    },
    Vector {
        slug: "wpa-pmkid",
        hashcat: &[
            hc!(
                22000,
                "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***"
            ),
            hc!(
                22001,
                "WPA*01*5ce7ebe97a1bbfeb2822ae627b726d5b*27462da350ac*accd10fb464e*686173686361742d6573736964***"
            ),
        ],
        john: &[],
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

fn find_on_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|directory| directory.join(name))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}
