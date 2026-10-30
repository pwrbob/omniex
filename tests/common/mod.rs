//! Shared vectors and reference-tool discovery for conformance tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use omniex::{HashTypeDescriptor, Mode};

pub struct HashcatVector {
    pub mode: u32,
    pub hash: &'static str,
    pub identify: bool,
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
    ($mode:literal, $hash:literal $(,)?) => {
        HashcatVector {
            mode: $mode,
            hash: $hash,
            identify: true,
        }
    };
}

macro_rules! hc_ambiguous {
    ($mode:literal, $hash:literal $(,)?) => {
        HashcatVector {
            mode: $mode,
            hash: $hash,
            identify: false,
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
        john: &[john!(
            "PHPS",
            "$PHPS$433925$5d756853cd63acee76e6dcd6d3728447"
        )],
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
        john: &[john!(
            "netntlmv2",
            "0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700"
        )],
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
        john: &[],
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
        john: &[],
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
        john: &[],
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
        john: &[],
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
        john: &[],
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
        john: &[],
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
        hashcat: &[hc!(
            13100,
            "$krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$35e8e45658860bc31a859b41a08989265f4ef8afd75652ab4d7a30ef151bf6350d879ae189a8cb769e01fa573c6315232b37e4bcad9105520640a781e5fd85c09615e78267e494f433f067cc6958200a82f70627ce0eebc2ac445729c2a8a0255dc3ede2c4973d2d93ac8c1a56b26444df300cb93045d05ff2326affaa3ae97f5cd866c14b78a459f0933a550e0b6507bf8af27c2391ef69fbdd649dd059a4b9ae2440edd96c82479645ccdb06bae0eead3b7f639178a90cf24d9a"
        )],
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
        hashcat: &[hc!(
            18200,
            "$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac"
        )],
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
        john: &[],
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
        john: &[],
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
        john: &[],
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
        john: &[],
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
        john: &[],
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
        slug: "metamask-short",
        hashcat: &[hc!(
            26610,
            "$metamask-short$jfGI3TXguhb8GPnKSXFrMzRk2NCEc131Gt5G3kZr5+s=$h+BoIf2CQ5BEjaIOShFE7g==$R95fzGt4UQ0uwrcrVYnIi4UcSlWn9wlmer+//526ZDwYAp50K82F1u1oacYcdjjhuEvbZnWk/uBG00UkgLLlOw=="
        )],
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
        john: &[],
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
        john: &[],
    },
    Vector {
        slug: "md6",
        hashcat: &[
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
        john: &[],
    },
    Vector {
        slug: "as400-des",
        hashcat: &[hc!(8501, "$as400$des$*OPEN3*EC76FC0DEF5B0A83")],
        john: &[],
    },
    Vector {
        slug: "scrypt",
        hashcat: &[hc!(
            8900,
            "SCRYPT:16384:8:1:OTEyNzU0ODg=:Cc8SPjRH1hFQhuIPCdF51uNGtJ2aOY/isuoMlMUsJ8c="
        )],
        john: &[],
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
        john: &[],
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
        john: &[],
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
        john: &[],
    },
    Vector {
        slug: "multibit",
        hashcat: &[hc!(
            22500,
            "$multibit$1*e5912fe5c84af3d5*5f0391c219e8ef62c06505b1f6232858f5bcaa739c2b471d45dd0bd8345334de"
        )],
        john: &[],
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
        john: &[],
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
        john: &[],
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
        john: &[],
    },
    Vector {
        slug: "bitcoin-wif",
        hashcat: &[
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
