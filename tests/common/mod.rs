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
    ($mode:literal, $hash:literal) => {
        HashcatVector {
            mode: $mode,
            hash: $hash,
            identify: true,
        }
    };
}

macro_rules! hc_ambiguous {
    ($mode:literal, $hash:literal) => {
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
            hc!(4500, "3db9184f5da4e463832b086211af8d2314919951"),
            hc!(4700, "92d85978d884eb1d99a51652b1139c8279fa8663"),
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
        hashcat: &[hc!(
            5500,
            "user::DOMAIN:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c094853920"
        )],
        john: &[],
    },
    Vector {
        slug: "netntlmv2",
        hashcat: &[hc!(
            5600,
            "0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700"
        )],
        john: &[],
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
        slug: "ripemd-160",
        hashcat: &[hc!(6000, "012cb9b334ec1aeb71a9c8ce85586082467f7eb6")],
        john: &[],
    },
    Vector {
        slug: "whirlpool",
        hashcat: &[hc!(
            6100,
            "7ca8eaaaa15eaa4c038b4c47b9313e92da827c06940e69947f85bc0fbef3eb8fd254da220ad9e208b6b28f6bb9be31dd760f1fdb26112d83f87d96b416a4d258"
        )],
        john: &[],
    },
    Vector {
        slug: "gost",
        hashcat: &[hc!(
            6900,
            "df226c2c6dcb1d995c0299a33a084b201544293c31fc3d279530121d36bbcea9"
        )],
        john: &[],
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
        slug: "sha3-224",
        hashcat: &[hc!(
            17300,
            "412ef78534ba6ab0e9b1607d3e9767a25c1ea9d5e83176b4c2817a6c"
        )],
        john: &[],
    },
    Vector {
        slug: "sha3-256",
        hashcat: &[hc!(
            17400,
            "d60fcf6585da4e17224f58858970f0ed5ab042c3916b76b0b828e62eaf636cbd"
        )],
        john: &[],
    },
    Vector {
        slug: "sha3-384",
        hashcat: &[hc!(
            17500,
            "983ba28532cc6320d04f20fa485bcedb38bddb666eca5f1e5aa279ff1c6244fe5f83cf4bbf05b95ff378dd2353617221"
        )],
        john: &[],
    },
    Vector {
        slug: "sha3-512",
        hashcat: &[hc!(
            17600,
            "7c2dc1d743735d4e069f3bda85b1b7e9172033dfdd8cd599ca094ef8570f3930c3f2c0b7afc8d6152ce4eaad6057a2ff22e71934b3a3dd0fb55a7fc84a53144e"
        )],
        john: &[john!(
            "Raw-SHA3",
            "7c2dc1d743735d4e069f3bda85b1b7e9172033dfdd8cd599ca094ef8570f3930c3f2c0b7afc8d6152ce4eaad6057a2ff22e71934b3a3dd0fb55a7fc84a53144e"
        )],
    },
    Vector {
        slug: "keccak-224",
        hashcat: &[hc!(
            17700,
            "e1dfad9bafeae6ef15f5bbb16cf4c26f09f5f1e7870581962fc84636"
        )],
        john: &[],
    },
    Vector {
        slug: "keccak-256",
        hashcat: &[hc!(
            17800,
            "203f88777f18bb4ee1226627b547808f38d90d3e106262b5de9ca943b57137b6"
        )],
        john: &[john!(
            "Raw-Keccak-256",
            "203f88777f18bb4ee1226627b547808f38d90d3e106262b5de9ca943b57137b6"
        )],
    },
    Vector {
        slug: "keccak-384",
        hashcat: &[hc!(
            17900,
            "5804b7ada5806ba79540100e9a7ef493654ff2a21d94d4f2ce4bf69abda5d94bf03701fe9525a15dfdc625bfbd769701"
        )],
        john: &[],
    },
    Vector {
        slug: "keccak-512",
        hashcat: &[hc!(
            18000,
            "2fbf5c9080f0a704de2e915ba8fdae6ab00bbc026b2c1c8fa07da1239381c6b7f4dfd399bf9652500da723694a4c719587dd0219cb30eabe61210a8ae4dc0b03"
        )],
        john: &[john!(
            "Raw-Keccak",
            "2fbf5c9080f0a704de2e915ba8fdae6ab00bbc026b2c1c8fa07da1239381c6b7f4dfd399bf9652500da723694a4c719587dd0219cb30eabe61210a8ae4dc0b03"
        )],
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
        slug: "ripemd-128",
        hashcat: &[hc_ambiguous!(40086, "c79c5eefc7c8e629c12aa936f1bda9a9")],
        john: &[],
    },
    Vector {
        slug: "ripemd-256",
        hashcat: &[hc_ambiguous!(
            40087,
            "33d5166e2930db590e82d3a855564acc526568c39679d778844ebf9b5be75738"
        )],
        john: &[],
    },
    Vector {
        slug: "gost94-cryptopro",
        hashcat: &[hc_ambiguous!(
            40088,
            "256f021ad5729ca0a89fcb8377027f2f3a769748c8cdcb469cffab9aa2fac60b"
        )],
        john: &[],
    },
    Vector {
        slug: "tiger",
        hashcat: &[hc_ambiguous!(
            40089,
            "6e2d24e09a70a02bdd9c4885ea199b064982130432331b44"
        )],
        john: &[],
    },
    Vector {
        slug: "tiger-128",
        hashcat: &[hc_ambiguous!(40090, "6e2d24e09a70a02bdd9c4885ea199b06")],
        john: &[],
    },
    Vector {
        slug: "tiger-160",
        hashcat: &[hc_ambiguous!(
            40091,
            "6e2d24e09a70a02bdd9c4885ea199b0649821304"
        )],
        john: &[],
    },
    Vector {
        slug: "tiger2",
        hashcat: &[hc_ambiguous!(
            40092,
            "6ff6a5dc0f02836902a17fe15816fad45d6d39de1d14b240"
        )],
        john: &[],
    },
    Vector {
        slug: "tth",
        hashcat: &[hc_ambiguous!(
            40093,
            "4f5e0dc524eaf4c41fe58b74aa23d7e74db94153073c09cb"
        )],
        john: &[],
    },
    Vector {
        slug: "snefru-128",
        hashcat: &[hc_ambiguous!(40094, "ba1d02bbc8eb20ace9162b1653da8483")],
        john: &[],
    },
    Vector {
        slug: "snefru-256",
        hashcat: &[hc_ambiguous!(
            40095,
            "7f224f9a530d90acae8c051c87e9f2dfd60232c6529aee3aec16e0578d625f7e"
        )],
        john: &[],
    },
    Vector {
        slug: "skein-512-224",
        hashcat: &[hc_ambiguous!(
            40096,
            "24a3df2fc779538c1c8f2372b9b87f9176922086fefd099bf9efca6f"
        )],
        john: &[],
    },
    Vector {
        slug: "skein-512-256",
        hashcat: &[hc_ambiguous!(
            40097,
            "45e91567c3263a5fb2bcb4a4e403c3b776c087be7176335b2b4d97d3ef47614c"
        )],
        john: &[],
    },
    Vector {
        slug: "skein-512-384",
        hashcat: &[hc_ambiguous!(
            40098,
            "ae07ebdbdc899f2e0fdd8ec11378ed673ed407eb4d947b334fc8ff4ae0da0b4b0505e43a5efe143cb33167bf3bac0e1e"
        )],
        john: &[],
    },
    Vector {
        slug: "skein-512-512",
        hashcat: &[hc_ambiguous!(
            40099,
            "67a6caf6e02968509ea3893d65eda0d8ffcaf22c6c5466357d3fd1e34c9a9e8c2b349b6ba6f8b2c2ee672f30c2ee982e5da7ee20509125830af88ff57169a742"
        )],
        john: &[],
    },
    Vector {
        slug: "panama",
        hashcat: &[hc_ambiguous!(
            40100,
            "ec3600d769166760e905fd928fd1172ea4e706eb23aff9dea91e052a6c699b7c"
        )],
        john: &[],
    },
    Vector {
        slug: "mdc2",
        hashcat: &[hc_ambiguous!(40101, "5da8fead05e8cd9d4d5424957b5bb4d6")],
        john: &[],
    },
    Vector {
        slug: "haval-128-3",
        hashcat: &[hc_ambiguous!(40102, "7bdb3946de69fa2bbd719b97f4472b4c")],
        john: &[],
    },
    Vector {
        slug: "haval-128-4",
        hashcat: &[hc_ambiguous!(40103, "6e2f70e6b9f2dd69cc6b85f6e4098292")],
        john: &[],
    },
    Vector {
        slug: "haval-128-5",
        hashcat: &[hc_ambiguous!(40104, "c339c70717f3448624ed14bf5e4c7784")],
        john: &[],
    },
    Vector {
        slug: "haval-160-3",
        hashcat: &[hc_ambiguous!(
            40105,
            "7e7e7fe1c80992a5183138e3948e4424c4121e6a"
        )],
        john: &[],
    },
    Vector {
        slug: "haval-160-4",
        hashcat: &[hc_ambiguous!(
            40106,
            "0a51a5fd18e4e288ae1a9234634af9df1b2a5b44"
        )],
        john: &[],
    },
    Vector {
        slug: "haval-160-5",
        hashcat: &[hc_ambiguous!(
            40107,
            "5d91ae221d22b2a9a4eba549fd6b3743ea2ca8d5"
        )],
        john: &[],
    },
    Vector {
        slug: "haval-192-3",
        hashcat: &[hc_ambiguous!(
            40108,
            "5d97366a5be117a571a6e0541397c2e3d051aab557a224b0"
        )],
        john: &[],
    },
    Vector {
        slug: "haval-192-4",
        hashcat: &[hc_ambiguous!(
            40109,
            "31fd78faba008a0dab71adc7d2acb60c43c34cb5ccc4f84c"
        )],
        john: &[],
    },
    Vector {
        slug: "haval-192-5",
        hashcat: &[hc_ambiguous!(
            40110,
            "2b0836388e3b8fbc0b2a675ac3668c6fe14e2957cc3f3084"
        )],
        john: &[],
    },
    Vector {
        slug: "haval-224-3",
        hashcat: &[hc_ambiguous!(
            40111,
            "fa9f54ea58a54f14bc9592e27b8aea42f21e3851a3d724be32e5813d"
        )],
        john: &[],
    },
    Vector {
        slug: "haval-224-4",
        hashcat: &[hc_ambiguous!(
            40112,
            "62c10f8cdb079d349e5d6af1c78c22e84beb332ba750a6c257c6177d"
        )],
        john: &[],
    },
    Vector {
        slug: "haval-224-5",
        hashcat: &[hc_ambiguous!(
            40113,
            "ce7053168ec92d0bb83e6039ada7477fef6eecfc3116d93278c0f36a"
        )],
        john: &[],
    },
    Vector {
        slug: "haval-256-3",
        hashcat: &[hc_ambiguous!(
            40114,
            "9ddb8d41435015df7caf22cbe436f512f90008a119fb7836c79af30a15e61e37"
        )],
        john: &[],
    },
    Vector {
        slug: "haval-256-4",
        hashcat: &[hc_ambiguous!(
            40115,
            "b5f791bf79336c8d34efceb2adf89550261640a122b05c3620740967c64e84aa"
        )],
        john: &[],
    },
    Vector {
        slug: "haval-256-5",
        hashcat: &[hc_ambiguous!(
            40116,
            "72f72ddb75c084e6bfe4b939299c55f3d1c1d79f5ec5a9cc3470e0fa56914e9a"
        )],
        john: &[],
    },
    Vector {
        slug: "blake-224",
        hashcat: &[hc_ambiguous!(
            40117,
            "b97223695a40301e703fde4f93c7e376635f5545b36302dff81e7f44"
        )],
        john: &[],
    },
    Vector {
        slug: "blake-256",
        hashcat: &[hc_ambiguous!(
            40118,
            "5cc8cc69c778c46c5a27790a887addda9b7b155e12adfbba7e97c5c1a6eac3dd"
        )],
        john: &[],
    },
    Vector {
        slug: "blake-384",
        hashcat: &[hc_ambiguous!(
            40119,
            "665ce5461d27a7a3d7b907b5d7822ed08ef5be964d4e46a550abf63fe08b0bfa0ac52357c3ac3903492d38dcb882e531"
        )],
        john: &[],
    },
    Vector {
        slug: "blake-512",
        hashcat: &[hc_ambiguous!(
            40120,
            "dbe858c23dc30b73d4df036696ce3189dbf971070bddebdd76004c9fbc0bf010d18aa1448212b098b569ef0b08ceedfe50f0899b4162d7c2115be3f7a725713c"
        )],
        john: &[],
    },
    Vector {
        slug: "bmw-224",
        hashcat: &[hc_ambiguous!(
            40121,
            "e307f60003a3440b5a324e3cbff297d752ccf07ec8474062f7030b1e"
        )],
        john: &[],
    },
    Vector {
        slug: "bmw-256",
        hashcat: &[hc_ambiguous!(
            40122,
            "94a9c07402d39d630c9d301d3ab3aa8a7d55493ab8417412d103a1212b0c5170"
        )],
        john: &[],
    },
    Vector {
        slug: "bmw-384",
        hashcat: &[hc_ambiguous!(
            40123,
            "7dc6a952dc1b116958198cf1d1ca9e972549a5558464e6ffe51b18f237d08ab43487e5a76288647cb18bb1c49cfe7f04"
        )],
        john: &[],
    },
    Vector {
        slug: "bmw-512",
        hashcat: &[hc_ambiguous!(
            40124,
            "1eaf35f8c9ccb48d6305f10df3f220bdffb416fc5b7335630a27f77f251f54e20933d8bcc784703ce2eafa1856df8879664d8d2a18f22ecb3cd40646b3c6c006"
        )],
        john: &[],
    },
    Vector {
        slug: "cubehash-224",
        hashcat: &[hc_ambiguous!(
            40125,
            "4b87a448b4ec677c4748cf8d00efac7662933807c37e3f837b5f9c57"
        )],
        john: &[],
    },
    Vector {
        slug: "cubehash-256",
        hashcat: &[hc_ambiguous!(
            40126,
            "83197263f83cd8665bd7aa75f3df2a569559a79a8eefe3057d30259b55334dc7"
        )],
        john: &[],
    },
    Vector {
        slug: "cubehash-384",
        hashcat: &[hc_ambiguous!(
            40127,
            "312a0146534d4ad452d696d8a44fb2d3fb4739cc83eb217a8a04620cfeac43a4c83ccdbd9a8c0cbe2a22aeb884dbc878"
        )],
        john: &[],
    },
    Vector {
        slug: "cubehash-512",
        hashcat: &[hc_ambiguous!(
            40128,
            "8884ea07f9b0a33433c734caaa28db1eb662958e0f7594f7199a336467ffe99711c6d0951c2f0ce717bdc9f757d979b360c4199b984a55a30147cc4cd3fb029b"
        )],
        john: &[],
    },
    Vector {
        slug: "echo-224",
        hashcat: &[hc_ambiguous!(
            40129,
            "dda4e7ebdab515a590e23a0160debb6467ddb124a3a4620f7511673d"
        )],
        john: &[],
    },
    Vector {
        slug: "echo-256",
        hashcat: &[hc_ambiguous!(
            40130,
            "4d8ab56039659b602c114b58688a8151f5f78b016b882e95b4c8ba0198d1c6c3"
        )],
        john: &[],
    },
    Vector {
        slug: "echo-384",
        hashcat: &[hc_ambiguous!(
            40131,
            "313332f8ddf5fbb4bbf34485cfc74c179ecb3fc0e8df1c82efdb4092859632bd2542e61f87a6a187c4f591226a6ccdd2"
        )],
        john: &[],
    },
    Vector {
        slug: "echo-512",
        hashcat: &[hc_ambiguous!(
            40132,
            "94d8804c8eb3de22edd238e80a74d6b91284853121fae4a78dc8c0f658e2a202d8eab1d266bc5fa99e81feef96c3d71e84be1e30b213354d52f1b9f0f22d4eb9"
        )],
        john: &[],
    },
    Vector {
        slug: "fugue-224",
        hashcat: &[hc_ambiguous!(
            40133,
            "0b1aaf18cd6cd949867b99aa28e7f19d368b064269e753e8c5ee01c6"
        )],
        john: &[],
    },
    Vector {
        slug: "fugue-256",
        hashcat: &[hc_ambiguous!(
            40134,
            "e545a4d7a9252cccd07152377af7326b262f43ce0a83eb447cbb82713b307e78"
        )],
        john: &[],
    },
    Vector {
        slug: "fugue-384",
        hashcat: &[hc_ambiguous!(
            40135,
            "adde0faf0065af5c2b5c41b177142870e4add47b54651f09bdf940c1a654c771f2c7908e486e5cb5b8cd2488a0f2ebeb"
        )],
        john: &[],
    },
    Vector {
        slug: "fugue-512",
        hashcat: &[hc_ambiguous!(
            40136,
            "920e968668a8a3aacff1c855449e7db1572fcbaa5d16a1ae7973a5868c95bddeae9551e6fc7d98760f23d320f614d175fd0e52068654bca17ca27080c68e9180"
        )],
        john: &[],
    },
    Vector {
        slug: "groestl-224",
        hashcat: &[hc_ambiguous!(
            40137,
            "088233a104bb48b9fbc22e96267488207f0520c102a5bbc3fbc5caa9"
        )],
        john: &[],
    },
    Vector {
        slug: "groestl-256",
        hashcat: &[hc_ambiguous!(
            40138,
            "fd032bc81a0ffed5201add8209a80c4f8d06c2b96a17ae5e1452e1a78ff3a31a"
        )],
        john: &[],
    },
    Vector {
        slug: "groestl-384",
        hashcat: &[hc_ambiguous!(
            40139,
            "1a66a7e00890353567076161c13f20a180ebda13b5bc9185cdbaeab28ba07c818b860e71fa1a9344c7978bf5ccbbf757"
        )],
        john: &[],
    },
    Vector {
        slug: "groestl-512",
        hashcat: &[hc_ambiguous!(
            40140,
            "a579375673904bf1cd42a7776744e7ff596e4896830aa441867795b4bf372d0a7567003dba016ae6f5f838eafc940f87367897c1578f3c31d274877cf5174ec2"
        )],
        john: &[],
    },
    Vector {
        slug: "hamsi-224",
        hashcat: &[hc_ambiguous!(
            40141,
            "56b7c2cd4d31621bb5350f7b915e3a534582285a7bd25845950449d5"
        )],
        john: &[],
    },
    Vector {
        slug: "hamsi-256",
        hashcat: &[hc_ambiguous!(
            40142,
            "23992c5687d75482dc8ccd8873f51fa597da826f777941e0ae19c11582592305"
        )],
        john: &[],
    },
    Vector {
        slug: "hamsi-384",
        hashcat: &[hc_ambiguous!(
            40143,
            "0b7fb3ab0059dab2664f896182e48b1b6b711bf87bc737aa4539b24a15078d8309b74f33112bec9b57b1ff6391c455b3"
        )],
        john: &[],
    },
    Vector {
        slug: "hamsi-512",
        hashcat: &[hc_ambiguous!(
            40144,
            "6086c74b28820775e4ab101a521ced7680985b43abe586d97096beaf87e89a5ebc0d4923decd9449c5226299e8f10961aff44747d088d98a47c662a137b543bf"
        )],
        john: &[],
    },
    Vector {
        slug: "jh-224",
        hashcat: &[hc_ambiguous!(
            40145,
            "69ff0662d2eb9ca2819fd714e14cad1ae1a3e8dffd6f56ac61e3db7f"
        )],
        john: &[],
    },
    Vector {
        slug: "jh-256",
        hashcat: &[hc_ambiguous!(
            40146,
            "d9a369b52c209dd119397326b8a16b0aca7dad7ada830bcba2a9e8739f1337f0"
        )],
        john: &[],
    },
    Vector {
        slug: "jh-384",
        hashcat: &[hc_ambiguous!(
            40147,
            "f3f78e8b52b7c24d49938d91ad406bae1b7879662f0acf95bf8bb93710bdf603f594e90292fdb135f130ad71206e0a42"
        )],
        john: &[],
    },
    Vector {
        slug: "jh-512",
        hashcat: &[hc_ambiguous!(
            40148,
            "824904b6ebd86ba610043d2e69f7e0755de4178a21a56960c39a26ec1b8046c48b2363b92c5de090ab4100c80703a3fc81cb75711057369541ed529b46770ad5"
        )],
        john: &[],
    },
    Vector {
        slug: "luffa-224",
        hashcat: &[hc_ambiguous!(
            40149,
            "22f54680de2d223b759198c33907627fd2f77aabf6888d37532b3000"
        )],
        john: &[],
    },
    Vector {
        slug: "luffa-256",
        hashcat: &[hc_ambiguous!(
            40150,
            "22f54680de2d223b759198c33907627fd2f77aabf6888d37532b300073c6d069"
        )],
        john: &[],
    },
    Vector {
        slug: "luffa-384",
        hashcat: &[hc_ambiguous!(
            40151,
            "8dd83061ff0d2fa32a84c98a360b3f1a509e5186fa64895e812decd9112cff72cfb450f8ef51c8264d3ef3307284b4d6"
        )],
        john: &[],
    },
    Vector {
        slug: "luffa-512",
        hashcat: &[hc_ambiguous!(
            40152,
            "a2d33bd8e84794c6bf3fefe2019c6af5ccf25a19b96e1a0ca83260812bf1f56a882d3e554710668b79ab886b3463245994ab70bc59765f285a0bbfc714745725"
        )],
        john: &[],
    },
    Vector {
        slug: "shabal-224",
        hashcat: &[hc_ambiguous!(
            40153,
            "3262dad883ed99f43a344fb2c5045253ce935fe36bb461826e27f09f"
        )],
        john: &[],
    },
    Vector {
        slug: "shabal-256",
        hashcat: &[hc_ambiguous!(
            40154,
            "69f72ed7674889359266a38a602f900505944cde9b9341e42018eb797a69cfdf"
        )],
        john: &[],
    },
    Vector {
        slug: "shabal-384",
        hashcat: &[hc_ambiguous!(
            40155,
            "c795ef512476e7dd3e9df347196ceadf0e5c34122ee092468941fa2ee96c904332e1d2764c74789b4f3bfe9edc8f5559"
        )],
        john: &[],
    },
    Vector {
        slug: "shabal-512",
        hashcat: &[hc_ambiguous!(
            40156,
            "d3d3b8e1030607bea0b49558e5e4a583a0365a611d615823895766b0449580228edf9c8c396cb0bb62c5ee8b589431640d9fc6e1f546d9921b37f2651e807ae8"
        )],
        john: &[],
    },
    Vector {
        slug: "shavite3-224",
        hashcat: &[hc_ambiguous!(
            40157,
            "dcd131d53b576e0615fd3c68e8d7bf32e4a70669e41b727db7f218ca"
        )],
        john: &[],
    },
    Vector {
        slug: "shavite3-256",
        hashcat: &[hc_ambiguous!(
            40158,
            "4822be4d566dc19f8c8cd67290eeeeeebd7579ba84a1a4a3fa0d58840a113b44"
        )],
        john: &[],
    },
    Vector {
        slug: "shavite3-384",
        hashcat: &[hc_ambiguous!(
            40159,
            "80d57b047711a509e9444c769e65c258e2feacdab7c4970cbb3e66f96a726c307f135e86022d270e26c8b92a6f186cca"
        )],
        john: &[],
    },
    Vector {
        slug: "shavite3-512",
        hashcat: &[hc_ambiguous!(
            40160,
            "6fc6c372cbbc8dfddab17b65ada3818795282ae5da4162ce4b2724c3b67636a494c15972792eb155106cbb2cc53d559c7fdd0f5937a3935ac55fbf25080acfc9"
        )],
        john: &[],
    },
    Vector {
        slug: "simd-224",
        hashcat: &[hc_ambiguous!(
            40161,
            "2f74b6bf688efcf84af322aaae9d520c14c73a7c2f23a950990b61b6"
        )],
        john: &[],
    },
    Vector {
        slug: "simd-256",
        hashcat: &[hc_ambiguous!(
            40162,
            "7cb7c2409260124fa0b3738b0dc42183d57fc92abf36e077bcb553bf493d9a12"
        )],
        john: &[],
    },
    Vector {
        slug: "simd-384",
        hashcat: &[hc_ambiguous!(
            40163,
            "6f6c2f83b43a3fe173ba9b58aaccee8e5e3fc2e4f191514c485acf79db9932edba23034f69530eb91a059bda05545ef9"
        )],
        john: &[],
    },
    Vector {
        slug: "simd-512",
        hashcat: &[hc_ambiguous!(
            40164,
            "fc4623e13134947b85f567426734c80f65d2c7cfd9ff410c4a26058731aed3d1efd3709d8a31ec1e10b4c38f587aa43740ab52ec6dae8dd8ead0818e808ef87f"
        )],
        john: &[],
    },
    Vector {
        slug: "has-160",
        hashcat: &[hc_ambiguous!(
            40165,
            "f070541c734597e89e371337bd82d7ebec8fe096"
        )],
        john: &[],
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
        slug: "md6-128",
        hashcat: &[hc_ambiguous!(40168, "387369565c845fffaa4e8c56d79f245d")],
        john: &[],
    },
    Vector {
        slug: "md6-512",
        hashcat: &[hc_ambiguous!(
            40170,
            "06bb86c04bb969f9057a034f0024b1b7a25f8378938d61e594f9a5b4dfb9fc122c8641eaf75d7b7c07de63cb7870822b8793c0e10b8177da56700bf2131eba75"
        )],
        john: &[],
    },
    Vector {
        slug: "radiogatun-32",
        hashcat: &[hc_ambiguous!(40171, "d013f6fde4161f6260784ac0940ab1d0")],
        john: &[],
    },
    Vector {
        slug: "radiogatun-64",
        hashcat: &[hc_ambiguous!(
            40172,
            "f972538913e4a99b318236833101e312c4922d83b40c8301ab3d81e0c82460a7"
        )],
        john: &[],
    },
    Vector {
        slug: "ripemd-original",
        hashcat: &[hc_ambiguous!(40173, "540a38d3ed9357f8f331867815733fae")],
        john: &[],
    },
    Vector {
        slug: "whirlpool-0",
        hashcat: &[hc_ambiguous!(
            40174,
            "21d9e5d0674ea7bfa40f2bdcae869cdccc2a2771481a1c08e084775a1424011a1c42149b2db396bc19ab2844b0cbcf9bf4043dd12bb6a91c12111f585f322dce"
        )],
        john: &[],
    },
    Vector {
        slug: "whirlpool-t",
        hashcat: &[hc_ambiguous!(
            40175,
            "e57fc143265bf3a566290cd59f7cd31ffe607e0acffe5a98bc7bb104e3f5bbd1fe047b42d054737a1adf37a626064bf6bba271e2b4dbaeab9e14c6d824a9246b"
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
        john: &[],
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
        john: &[],
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
        john: &[],
    },
    Vector {
        slug: "drupal7",
        hashcat: &[hc!(
            40020,
            "$S$C20340258nzjDWpoQthrdNTR02f0pmev0K/5/Nx80WSkOQcPEQRh"
        )],
        john: &[],
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
        slug: "streebog-256",
        hashcat: &[hc!(
            11700,
            "57e9e50caec93d72e9498c211d6dc4f4d328248b48ecf46ba7abfa874f666e36"
        )],
        john: &[],
    },
    Vector {
        slug: "streebog-512",
        hashcat: &[hc!(
            11800,
            "5d5bdba48c8f89ee6c0a0e11023540424283e84902de08013aeeb626e819950bb32842903593a1d2e8f71897ff7fe72e17ac9ba8ce1d1d2f7e9c4359ea63bdc3"
        )],
        john: &[],
    },
    Vector {
        slug: "hmac-ripemd160-pass",
        hashcat: &[hc!(
            40013,
            "4f5edca01734e03dd7e735362625a76e6bcb61b2:52355614946067"
        )],
        john: &[],
    },
    Vector {
        slug: "hmac-ripemd160-salt",
        hashcat: &[hc!(
            40014,
            "34d8e55a2ae1e9549a291326ce2f0a8dcdc75c5c:08523202563542341"
        )],
        john: &[],
    },
    Vector {
        slug: "hmac-streebog256-pass",
        hashcat: &[hc!(
            40027,
            "0f71c7c82700c9094ca95eee3d804cc283b538bec49428a9ef8da7b34effb3ba:08151337"
        )],
        john: &[],
    },
    Vector {
        slug: "hmac-streebog256-salt",
        hashcat: &[hc!(
            40028,
            "d5c6b874338a492ac57ddc6871afc3c70dcfd264185a69d84cf839a07ef92b2c:08151337"
        )],
        john: &[],
    },
    Vector {
        slug: "hmac-streebog512-pass",
        hashcat: &[hc!(
            40029,
            "be4555415af4a05078dcf260bb3c0a35948135df3dbf93f7c8b80574ceb0d71ea4312127f839b7707bf39ccc932d9e7cb799671183455889e8dde3738dfab5b6:08151337"
        )],
        john: &[],
    },
    Vector {
        slug: "hmac-streebog512-salt",
        hashcat: &[hc!(
            40030,
            "bebf6831b3f9f958acb345a88cb98f30cb0374cff13e6012818487c8dc8d5857f23bca2caed280195ad558b8ce393503e632e901e8d1eb2ccb349a544ac195fd:08151337"
        )],
        john: &[],
    },
    Vector {
        slug: "hmac-blake2s-pass",
        hashcat: &[hc!(
            40072,
            "0d541ae24d30aff2627c4d1a910f766088a64809edb46a05d29649a9b944da6c:1234"
        )],
        john: &[],
    },
    Vector {
        slug: "hmac-ripemd320-pass",
        hashcat: &[hc!(
            40073,
            "e740440e7bd65056a90f1aa4eb00e00308a9f1788866b4eacbd46cfc8032301d4e5b3a9d179be044:95454599772294521162217"
        )],
        john: &[],
    },
    Vector {
        slug: "hmac-ripemd320-salt",
        hashcat: &[hc!(
            40074,
            "345136b13b3a6e52901e2a414efa0cf5fca2fecf8b03279656d3b0f42c30df3006c5ad186494996b:2436077107013929602"
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
        john: &[],
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
        john: &[],
    },
    Vector {
        slug: "mysql-cram-sha1",
        hashcat: &[hc!(
            11200,
            "$mysqlna$2576670568531371763643101056213751754328*5e4be686a3149a12847caa9898247dcc05739601"
        )],
        john: &[],
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
        john: &[],
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
