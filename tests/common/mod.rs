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
