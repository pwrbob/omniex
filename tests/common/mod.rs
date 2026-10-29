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
            hc!(3800, "78274b1105fb8a7c415b43ffe35ec4a9:6"),
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
