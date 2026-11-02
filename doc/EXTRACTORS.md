# Registered extractors

This file documents the extractors currently registered in
`omniex::extract::EXTRACTORS`. Extraction coverage status remains in
[`EXTRACTION.md`](../EXTRACTION.md). An extractor is exact when it can return
`Probe::Yes` for at least one valid artifact; extractors that are always
`Probe::Maybe` override `Extractor::exact()` to return `false`.

- `gpg` - OpenPGP secret keys, including armored and binary keys, subkeys, and
  ECC. The extractor scans the whole keyring, so secret keys are found even
  when public-key packets come first. RSA keys render to the matching hashcat
  mode among `17010`, `17020`, `17030`, `17040`, and `17050`; ECC keys render
  for John's `gpg` format because hashcat 8.0.0 rejects their two-digit
  public-key algorithm.
- `ansible-vault` - Ansible Vault files (hashcat `16900`).
- `filezilla-server` - FileZilla Server XML configurations (hashcat `15000`).
- `enpass` - Enpass databases (John only), selected by the `.enpassdb`
  extension and requiring `--type`.
- `fernet` - Fernet tokens whose version, timestamp, IV, ciphertext, and HMAC
  layout is valid.
- `jwt` - HMAC JSON Web Tokens whose header, payload, algorithm, and signature
  length are structurally valid. Non-HMAC JWTs are reported as possible
  candidates and require `--type`.
- `known-hosts` - Hashed SSH `known_hosts` entries (John only).
- `pwsafe` - Password Safe v3 databases in the John serialization.
- `pwsafe-v3` - Password Safe v3 database headers for hashcat `40011`.
- `encfs` - EncFS `.encfs6.xml` configurations (John only).
- `agilekeychain` - 1Password agilekeychain `encryptionKeys.js` files in the John serialization.
- `onepassword-agile` - 1Password agilekeychain keys for hashcat `6600`.
- `monero` - Monero `.keys` wallet files (John only).
- `bks` - Bouncy Castle BKS v1/v2 keystores (John only).
- `dashlane` - Dashlane `.aes` databases and secure archives (John only).
- `geli` - FreeBSD GELI metadata from disk images.
- `openbsd-softraid` - OpenBSD softraid crypto metadata from disk images.
- `pgpsda` - PGP self-decrypting archive stubs.
- `iwork` - Apple iWork 2013/2014 password verifiers (`iwpv2`).
- `ecryptfs` - eCryptfs version 2 wrapped passphrases.
- `kwallet` - legacy KDE KWallet files.
- `odf` - encrypted OpenDocument packages.
- `winzip` - WinZip AES ZIP entries.
- `dmg-john` - Apple DMG encrcdsa v2 images.
- `blockchain` - Blockchain.com wallet JSON.
- `electrum` - encrypted Electrum wallets.
- `ethereum-pbkdf2` - Ethereum keystore wallets using PBKDF2.
- `ethereum-presale` - Ethereum pre-sale wallets.
- `ethereum-scrypt` - Ethereum keystore wallets using scrypt.
- `adxcrypt` - IBM/Toshiba 4690 ADXCSOUF user databases.
- `bitshares-john` - BitShares backup wallets in the John serialization.
- `multibit` - MultiBit Classic `.key` files.
- `multibit-hd` - MultiBit HD `.wallet.aes` files.
- `vdi` - VirtualBox VDI key stores from `.vbox` configuration files.
- `vmx-john` - VMware VMX encryption keySafe entries.
- `virtualbox` - VirtualBox hashcat disk metadata from `.vbox` files.
- `cloudkeychain` - 1Password cloudkeychain `profile.js` files.
- `pgpdisk` - PGP Virtual Disk headers and user records.
- `pgpwde` - PGP Whole Disk Encryption user records.
- `ldap-sha1` - LDAP `{SHA}` attributes in LDIF exports.
- `ldap-ssha1` - LDAP `{SSHA}` attributes in LDIF exports.
- `ldap-ssha256` - LDAP `{SSHA256}` attributes in LDIF exports.
- `ldap-ssha512` - LDAP `{SSHA512}` attributes in LDIF exports.
- `apr1` - Apache `$apr1$` password hashes in text password files.
- `bcrypt` - bcrypt password hashes in text password files.
- `bsdi-crypt` - BSDi crypt hashes from `master.passwd` dumps.
- `descrypt` - traditional DES crypt hashes from shadow files.
- `md5crypt` - md5crypt hashes from shadow files.
- `sha1crypt` - Solaris SHA1 crypt hashes.
- `sha256crypt` - sha256crypt hashes from shadow files.
- `sha512crypt` - sha512crypt hashes from shadow files.
- `sunmd5` - Solaris SunMD5 hashes.
- `yescrypt` - yescrypt hashes from shadow files.
- `aix-smd5` - AIX `{smd5}` password hashes.
- `ssha1-aix` - AIX `{ssha1}` password hashes.
- `ssha256-aix` - AIX `{ssha256}` password hashes.
- `ssha512-aix` - AIX `{ssha512}` password hashes.
- `lotus5` - Lotus Notes/Domino 5 user ID blobs.
- `racf` - RACF DES records from CRACF.TXT.
- `mssql-2000`, `mssql-2005`, `mssql-2012`, `mssql-2025` - database user hashes in SQL dumps.
- `mysql323`, `mysql-sha1`, `mysql-a` - MySQL user-table hashes in SQL dumps.
- `oracle-h`, `oracle-t` - Oracle password hashes in SQL dumps.
- `postgres-scram-sha256` - PostgreSQL SCRAM verifiers in SQL dumps.
- `as400-des`, `as400-ssha1` - AS/400 hash exports.
- `lotus-notes` - Lotus Notes/Domino 6/8 hash exports.
- `openvms` - OpenVMS hash exports.
- `oracle11`, `oracle12c`, `oracle-otm` - Oracle hash exports.
- `racf-kdfaes`, `racf-passphrase` - RACF KDFAES and passphrase exports.
- `sybase-prop` - Sybase hash exports.
