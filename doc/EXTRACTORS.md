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
