# Registered extractors

This file documents the extractors currently registered in
`omniex::extract::EXTRACTORS`. Extraction coverage status remains in
[`EXTRACTION.md`](../EXTRACTION.md).

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
