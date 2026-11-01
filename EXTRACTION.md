# Extraction checklist

Working list of artifact families to support. Remove or split an entry only
when its extractor and fixtures land; each checked entry corresponds to one or
more registered extractors.

- [x] OpenPGP secret keys (`gpg`, armored and binary, primary keys and subkeys)
- [ ] Windows hives (`SAM`, `SYSTEM`, `SECURITY`)
- [ ] Browser credential stores (Chromium, Firefox, and key material)
- [ ] macOS keychains
- [ ] PGP SDA, PGP WDE, and PGP Disk volumes
- [ ] Disk-encryption headers (LUKS, TrueCrypt, VeraCrypt)
- [ ] Wallet files (Electrum, Bitcoin Core, and similar)
- [ ] Archive and document containers (ZIP, Office, PDF)
- [ ] Network captures (EAPOL, Kerberos, and similar)
- [ ] Password-manager databases (KeePass, 1Password, Bitwarden)
