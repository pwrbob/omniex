# Mode checklist

Working list of hashcat and John modes to cover. Remove an entry when the
corresponding `HashType` struct is implemented and tested. If one struct covers
several modes, remove all of those entries together.

Sources:

- hashcat 8.0.0 example hashes (`docs/hashcat-example-hashes.md`; local copy in
  `tmp/hc-hashes.md`).
- John the Ripper jumbo `--list=formats` output (local copy in
  `tmp/john-labels.txt`).

Conventions:

- One line per hashcat mode. A single struct may cover several entries.
- Use `hashcat --example-hashes -m <mode>` for a test vector.
- John `*-opencl` labels share the same hash string as their CPU label and are
  grouped under it; list both labels in the type's `ModeCompat::modes()` when
  supported. OpenCL-only labels are marked.
- Ad-hoc John dynamic formats (`dynamic=...`) are out of scope. Predefined
  `dynamic_N` formats are not enumerated in this first pass; add one when a
  hashcat mode maps to it.
- hashcat `[Bridged: ...]` modes duplicate existing algorithms. They are listed
  separately; normally no new struct is needed.

## hashcat modes

Initial source set: 728 listed hashcat entries (7 of them bridged modes).
Hashcat's plaintext mode is excluded below.

### 1000-1999


### 2000-2999


### 3000-3999


### 4000-4999


### 5000-5999


### 6000-6999

- [ ] `6211` - `TrueCrypt RIPEMD160 + XTS 512 bit (legacy)`
- [ ] `6212` - `TrueCrypt RIPEMD160 + XTS 1024 bit (legacy)`
- [ ] `6213` - `TrueCrypt RIPEMD160 + XTS 1536 bit (legacy)`
- [ ] `6221` - `TrueCrypt SHA512 + XTS 512 bit (legacy)`
- [ ] `6222` - `TrueCrypt SHA512 + XTS 1024 bit (legacy)`
- [ ] `6223` - `TrueCrypt SHA512 + XTS 1536 bit (legacy)`
- [ ] `6231` - `TrueCrypt Whirlpool + XTS 512 bit (legacy)`
- [ ] `6232` - `TrueCrypt Whirlpool + XTS 1024 bit (legacy)`
- [ ] `6233` - `TrueCrypt Whirlpool + XTS 1536 bit (legacy)`
- [ ] `6241` - `TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)`
- [ ] `6242` - `TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)`
- [ ] `6243` - `TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)`

### 7000-7999

- [ ] `7500` - `Kerberos 5, etype 23, AS-REQ Pre-Auth`

### 8000-8999


### 9000-9999

- [ ] `9000` - `Password Safe v2`

### 10000-10999


### 11000-11999

- [ ] `11400` - `SIP digest authentication (MD5)`

### 12000-12999


### 13000-13999

- [ ] `13711` - `VeraCrypt RIPEMD160 + XTS 512 bit (legacy)`
- [ ] `13712` - `VeraCrypt RIPEMD160 + XTS 1024 bit (legacy)`
- [ ] `13713` - `VeraCrypt RIPEMD160 + XTS 1536 bit (legacy)`
- [ ] `13721` - `VeraCrypt SHA512 + XTS 512 bit (legacy)`
- [ ] `13722` - `VeraCrypt SHA512 + XTS 1024 bit (legacy)`
- [ ] `13723` - `VeraCrypt SHA512 + XTS 1536 bit (legacy)`
- [ ] `13731` - `VeraCrypt Whirlpool + XTS 512 bit (legacy)`
- [ ] `13732` - `VeraCrypt Whirlpool + XTS 1024 bit (legacy)`
- [ ] `13733` - `VeraCrypt Whirlpool + XTS 1536 bit (legacy)`
- [ ] `13741` - `VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)`
- [ ] `13742` - `VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)`
- [ ] `13743` - `VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)`
- [ ] `13751` - `VeraCrypt SHA256 + XTS 512 bit (legacy)`
- [ ] `13752` - `VeraCrypt SHA256 + XTS 1024 bit (legacy)`
- [ ] `13753` - `VeraCrypt SHA256 + XTS 1536 bit (legacy)`
- [ ] `13761` - `VeraCrypt SHA256 + XTS 512 bit + boot-mode (legacy)`
- [ ] `13762` - `VeraCrypt SHA256 + XTS 1024 bit + boot-mode (legacy)`
- [ ] `13763` - `VeraCrypt SHA256 + XTS 1536 bit + boot-mode (legacy)`
- [ ] `13771` - `VeraCrypt Streebog-512 + XTS 512 bit (legacy)`
- [ ] `13772` - `VeraCrypt Streebog-512 + XTS 1024 bit (legacy)`
- [ ] `13773` - `VeraCrypt Streebog-512 + XTS 1536 bit (legacy)`
- [ ] `13781` - `VeraCrypt Streebog-512 + XTS 512 bit + boot-mode (legacy)`
- [ ] `13782` - `VeraCrypt Streebog-512 + XTS 1024 bit + boot-mode (legacy)`
- [ ] `13783` - `VeraCrypt Streebog-512 + XTS 1536 bit + boot-mode (legacy)`

### 14000-14999

- [ ] `14600` - `LUKS v1 (legacy)`

### 15000-15999


### 16000-16999


### 17000-17999

- [ ] `17200` - `PKZIP (Compressed)`
- [ ] `17210` - `PKZIP (Uncompressed)`
- [ ] `17220` - `PKZIP (Compressed Multi-File)`
- [ ] `17225` - `PKZIP (Mixed Multi-File)`
- [ ] `17230` - `PKZIP (Mixed Multi-File Checksum-Only)`

### 18000-18999

- [ ] `18100` - `TOTP (HMAC-SHA1)`

### 19000-19999


### 20000-20999


### 21000-21999


### 22000-22999


### 23000-23999

- [ ] `23001` - `SecureZIP AES-128`
- [ ] `23002` - `SecureZIP AES-192`
- [ ] `23003` - `SecureZIP AES-256`
- [ ] `23800` - `RAR3-p (Compressed)` (no test module)

### 24000-24999


### 25000-25999

- [ ] `25400` - `PDF 1.4 - 1.6 (Acrobat 5 - 8) - user and owner pass`

### 26000-26999

- [ ] `26500` - `iPhone passcode (UID key + System Keybag)`

### 27000-27999


### 28000-28999


### 29000-29999

- [ ] `29511` - `LUKS v1 SHA-1 + AES`
- [ ] `29512` - `LUKS v1 SHA-1 + Serpent`
- [ ] `29513` - `LUKS v1 SHA-1 + Twofish`
- [ ] `29521` - `LUKS v1 SHA-256 + AES`
- [ ] `29522` - `LUKS v1 SHA-256 + Serpent`
- [ ] `29523` - `LUKS v1 SHA-256 + Twofish`
- [ ] `29531` - `LUKS v1 SHA-512 + AES`
- [ ] `29532` - `LUKS v1 SHA-512 + Serpent`
- [ ] `29533` - `LUKS v1 SHA-512 + Twofish`
- [ ] `29541` - `LUKS v1 RIPEMD-160 + AES`
- [ ] `29542` - `LUKS v1 RIPEMD-160 + Serpent`
- [ ] `29543` - `LUKS v1 RIPEMD-160 + Twofish`
- [ ] `29800` - `Bisq .wallet (scrypt)`
- [ ] `29910` - `ENCsecurity Datavault (PBKDF2/no keychain)`
- [ ] `29920` - `ENCsecurity Datavault (PBKDF2/keychain)`
- [ ] `29930` - `ENCsecurity Datavault (MD5/no keychain)`
- [ ] `29940` - `ENCsecurity Datavault (MD5/keychain)`

### 30000-30999

- [ ] `30600` - `bcrypt(sha256($pass))`
- [ ] `30601` - `bcrypt(HMAC-SHA256($pass))`
- [ ] `30901` - `Bitcoin raw private key (P2PKH), compressed`
- [ ] `30902` - `Bitcoin raw private key (P2PKH), uncompressed`
- [ ] `30903` - `Bitcoin raw private key (P2WPKH, Bech32), compressed`
- [ ] `30904` - `Bitcoin raw private key (P2WPKH, Bech32), uncompressed`
- [ ] `30905` - `Bitcoin raw private key (P2SH(P2WPKH)), compressed`
- [ ] `30906` - `Bitcoin raw private key (P2SH(P2WPKH)), uncompressed`

### 31000-31999

- [ ] `31200` - `Veeam VBK`
- [ ] `31300` - `MS SNTP`
- [ ] `31400` - `SecureCRT MasterPassphrase v2`
- [ ] `31800` - `1Password, mobilekeychain (1Password 8)`
- [ ] `31900` - `MetaMask Mobile Wallet`

### 32000-32999

- [ ] `32300` - `Empire CMS (Admin password)`
- [ ] `32500` - `Dogechain.info Wallet`
- [ ] `32700` - `Kremlin Encrypt 3.0 w/NewDES`

### 33000-33999

- [ ] `33400` - `mega.nz password-protected link (PBKDF2-HMAC-SHA512)`
- [ ] `33500` - `RC4 40-bit DropN`
- [ ] `33501` - `RC4 72-bit DropN`
- [ ] `33502` - `RC4 104-bit DropN`
- [ ] `33700` - `Microsoft Online Account (PBKDF2-HMAC-SHA256 + AES256)`
- [ ] `33800` - `WBB4 (Woltlab Burning Board) [bcrypt(bcrypt($pass))]`

### 34000-34999

- [ ] `34000` - `Argon2`
- [ ] `34100` - `LUKS v2 argon2 + SHA-256 + AES`
- [ ] `34700` - `Blockchain, My Wallet, Legacy Wallets`

### 35000-35999

- [ ] `35500` - `Wordpress bcrypt(hmac-sha384($pass))`
- [ ] `35600` - `gost12512crypt [$gost12512hash$] (Unix)`

### 36000-36999

- [ ] `36000` - `BIP39 Passphrase Recovery (ASCII, P2SH/P2PKH/P2WPKH)`
- [ ] `36100` - `yescrypt`
- [ ] `36200` - `gost-yescrypt`
- [ ] `36400` - `KDE KWallet 4.13+ (PBKDF2-HMAC-SHA512, Blowfish)`
- [ ] `36410` - `KDE KWallet < 4.13 (SHA-1, Blowfish)`
- [ ] `36800` - `OpenSSH Private Keys (bcrypt-pbkdf)`
- [ ] `36900` - `iClass Standard (DES + hash0 + iClass Cipher, dual-MAC)`
- [ ] `36901` - `iClass Legacy (partial div_key + iClass Cipher, dual-MAC)`

### 37000-37999

- [ ] `37000` - `MIFARE Ultralight C 3DES Key Recovery`
- [ ] `37400` - `RACF DES Passphrase`
- [ ] `37500` - `RACF KDFAES Passphrase`
- [ ] `37700` - `Cardano Eternl Wallet (PBKDF2-HMAC-SHA512, ChaCha20)`

### 38000-38999

- [ ] `38000` - `Mikrotik RouterOS EC-SRP5 (Curve25519)`
- [ ] `38200` - `Cisco-IOS $14$ (MD5 (Type 5) + scrypt, Convoluted)`
- [ ] `38300` - `Apple DMG (encrcdsa v2, PBKDF2-HMAC-SHA1 + AES-192 key)`
- [ ] `38700` - `FreeBSD GELI`
- [ ] `38800` - `OpenBSD softraid FDE (PBKDF2-HMAC-SHA1)`
- [ ] `38810` - `OpenBSD softraid FDE (bcrypt-pbkdf)`
- [ ] `38900` - `Google fscrypt (Argon2id)`

### 40000-40099

- [ ] `40000` - `XCA database password`
- [ ] `40011` - `Password Safe v3`
- [ ] `40040` - `Blockchain, My Wallet, Second Password (SHA256)`
- [ ] `40055` - `PostgreSQL SCRAM-SHA-256`
- [ ] `40056` - `Flask Session Cookie ($salt.$salt.$pass)`

### 40100-40199


## John the Ripper formats

Initial source set: 264 entries (255 CPU labels plus
9 OpenCL-only labels; 100 `*-opencl` labels total,
with 91 grouped as aliases).

`*-opencl` variants are grouped with their CPU label and normally share the same
struct. Labels marked `OpenCL only` have no CPU equivalent in the source list.

### 0-9


### A-C

- [ ] `adxcrypt`
- [ ] `AFS`
- [ ] `agilekeychain` - OpenCL: `agilekeychain-opencl`
- [ ] `andOTP`
- [ ] `ansible` - OpenCL: `ansible-opencl`
- [ ] `Argon2` - OpenCL: `argon2-opencl`
- [ ] `armory`
- [ ] `as400-des`
- [ ] `as400-ssha1`
- [ ] `asa-md5`
- [ ] `AxCrypt` - OpenCL: `axcrypt-opencl`
- [ ] `axcrypt2-opencl` - OpenCL only
- [ ] `AzureAD`
- [ ] `BestCrypt`
- [ ] `BestCryptVE4`
- [ ] `bfegg`
- [ ] `Bitcoin` - OpenCL: `Bitcoin-opencl`
- [ ] `bitshares`
- [ ] `Bitwarden` - OpenCL: `bitwarden-opencl`
- [ ] `BKS`
- [ ] `Blackberry-ES10`
- [ ] `Blockchain` - OpenCL: `blockchain-opencl`
- [ ] `cardano`
- [ ] `chap`
- [ ] `Clipperz`
- [ ] `cloudkeychain` - OpenCL: `cloudkeychain-opencl`
- [ ] `cq`
- [ ] `CRC32`
- [ ] `cryptoSafe` - OpenCL: `cryptosafe-opencl`

### D-F

- [ ] `dahua`
- [ ] `dashlane` - OpenCL: `dashlane-opencl`
- [ ] `diskcryptor` - OpenCL: `diskcryptor-opencl`
- [ ] `diskcryptor-aes-opencl` - OpenCL only
- [ ] `Django`
- [ ] `django-scrypt`
- [ ] `dmd5`
- [ ] `dmg` - OpenCL: `dmg-opencl`
- [ ] `dominosec`
- [ ] `dominosec8`
- [ ] `eigrp`
- [ ] `electrum`
- [ ] `electrum-modern-opencl` - OpenCL only
- [ ] `EncFS` - OpenCL: `EncFS-opencl`
- [ ] `enpass` - OpenCL: `enpass-opencl`
- [ ] `ethereum` - OpenCL: `ethereum-opencl`
- [ ] `ethereum-presale-opencl` - OpenCL only
- [ ] `fde`
- [ ] `FormSpring`

### G-I

- [ ] `geli` - OpenCL: `geli-opencl`
- [ ] `gost94crypt` - OpenCL: `gost94crypt-opencl`
- [ ] `h3c`
- [ ] `hdaa`
- [ ] `HMAC-MD5`
- [ ] `HMAC-SHA1`
- [ ] `HMAC-SHA256`
- [ ] `HMAC-SHA512`
- [ ] `hsrp`
- [ ] `IKE`
- [ ] `ipb2`
- [ ] `Iterated-SHA1` - OpenCL: `Iterated-SHA1-opencl`
- [ ] `Iterated-SHA256` - OpenCL: `Iterated-SHA256-opencl`
- [ ] `iwork` - OpenCL: `iwork-opencl`

### J-L

- [ ] `keplr`
- [ ] `keychain` - OpenCL: `keychain-opencl`
- [ ] `keyring` - OpenCL: `keyring-opencl`
- [ ] `keystore` - OpenCL: `keystore-opencl`
- [ ] `known_hosts`
- [ ] `krb4`
- [ ] `krb5`
- [ ] `krb5-18`
- [ ] `krb5asrep`
- [ ] `krb5asrep-aes-opencl` - OpenCL only
- [ ] `krb5pa-md5` - OpenCL: `krb5pa-md5-opencl`
- [ ] `krb5pa-sha1` - OpenCL: `krb5pa-sha1-opencl`
- [ ] `krb5tgs` - OpenCL: `krb5tgs-opencl`
- [ ] `krb5tgs-sha1` - OpenCL: `krb5tgs-sha1-opencl`
- [ ] `kwallet`
- [ ] `LastPass`
- [ ] `leet`
- [ ] `lotus5` - OpenCL: `lotus5-opencl`
- [ ] `lotus85`
- [ ] `lp` - OpenCL: `lp-opencl`
- [ ] `lpcli` - OpenCL: `lpcli-opencl`
- [ ] `LUKS`

### M-O

- [ ] `MD2`
- [ ] `md5crypt-long`
- [ ] `md5ns`
- [ ] `mdc2`
- [ ] `Monero`
- [ ] `money`
- [ ] `MongoDB`
- [ ] `Mozilla`
- [ ] `mscash` - OpenCL: `mscash-opencl`
- [ ] `mschapv2-naive`
- [ ] `multibit`
- [ ] `mysql-sha1` - OpenCL: `mysql-sha1-opencl`
- [ ] `net-ah`
- [ ] `net-md5`
- [ ] `net-sha1`
- [ ] `nethalflm`
- [ ] `netlm`
- [ ] `netlmv2`
- [ ] `netntlm-naive`
- [ ] `nk`
- [ ] `notes` - OpenCL: `notes-opencl`
- [ ] `nsec3`
- [ ] `ntlmv2-opencl` - OpenCL only
- [ ] `o10glogon`
- [ ] `o3logon`
- [ ] `o5logon` - OpenCL: `o5logon-opencl`
- [ ] `ODF` - OpenCL: `ODF-opencl`
- [ ] `Office` - OpenCL: `office-opencl`
- [ ] `oldoffice` - OpenCL: `oldoffice-opencl`
- [ ] `OpenBSD-SoftRAID` - OpenCL: `OpenBSD-SoftRAID-opencl`
- [ ] `openssl-enc`
- [ ] `OpenVMS`
- [ ] `oracle`
- [ ] `oracle11`
- [ ] `Oracle12C`
- [ ] `osc`
- [ ] `ospf`
- [ ] `Oubliette-Blowfish`
- [ ] `Oubliette-IDEA`

### P-R

- [ ] `Padlock`
- [ ] `Palshop`
- [ ] `PBKDF2-HMAC-MD4` - OpenCL: `PBKDF2-HMAC-MD4-opencl`
- [ ] `PBKDF2-HMAC-MD5` - OpenCL: `PBKDF2-HMAC-MD5-opencl`
- [ ] `PBKDF2-HMAC-SHA1` - OpenCL: `PBKDF2-HMAC-SHA1-opencl`
- [ ] `PBKDF2-HMAC-SHA256` - OpenCL: `PBKDF2-HMAC-SHA256-opencl`
- [ ] `PBKDF2-HMAC-SHA512` - OpenCL: `PBKDF2-HMAC-SHA512-opencl`
- [ ] `PDF` - OpenCL: `pdf-opencl`
- [ ] `PEM` - OpenCL: `pem-opencl`
- [ ] `pfx` - OpenCL: `pfx-opencl`
- [ ] `pgpdisk` - OpenCL: `pgpdisk-opencl`
- [ ] `pgpsda` - OpenCL: `pgpsda-opencl`
- [ ] `pgpwde` - OpenCL: `pgpwde-opencl`
- [ ] `PHPS2`
- [ ] `PKZIP`
- [ ] `po`
- [ ] `PST`
- [ ] `PuTTY`
- [ ] `pwsafe` - OpenCL: `pwsafe-opencl`
- [ ] `RACF`
- [ ] `RACF-KDFAES`
- [ ] `radius`
- [ ] `RAdmin`
- [ ] `RAKP-MD5` - OpenCL: `RAKP-MD5-opencl`
- [ ] `RAKP-SHA1` - OpenCL: `RAKP-SHA1-opencl`
- [ ] `RAKP-SHA256` - OpenCL: `RAKP-SHA256-opencl`
- [ ] `rar` - OpenCL: `rar-opencl`
- [ ] `RAR5` - OpenCL: `RAR5-opencl`
- [ ] `Raw-MD5-flat`
- [ ] `raw-SHA512-free-opencl` - OpenCL only
- [ ] `Raw-SM3`
- [ ] `restic`
- [ ] `rsvp`
- [ ] `RVARY`

### S-U

- [ ] `sapb`
- [ ] `sapg`
- [ ] `saph`
- [ ] `sappse` - OpenCL: `sappse-opencl`
- [ ] `SCRAM-PBKDF2-SHA1`
- [ ] `SCRAM-PBKDF2-SHA1-MongoDB`
- [ ] `SCRAM-PBKDF2-SHA256`
- [ ] `scrypt`
- [ ] `securezip`
- [ ] `Siemens-S7`
- [ ] `Signal`
- [ ] `SIP`
- [ ] `Skein`
- [ ] `skey`
- [ ] `SL3` - OpenCL: `SL3-opencl`
- [ ] `sm3crypt` - OpenCL: `sm3crypt-opencl`
- [ ] `Snefru`
- [ ] `SNMP`
- [ ] `solarwinds` - OpenCL: `solarwinds-opencl`
- [ ] `SSH` - OpenCL: `ssh-opencl`
- [ ] `sspr` - OpenCL: `sspr-opencl`
- [ ] `streebog256crypt` - OpenCL: `streebog256crypt-opencl`
- [ ] `streebog512crypt` - OpenCL: `streebog512crypt-opencl`
- [ ] `STRIP` - OpenCL: `strip-opencl`
- [ ] `Sybase-PROP`
- [ ] `SybaseASE`
- [ ] `tcp-md5`
- [ ] `telegram` - OpenCL: `telegram-opencl`
- [ ] `tezos` - OpenCL: `tezos-opencl`
- [ ] `Tiger`
- [ ] `timeroast` - OpenCL: `timeroast-opencl`
- [ ] `tripcode`
- [ ] `TrueCrypt-opencl` - OpenCL only

### V-Z

- [ ] `vdi`
- [ ] `vmx` - OpenCL: `vmx-opencl`
- [ ] `VNC`
- [ ] `vtp`
- [ ] `wbb3`
- [ ] `Whirpool`
- [ ] `WoWSRP`
- [ ] `wpapsk` - OpenCL: `wpapsk-opencl`
- [ ] `wpapsk-pmk` - OpenCL: `wpapsk-pmk-opencl`
- [ ] `XSHA512-free-opencl` - OpenCL only
- [ ] `zed` - OpenCL: `zed-opencl`
- [ ] `ZIP` - OpenCL: `ZIP-opencl`
- [ ] `ZipMonster`

- [ ] `xsha`
- [ ] `xsha512`

- [ ] `EPiServer`

## hashcat bridged modes

These duplicate an existing hash type and usually need no separate struct.
Remove each entry together with the base mode it duplicates.

- [ ] `70000` - `Argon2id [Bridged: reference implementation + tunings]`
- [ ] `70100` - `scrypt [Bridged: Scrypt-Jane SMix]`
- [ ] `70200` - `scrypt [Bridged: Scrypt-Yescrypt]`
- [ ] `73000` - `Generic Hash [Bridged: Python]`
- [ ] `74000` - `Generic Hash [Bridged: Rust]`
- [ ] `75000` - `bcrypt $2*$, Blowfish (Unix) [Bridged: FPGA]`
- [ ] `79000` - `bcrypt $2*$, Blowfish (Unix) [Bridged: FPGA fleet sim]`

## Excluded

- hashcat `99999` - `Plaintext`: not a hash.
- John `plaintext`: not a hash.
- hashcat `2000` - `STDOUT`: not a hash.
- hashcat `4000` - `Hash Recipe`: not a hash.
- hashcat `2500`/`2501`: deprecated in hashcat 8.0.0 and replaced by `22000`/`22001`.
- John `dynamic` and `dynamic=`: dynamic compiler support is out of scope.
