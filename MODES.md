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

- [ ] `4000` - `Hash Recipe, see --hash-recipe`
- [ ] `4010` - `md5($salt.md5($salt.$pass))`
- [ ] `4110` - `md5($salt.md5($pass.$salt))`
- [ ] `4300` - `md5(strtoupper(md5($pass)))`
- [ ] `4400` - `md5(sha1($pass))`
- [ ] `4410` - `md5(sha1($pass).$salt)`
- [ ] `4420` - `md5(sha1($pass.$salt))`
- [ ] `4430` - `md5(sha1($salt.$pass))`
- [ ] `4500` - `sha1(sha1($pass))`
- [ ] `4510` - `sha1(sha1($pass).$salt)`
- [ ] `4520` - `sha1($salt.sha1($pass))`
- [ ] `4521` - `Redmine`
- [ ] `4522` - `PunBB`
- [ ] `4700` - `sha1(md5($pass))`
- [ ] `4710` - `sha1(md5($pass).$salt)`
- [ ] `4711` - `Huawei sha1(md5($pass).$salt)`
- [ ] `4800` - `iSCSI CHAP authentication, MD5(CHAP)`
- [ ] `4900` - `sha1($salt.$pass.$salt)`

### 5000-5999

- [ ] `5000` - `sha1(sha1($salt.$pass.$salt))`
- [ ] `5100` - `Half MD5`
- [ ] `5300` - `IKE-PSK MD5`
- [ ] `5400` - `IKE-PSK SHA1`
- [ ] `5500` - `NetNTLMv1 / NetNTLMv1+ESS`
- [ ] `5600` - `NetNTLMv2`
- [ ] `5700` - `Cisco-IOS type 4 (SHA256)`
- [ ] `5800` - `Samsung Android Password/PIN`

### 6000-6999

- [ ] `6000` - `RIPEMD-160`
- [ ] `6100` - `Whirlpool`
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
- [ ] `6300` - `AIX {smd5}`
- [ ] `6600` - `1Password, agilekeychain`
- [ ] `6800` - `LastPass + LastPass sniffed`
- [ ] `6900` - `GOST R 34.11-94`

### 7000-7999

- [ ] `7000` - `FortiGate (FortiOS)`
- [ ] `7300` - `IPMI2 RAKP HMAC-SHA1`
- [ ] `7350` - `IPMI2 RAKP HMAC-MD5`
- [ ] `7400` - `sha256crypt $5$, SHA256 (Unix)`
- [ ] `7401` - `MySQL $A$ (sha256crypt)`
- [ ] `7500` - `Kerberos 5, etype 23, AS-REQ Pre-Auth`
- [ ] `7700` - `SAP CODVN B (BCODE)`
- [ ] `7701` - `SAP CODVN B (BCODE) from RFC_READ_TABLE`
- [ ] `7800` - `SAP CODVN F/G (PASSCODE)`
- [ ] `7801` - `SAP CODVN F/G (PASSCODE) from RFC_READ_TABLE`

### 8000-8999

- [ ] `8000` - `Sybase ASE`
- [ ] `8100` - `Citrix NetScaler (SHA1)`
- [ ] `8200` - `1Password, cloudkeychain`
- [ ] `8300` - `DNSSEC (NSEC3)`
- [ ] `8400` - `WBB3 (Woltlab Burning Board)`
- [ ] `8500` - `RACF`
- [ ] `8501` - `AS/400 DES`
- [ ] `8600` - `Lotus Notes/Domino 5`
- [ ] `8700` - `Lotus Notes/Domino 6`
- [ ] `8800` - `Android FDE <= 4.3`
- [ ] `8900` - `scrypt`

### 9000-9999

- [ ] `9000` - `Password Safe v2`
- [ ] `9100` - `Lotus Notes/Domino 8`
- [ ] `9300` - `Cisco-IOS $9$ (scrypt)`
- [ ] `9400` - `MS Office 2007`
- [ ] `9500` - `MS Office 2010`
- [ ] `9600` - `MS Office 2013`
- [ ] `9700` - `MS Office <= 2003 $0/$1, MD5 + RC4`
- [ ] `9710` - `MS Office <= 2003 $0/$1, MD5 + RC4, collider #1`
- [ ] `9720` - `MS Office <= 2003 $0/$1, MD5 + RC4, collider #2`
- [ ] `9800` - `MS Office <= 2003 $3/$4, SHA1 + RC4`
- [ ] `9810` - `MS Office <= 2003 $3, SHA1 + RC4, collider #1`
- [ ] `9820` - `MS Office <= 2003 $3, SHA1 + RC4, collider #2`
- [ ] `9900` - `Radmin2`

### 10000-10999

- [ ] `10100` - `SipHash`
- [ ] `10200` - `CRAM-MD5`
- [ ] `10400` - `PDF 1.1 - 1.3 (Acrobat 2 - 4)`
- [ ] `10410` - `PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1`
- [ ] `10420` - `PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2`
- [ ] `10500` - `PDF 1.4 - 1.6 (Acrobat 5 - 8)`
- [ ] `10510` - `PDF 1.3 - 1.6 (Acrobat 4 - 8) w/ RC4-40`
- [ ] `10600` - `PDF 1.7 Level 3 (Acrobat 9)`
- [ ] `10700` - `PDF 1.7 Level 8 (Acrobat 10 - 11)`
- [ ] `10800` - `SHA2-384`
- [ ] `10810` - `sha384($pass.$salt)`
- [ ] `10820` - `sha384($salt.$pass)`
- [ ] `10830` - `sha384(utf16le($pass).$salt)`
- [ ] `10840` - `sha384($salt.utf16le($pass))`
- [ ] `10870` - `sha384(utf16le($pass))`

### 11000-11999

- [ ] `11100` - `PostgreSQL CRAM (MD5)`
- [ ] `11200` - `MySQL CRAM (SHA1)`
- [ ] `11300` - `Bitcoin/Litecoin wallet.dat`
- [ ] `11400` - `SIP digest authentication (MD5)`
- [ ] `11500` - `CRC32`
- [ ] `11600` - `7-Zip`
- [ ] `11700` - `GOST R 34.11-2012 (Streebog) 256-bit, big-endian`
- [ ] `11800` - `GOST R 34.11-2012 (Streebog) 512-bit, big-endian`

### 12000-12999

- [ ] `12200` - `eCryptfs`
- [ ] `12400` - `BSDi Crypt, Extended DES`
- [ ] `12500` - `RAR3-hp`
- [ ] `12600` - `ColdFusion 10+`
- [ ] `12700` - `Blockchain, My Wallet`
- [ ] `12900` - `Android FDE (Samsung DEK)`

### 13000-13999

- [ ] `13000` - `RAR5`
- [ ] `13100` - `Kerberos 5, etype 23, TGS-REP`
- [ ] `13200` - `AxCrypt 1`
- [ ] `13300` - `AxCrypt 1 in-memory SHA1`
- [ ] `13400` - `KeePass (KDBX v2/v3)`
- [ ] `13500` - `PeopleSoft PS_TOKEN`
- [ ] `13600` - `WinZip`
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
- [ ] `13800` - `Windows Phone 8+ PIN/password`
- [ ] `13900` - `OpenCart`

### 14000-14999

- [ ] `14000` - `DES (PT = $salt, key = $pass)`
- [ ] `14100` - `3DES (PT = $salt, key = $pass)`
- [ ] `14200` - `RACF KDFAES`
- [ ] `14400` - `sha1(CX)`
- [ ] `14500` - `Linux Kernel Crypto API (2.4)`
- [ ] `14600` - `LUKS v1 (legacy)`
- [ ] `14700` - `iTunes backup < 10.0`
- [ ] `14800` - `iTunes backup >= 10.0`
- [ ] `14900` - `Skip32 (PT = $salt, key = $pass)`

### 15000-15999

- [ ] `15000` - `FileZilla Server >= 0.9.55`
- [ ] `15200` - `Blockchain, My Wallet, V2`
- [ ] `15300` - `DPAPI masterkey file v1 (context 1 and 2)`
- [ ] `15310` - `DPAPI masterkey file v1 (context 3)`
- [ ] `15400` - `ChaCha20`
- [ ] `15500` - `JKS Java Key Store Private Keys (SHA1)`
- [ ] `15600` - `Ethereum Wallet, PBKDF2-HMAC-SHA256`
- [ ] `15700` - `Ethereum Wallet, SCRYPT`
- [ ] `15900` - `DPAPI masterkey file v2 (context 1 and 2)`
- [ ] `15910` - `DPAPI masterkey file v2 (context 3)`

### 16000-16999

- [ ] `16000` - `Tripcode`
- [ ] `16100` - `TACACS+`
- [ ] `16200` - `Apple Secure Notes`
- [ ] `16300` - `Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256`
- [ ] `16400` - `CRAM-MD5 Dovecot`
- [ ] `16500` - `JWT (JSON Web Token)`
- [ ] `16501` - `Perl Mojolicious session cookie (HMAC-SHA256, >= v9.19)`
- [ ] `16600` - `Electrum Wallet (Salt-Type 1-3)`
- [ ] `16700` - `FileVault 2`
- [ ] `16800` - `WPA-PMKID-PBKDF2`
- [ ] `16801` - `WPA-PMKID-PMK`
- [ ] `16900` - `Ansible Vault`

### 17000-17999

- [ ] `17010` - `GPG (AES-128/AES-256 (SHA-1($pass)))`
- [ ] `17020` - `GPG (AES-128/AES-256 (SHA-512($pass)))`
- [ ] `17030` - `GPG (AES-128/AES-256 (SHA-256($pass)))`
- [ ] `17040` - `GPG (CAST5 (SHA-1($pass)))`
- [ ] `17050` - `GPG (AES-OCB-128 (SHA-1($pass)))`
- [ ] `17200` - `PKZIP (Compressed)`
- [ ] `17210` - `PKZIP (Uncompressed)`
- [ ] `17220` - `PKZIP (Compressed Multi-File)`
- [ ] `17225` - `PKZIP (Mixed Multi-File)`
- [ ] `17230` - `PKZIP (Mixed Multi-File Checksum-Only)`
- [ ] `17300` - `SHA3-224`
- [ ] `17400` - `SHA3-256`
- [ ] `17500` - `SHA3-384`
- [ ] `17600` - `SHA3-512`
- [ ] `17700` - `Keccak-224`
- [ ] `17800` - `Keccak-256`
- [ ] `17900` - `Keccak-384`

### 18000-18999

- [ ] `18000` - `Keccak-512`
- [ ] `18100` - `TOTP (HMAC-SHA1)`
- [ ] `18200` - `Kerberos 5, etype 23, AS-REP`
- [ ] `18300` - `Apple File System (APFS)`
- [ ] `18400` - `Open Document Format (ODF) 1.2 (SHA-256, AES)`
- [ ] `18600` - `Open Document Format (ODF) 1.1 (SHA-1, Blowfish)`
- [ ] `18700` - `Java Object hashCode()`
- [ ] `18900` - `Android Backup`

### 19000-19999

- [ ] `19000` - `QNX /etc/shadow (MD5)`
- [ ] `19100` - `QNX /etc/shadow (SHA256)`
- [ ] `19200` - `QNX /etc/shadow (SHA512)`
- [ ] `19300` - `sha1($salt1.$pass.$salt2)`
- [ ] `19500` - `Ruby on Rails Restful-Authentication`
- [ ] `19600` - `Kerberos 5, etype 17, TGS-REP`
- [ ] `19700` - `Kerberos 5, etype 18, TGS-REP`
- [ ] `19800` - `Kerberos 5, etype 17, Pre-Auth`
- [ ] `19900` - `Kerberos 5, etype 18, Pre-Auth`

### 20000-20999

- [ ] `20011` - `DiskCryptor SHA512 + XTS 512 bit`
- [ ] `20012` - `DiskCryptor SHA512 + XTS 1024 bit`
- [ ] `20013` - `DiskCryptor SHA512 + XTS 1536 bit`
- [ ] `20500` - `PKZIP Master Key`
- [ ] `20510` - `PKZIP Master Key (6 byte optimization)`
- [ ] `20710` - `sha256(sha256($pass).$salt)`
- [ ] `20711` - `AuthMe sha256`
- [ ] `20712` - `RSA Security Analytics / NetWitness (sha256)`
- [ ] `20800` - `sha256(md5($pass))`
- [ ] `20900` - `md5(sha1($pass).md5($pass).sha1($pass))`

### 21000-21999

- [ ] `21000` - `BitShares v0.x - sha512(sha512_bin(pass))`
- [ ] `21100` - `sha1(md5($pass.$salt))`
- [ ] `21200` - `md5(sha1($salt).md5($pass))`
- [ ] `21310` - `md5($salt1.sha1($salt2.$pass))`
- [ ] `21400` - `sha256(sha256_bin($pass))`
- [ ] `21500` - `SolarWinds Orion`
- [ ] `21501` - `SolarWinds Orion v2`
- [ ] `21700` - `Electrum Wallet (Salt-Type 4)`
- [ ] `21800` - `Electrum Wallet (Salt-Type 5)`
- [ ] `21900` - `md5(md5(md5($pass.$salt1)).$salt2)`

### 22000-22999

- [ ] `22100` - `BitLocker`
- [ ] `22200` - `Citrix NetScaler (SHA512)`
- [ ] `22300` - `sha256($salt.$pass.$salt)`
- [ ] `22301` - `Telegram Mobile App Passcode (SHA256)`
- [ ] `22400` - `AES Crypt (SHA256)`
- [ ] `22500` - `MultiBit Classic .key (MD5)`
- [ ] `22600` - `Telegram Desktop < v2.1.14 (PBKDF2-HMAC-SHA1)`
- [ ] `22700` - `MultiBit HD (scrypt)`
- [ ] `22911` - `RSA/DSA/EC/OpenSSH Private Keys ($0$)`
- [ ] `22921` - `RSA/DSA/EC/OpenSSH Private Keys ($6$)`
- [ ] `22931` - `RSA/DSA/EC/OpenSSH Private Keys ($1, $3$)`
- [ ] `22941` - `RSA/DSA/EC/OpenSSH Private Keys ($4$)`
- [ ] `22951` - `RSA/DSA/EC/OpenSSH Private Keys ($5$)`

### 23000-23999

- [ ] `23001` - `SecureZIP AES-128`
- [ ] `23002` - `SecureZIP AES-192`
- [ ] `23003` - `SecureZIP AES-256`
- [ ] `23100` - `Apple Keychain`
- [ ] `23300` - `Apple iWork`
- [ ] `23400` - `Bitwarden`
- [ ] `23500` - `AxCrypt 2 AES-128`
- [ ] `23600` - `AxCrypt 2 AES-256`
- [ ] `23700` - `RAR3-p (Uncompressed)`
- [ ] `23800` - `RAR3-p (Compressed)` (no test module)
- [ ] `23900` - `BestCrypt v3 Volume Encryption`

### 24000-24999

- [ ] `24000` - `BestCrypt v4 Volume Encryption`
- [ ] `24100` - `MongoDB ServerKey SCRAM-SHA-1`
- [ ] `24300` - `sha1($salt.sha1($pass.$salt))`
- [ ] `24410` - `PKCS#8 Private Keys (PBKDF2-HMAC-SHA1 + 3DES/AES)`
- [ ] `24420` - `PKCS#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES)`
- [ ] `24430` - `PKCS#12 (.pfx, .p12) (SHA1 + HMAC-SHA1)`
- [ ] `24440` - `PKCS#12 (.pfx, .p12) (SHA256 + HMAC-SHA256)`
- [ ] `24500` - `Telegram Desktop >= v2.1.14 (PBKDF2-HMAC-SHA512)`
- [ ] `24600` - `SQLCipher`
- [ ] `24700` - `Stuffit5`
- [ ] `24800` - `Umbraco HMAC-SHA1`
- [ ] `24900` - `Dahua Authentication MD5`
- [ ] `24901` - `Besder Authentication MD5`

### 25000-25999

- [ ] `25000` - `SNMPv3 HMAC-MD5-96/HMAC-SHA1-96`
- [ ] `25100` - `SNMPv3 HMAC-MD5-96`
- [ ] `25200` - `SNMPv3 HMAC-SHA1-96`
- [ ] `25300` - `MS Office 2016 - SheetProtection`
- [ ] `25400` - `PDF 1.4 - 1.6 (Acrobat 5 - 8) - user and owner pass`
- [ ] `25500` - `Stargazer Stellar Wallet XLM`
- [ ] `25600` - `bcrypt(md5($pass))`
- [ ] `25700` - `MurmurHash`
- [ ] `25800` - `bcrypt(sha1($pass))`
- [ ] `25900` - `KNX IP Secure - Device Authentication Code`

### 26000-26999

- [ ] `26000` - `Mozilla key3.db`
- [ ] `26100` - `Mozilla key4.db`
- [ ] `26150` - `Mozilla key4.db SHA384`
- [ ] `26200` - `OpenEdge Progress Encode`
- [ ] `26401` - `AES-128-ECB NOKDF (PT = $salt, key = $pass)`
- [ ] `26402` - `AES-192-ECB NOKDF (PT = $salt, key = $pass)`
- [ ] `26403` - `AES-256-ECB NOKDF (PT = $salt, key = $pass)`
- [ ] `26500` - `iPhone passcode (UID key + System Keybag)`
- [ ] `26600` - `MetaMask Wallet (needs all data, checks AES-GCM tag)`
- [ ] `26610` - `MetaMask Wallet (short hash, plaintext check)`
- [ ] `26700` - `SNMPv3 HMAC-SHA224-128`
- [ ] `26800` - `SNMPv3 HMAC-SHA256-192`
- [ ] `26900` - `SNMPv3 HMAC-SHA384-256`

### 27000-27999

- [ ] `27000` - `NetNTLMv1 / NetNTLMv1+ESS (NT)`
- [ ] `27100` - `NetNTLMv2 (NT)`
- [ ] `27200` - `Ruby on Rails Restful Auth (one round, no sitekey)`
- [ ] `27300` - `SNMPv3 HMAC-SHA512-384`
- [ ] `27400` - `VMware VMX (PBKDF2-HMAC-SHA1 + AES-256-CBC)`
- [ ] `27500` - `VirtualBox (PBKDF2-HMAC-SHA256 & AES-128-XTS)`
- [ ] `27600` - `VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS)`
- [ ] `27700` - `MultiBit Classic .wallet (scrypt)`
- [ ] `27800` - `MurmurHash3`
- [ ] `27900` - `CRC32C`

### 28000-28999

- [ ] `28000` - `CRC64Jones`
- [ ] `28100` - `Windows Hello PIN/Password`
- [ ] `28200` - `Exodus Desktop Wallet (scrypt)`
- [ ] `28300` - `Teamspeak 3 (channel hash)`
- [ ] `28400` - `bcrypt(sha512($pass))`
- [ ] `28501` - `Bitcoin WIF private key (P2PKH), compressed`
- [ ] `28502` - `Bitcoin WIF private key (P2PKH), uncompressed`
- [ ] `28503` - `Bitcoin WIF private key (P2WPKH, Bech32), compressed`
- [ ] `28504` - `Bitcoin WIF private key (P2WPKH, Bech32), uncompressed`
- [ ] `28505` - `Bitcoin WIF private key (P2SH(P2WPKH)), compressed`
- [ ] `28506` - `Bitcoin WIF private key (P2SH(P2WPKH)), uncompressed`
- [ ] `28700` - `Amazon AWS Signature Version 4`
- [ ] `28800` - `Kerberos 5, etype 17, DB`
- [ ] `28900` - `Kerberos 5, etype 18, DB`

### 29000-29999

- [ ] `29000` - `sha1($salt.sha1(utf16le($username).':'.utf16le($pass)))`
- [ ] `29200` - `Radmin3`
- [ ] `29311` - `TrueCrypt RIPEMD160 + XTS 512 bit`
- [ ] `29312` - `TrueCrypt RIPEMD160 + XTS 1024 bit`
- [ ] `29313` - `TrueCrypt RIPEMD160 + XTS 1536 bit`
- [ ] `29321` - `TrueCrypt SHA512 + XTS 512 bit`
- [ ] `29322` - `TrueCrypt SHA512 + XTS 1024 bit`
- [ ] `29323` - `TrueCrypt SHA512 + XTS 1536 bit`
- [ ] `29331` - `TrueCrypt Whirlpool + XTS 512 bit`
- [ ] `29332` - `TrueCrypt Whirlpool + XTS 1024 bit`
- [ ] `29333` - `TrueCrypt Whirlpool + XTS 1536 bit`
- [ ] `29341` - `TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode`
- [ ] `29342` - `TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode`
- [ ] `29343` - `TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode`
- [ ] `29411` - `VeraCrypt RIPEMD160 + XTS 512 bit`
- [ ] `29412` - `VeraCrypt RIPEMD160 + XTS 1024 bit`
- [ ] `29413` - `VeraCrypt RIPEMD160 + XTS 1536 bit`
- [ ] `29421` - `VeraCrypt SHA512 + XTS 512 bit`
- [ ] `29422` - `VeraCrypt SHA512 + XTS 1024 bit`
- [ ] `29423` - `VeraCrypt SHA512 + XTS 1536 bit`
- [ ] `29431` - `VeraCrypt Whirlpool + XTS 512 bit`
- [ ] `29432` - `VeraCrypt Whirlpool + XTS 1024 bit`
- [ ] `29433` - `VeraCrypt Whirlpool + XTS 1536 bit`
- [ ] `29441` - `VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode`
- [ ] `29442` - `VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode`
- [ ] `29443` - `VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode`
- [ ] `29451` - `VeraCrypt SHA256 + XTS 512 bit`
- [ ] `29452` - `VeraCrypt SHA256 + XTS 1024 bit`
- [ ] `29453` - `VeraCrypt SHA256 + XTS 1536 bit`
- [ ] `29461` - `VeraCrypt SHA256 + XTS 512 bit + boot-mode`
- [ ] `29462` - `VeraCrypt SHA256 + XTS 1024 bit + boot-mode`
- [ ] `29463` - `VeraCrypt SHA256 + XTS 1536 bit + boot-mode`
- [ ] `29471` - `VeraCrypt Streebog-512 + XTS 512 bit`
- [ ] `29472` - `VeraCrypt Streebog-512 + XTS 1024 bit`
- [ ] `29473` - `VeraCrypt Streebog-512 + XTS 1536 bit`
- [ ] `29481` - `VeraCrypt Streebog-512 + XTS 512 bit + boot-mode`
- [ ] `29482` - `VeraCrypt Streebog-512 + XTS 1024 bit + boot-mode`
- [ ] `29483` - `VeraCrypt Streebog-512 + XTS 1536 bit + boot-mode`
- [ ] `29491` - `VeraCrypt BLAKE2s-256 + XTS 512 bit`
- [ ] `29492` - `VeraCrypt BLAKE2s-256 + XTS 1024 bit`
- [ ] `29493` - `VeraCrypt BLAKE2s-256 + XTS 1536 bit`
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
- [ ] `29600` - `Terra Station Wallet (AES256-CBC(PBKDF2($pass)))`
- [ ] `29700` - `KeePass (KDBX v2/v3) - keyfile only`
- [ ] `29800` - `Bisq .wallet (scrypt)`
- [ ] `29910` - `ENCsecurity Datavault (PBKDF2/no keychain)`
- [ ] `29920` - `ENCsecurity Datavault (PBKDF2/keychain)`
- [ ] `29930` - `ENCsecurity Datavault (MD5/no keychain)`
- [ ] `29940` - `ENCsecurity Datavault (MD5/keychain)`

### 30000-30999

- [ ] `30000` - `Python Werkzeug MD5 (HMAC-MD5 (key = $salt))`
- [ ] `30120` - `Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt))`
- [ ] `30420` - `DANE RFC7929/RFC8162 SHA2-256`
- [ ] `30500` - `md5(md5($salt).md5(md5($pass)))`
- [ ] `30600` - `bcrypt(sha256($pass))`
- [ ] `30601` - `bcrypt(HMAC-SHA256($pass))`
- [ ] `30700` - `Anope IRC Services (enc_sha256)`
- [ ] `30901` - `Bitcoin raw private key (P2PKH), compressed`
- [ ] `30902` - `Bitcoin raw private key (P2PKH), uncompressed`
- [ ] `30903` - `Bitcoin raw private key (P2WPKH, Bech32), compressed`
- [ ] `30904` - `Bitcoin raw private key (P2WPKH, Bech32), uncompressed`
- [ ] `30905` - `Bitcoin raw private key (P2SH(P2WPKH)), compressed`
- [ ] `30906` - `Bitcoin raw private key (P2SH(P2WPKH)), uncompressed`

### 31000-31999

- [ ] `31000` - `BLAKE2s-256`
- [ ] `31100` - `ShangMi 3 (SM3)`
- [ ] `31200` - `Veeam VBK`
- [ ] `31300` - `MS SNTP`
- [ ] `31400` - `SecureCRT MasterPassphrase v2`
- [ ] `31500` - `Domain Cached Credentials (DCC), MS Cache (NT)`
- [ ] `31600` - `Domain Cached Credentials 2 (DCC2), MS Cache 2, (NT)`
- [ ] `31700` - `md5(md5(md5($pass).$salt1).$salt2)`
- [ ] `31800` - `1Password, mobilekeychain (1Password 8)`
- [ ] `31900` - `MetaMask Mobile Wallet`

### 32000-32999

- [ ] `32100` - `Kerberos 5, etype 17, AS-REP`
- [ ] `32200` - `Kerberos 5, etype 18, AS-REP`
- [ ] `32300` - `Empire CMS (Admin password)`
- [ ] `32500` - `Dogechain.info Wallet`
- [ ] `32700` - `Kremlin Encrypt 3.0 w/NewDES`
- [ ] `32800` - `md5(sha1(md5($pass)))`

### 33000-33999

- [ ] `33000` - `md5($salt1.$pass.$salt2)`
- [ ] `33400` - `mega.nz password-protected link (PBKDF2-HMAC-SHA512)`
- [ ] `33500` - `RC4 40-bit DropN`
- [ ] `33501` - `RC4 72-bit DropN`
- [ ] `33502` - `RC4 104-bit DropN`
- [ ] `33600` - `RIPEMD-320`
- [ ] `33700` - `Microsoft Online Account (PBKDF2-HMAC-SHA256 + AES256)`
- [ ] `33800` - `WBB4 (Woltlab Burning Board) [bcrypt(bcrypt($pass))]`

### 34000-34999

- [ ] `34000` - `Argon2`
- [ ] `34100` - `LUKS v2 argon2 + SHA-256 + AES`
- [ ] `34200` - `MurmurHash64A`
- [ ] `34201` - `MurmurHash64A (zero seed)`
- [ ] `34211` - `MurmurHash64A truncated (zero seed)`
- [ ] `34300` - `KeePass Argon2 (KDBX v4)`
- [ ] `34301` - `KeePass AESKDF (KDBX v4)`
- [ ] `34600` - `MD6 (256)`
- [ ] `34700` - `Blockchain, My Wallet, Legacy Wallets`
- [ ] `34800` - `BLAKE2b-256`
- [ ] `34810` - `BLAKE2b-256($pass.$salt)`
- [ ] `34820` - `BLAKE2b-256($salt.$pass)`

### 35000-35999

- [ ] `35100` - `sm3crypt $sm3$, SM3 (Unix)`
- [ ] `35200` - `AS/400 SSHA1`
- [ ] `35300` - `Kerberos 5, etype 23, TGS-REP (NT)`
- [ ] `35400` - `Kerberos 5, etype 23, AS-REP (NT)`
- [ ] `35500` - `Wordpress bcrypt(hmac-sha384($pass))`
- [ ] `35600` - `gost12512crypt [$gost12512hash$] (Unix)`
- [ ] `35800` - `Symfony Legacy SHA256`

### 36000-36999

- [ ] `36000` - `BIP39 Passphrase Recovery (ASCII, P2SH/P2PKH/P2WPKH)`
- [ ] `36100` - `yescrypt`
- [ ] `36200` - `gost-yescrypt`
- [ ] `36300` - `scryptcrypt, scrypt (Unix)`
- [ ] `36400` - `KDE KWallet 4.13+ (PBKDF2-HMAC-SHA512, Blowfish)`
- [ ] `36410` - `KDE KWallet < 4.13 (SHA-1, Blowfish)`
- [ ] `36600` - `PBKDF2-HMAC-SHA512(utf16le($pass))`
- [ ] `36601` - `MSSQL (2025)`
- [ ] `36800` - `OpenSSH Private Keys (bcrypt-pbkdf)`
- [ ] `36900` - `iClass Standard (DES + hash0 + iClass Cipher, dual-MAC)`
- [ ] `36901` - `iClass Legacy (partial div_key + iClass Cipher, dual-MAC)`

### 37000-37999

- [ ] `37000` - `MIFARE Ultralight C 3DES Key Recovery`
- [ ] `37400` - `RACF DES Passphrase`
- [ ] `37500` - `RACF KDFAES Passphrase`
- [ ] `37600` - `SASL DIGEST-MD5`
- [ ] `37601` - `POP3 APOP`
- [ ] `37700` - `Cardano Eternl Wallet (PBKDF2-HMAC-SHA512, ChaCha20)`

### 38000-38999

- [ ] `38000` - `Mikrotik RouterOS EC-SRP5 (Curve25519)`
- [ ] `38200` - `Cisco-IOS $14$ (MD5 (Type 5) + scrypt, Convoluted)`
- [ ] `38300` - `Apple DMG (encrcdsa v2, PBKDF2-HMAC-SHA1 + AES-192 key)`
- [ ] `38400` - `Kerberos 5, etype 1/2/3, DB`
- [ ] `38500` - `Kerberos 5, etype 3, TGS-REP`
- [ ] `38600` - `Kerberos 5, etype 3, AS-REP`
- [ ] `38700` - `FreeBSD GELI`
- [ ] `38800` - `OpenBSD softraid FDE (PBKDF2-HMAC-SHA1)`
- [ ] `38810` - `OpenBSD softraid FDE (bcrypt-pbkdf)`
- [ ] `38900` - `Google fscrypt (Argon2id)`

### 40000-40099

- [ ] `40000` - `XCA database password`
- [ ] `40001` - `OSPFv2/RIPv2 MD5 authentication`
- [ ] `40002` - `Huawei / H3C / HPE Comware $h$6$`
- [ ] `40004` - `UUID v3 (RFC 4122 name-based, MD5)`
- [ ] `40005` - `UUID v5 (RFC 4122 name-based, SHA-1)`
- [ ] `40006` - `MySQL caching_sha2_password challenge-response (fast auth)`
- [ ] `40007` - `MODX Evolution (uncrypt)`
- [ ] `40009` - `sha224($pass.$salt)`
- [ ] `40010` - `sha224($salt.$pass)`
- [ ] `40011` - `Password Safe v3`
- [ ] `40012` - `Cisco-ISE Hashed Password (SHA256)`
- [ ] `40013` - `HMAC-RIPEMD160 (key = $pass)`
- [ ] `40014` - `HMAC-RIPEMD160 (key = $salt)`
- [ ] `40015` - `AIX {ssha256}`
- [ ] `40016` - `AIX {ssha512}`
- [ ] `40017` - `AIX {ssha1}`
- [ ] `40018` - `macOS v10.8+ (PBKDF2-SHA512)`
- [ ] `40019` - `GRUB 2`
- [ ] `40020` - `Drupal7`
- [ ] `40021` - `Cisco-IOS $8$ (PBKDF2-SHA256)`
- [ ] `40022` - `Django (PBKDF2-SHA256)`
- [ ] `40023` - `SAP CODVN H (PWDSALTEDHASH) iSSHA-1`
- [ ] `40024` - `PBKDF2-HMAC-SHA256`
- [ ] `40025` - `RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)`
- [ ] `40026` - `PrestaShop`
- [ ] `40027` - `HMAC-Streebog-256 (key = $pass), big-endian`
- [ ] `40028` - `HMAC-Streebog-256 (key = $salt), big-endian`
- [ ] `40029` - `HMAC-Streebog-512 (key = $pass), big-endian`
- [ ] `40030` - `HMAC-Streebog-512 (key = $salt), big-endian`
- [ ] `40031` - `PBKDF2-HMAC-MD5`
- [ ] `40032` - `PBKDF2-HMAC-SHA1`
- [ ] `40033` - `Atlassian (PBKDF2-HMAC-SHA1)`
- [ ] `40034` - `PBKDF2-HMAC-SHA512`
- [ ] `40035` - `Apache Shiro 1 SHA-512`
- [ ] `40036` - `Oracle T: Type (Oracle 12+)`
- [ ] `40037` - `MS-AzureSync PBKDF2-HMAC-SHA256`
- [ ] `40038` - `Juniper/NetBSD sha1crypt`
- [ ] `40039` - `sha1(md5(md5($pass)))`
- [ ] `40040` - `Blockchain, My Wallet, Second Password (SHA256)`
- [ ] `40041` - `QNX 7 /etc/shadow (SHA512)`
- [ ] `40042` - `Python passlib pbkdf2-sha512`
- [ ] `40043` - `Python passlib pbkdf2-sha256`
- [ ] `40044` - `Python passlib pbkdf2-sha1`
- [ ] `40045` - `Oracle Transportation Management (SHA256)`
- [ ] `40046` - `sha256($salt.sha256($pass))`
- [ ] `40047` - `sha256(sha256($pass.$salt))`
- [ ] `40048` - `md5($salt.sha1($salt.$pass))`
- [ ] `40049` - `sha256($salt.sha256_bin($pass))`
- [ ] `40050` - `Web2py pbkdf2-sha512`
- [ ] `40051` - `Simpla CMS - md5($salt.$pass.md5($pass))`
- [ ] `40052` - `XMPP SCRAM PBKDF2-SHA1`
- [ ] `40053` - `MongoDB ServerKey SCRAM-SHA-256`
- [ ] `40054` - `FortiGate256 (FortiOS256)`
- [ ] `40055` - `PostgreSQL SCRAM-SHA-256`
- [ ] `40056` - `Flask Session Cookie ($salt.$salt.$pass)`
- [ ] `40057` - `NetIQ SSPR (MD5)`
- [ ] `40058` - `NetIQ SSPR (SHA1)`
- [ ] `40059` - `NetIQ SSPR (SHA-1 with Salt)`
- [ ] `40060` - `NetIQ SSPR (SHA-256 with Salt)`
- [ ] `40061` - `Adobe AEM (SSPR, SHA-256 with Salt)`
- [ ] `40062` - `NetIQ SSPR (SHA-512 with Salt)`
- [ ] `40063` - `Adobe AEM (SSPR, SHA-512 with Salt)`
- [ ] `40064` - `NetIQ SSPR (PBKDF2WithHmacSHA1)`
- [ ] `40065` - `NetIQ SSPR (PBKDF2WithHmacSHA256)`
- [ ] `40066` - `NetIQ SSPR (PBKDF2WithHmacSHA512)`
- [ ] `40067` - `sha512(sha512($pass).$salt)`
- [ ] `40068` - `sha512(sha512_bin($pass).$salt)`
- [ ] `40069` - `CubeCart (whirlpool($salt.$pass.$salt))`
- [ ] `40070` - `PBKDF1-SHA1`
- [ ] `40071` - `md5($salt.md5($pass).$salt)`
- [ ] `40072` - `HMAC-BLAKE2S (key = $pass)`
- [ ] `40073` - `HMAC-RIPEMD320 (key = $pass)`
- [ ] `40074` - `HMAC-RIPEMD320 (key = $salt)`
- [ ] `40075` - `Citrix NetScaler (PBKDF2-HMAC-SHA256)`
- [ ] `40076` - `sha224(sha224($pass))`
- [ ] `40077` - `sha224(sha1($pass))`
- [ ] `40078` - `SAP CODVN H (PWDSALTEDHASH) isSHA512`
- [ ] `40079` - `phpass(md5($pass))`
- [ ] `40080` - `NTLM(NTLM_bin($pass))`
- [ ] `40081` - `SAP CODVN H (PWDSALTEDHASH) iSSHA-256`
- [ ] `40082` - `SAP CODVN H (PWDSALTEDHASH) iSSHA-384`
- [ ] `40083` - `Fernet (key = SHA256($pass))`
- [ ] `40084` - `MD2`
- [ ] `40085` - `SHA-0`
- [ ] `40086` - `RIPEMD-128`
- [ ] `40087` - `RIPEMD-256`
- [ ] `40088` - `GOST R 34.11-94 (CryptoPro)`
- [ ] `40089` - `Tiger`
- [ ] `40090` - `Tiger-128`
- [ ] `40091` - `Tiger-160`
- [ ] `40092` - `Tiger2`
- [ ] `40093` - `TTH (Tiger Tree Hash, single leaf)`
- [ ] `40094` - `Snefru-128`
- [ ] `40095` - `Snefru-256`
- [ ] `40096` - `Skein-512-224`
- [ ] `40097` - `Skein-512-256`
- [ ] `40098` - `Skein-512-384`
- [ ] `40099` - `Skein-512-512`

### 40100-40199

- [ ] `40100` - `PANAMA`
- [ ] `40101` - `MDC-2`
- [ ] `40102` - `HAVAL-128 (3 passes)`
- [ ] `40103` - `HAVAL-128 (4 passes)`
- [ ] `40104` - `HAVAL-128 (5 passes)`
- [ ] `40105` - `HAVAL-160 (3 passes)`
- [ ] `40106` - `HAVAL-160 (4 passes)`
- [ ] `40107` - `HAVAL-160 (5 passes)`
- [ ] `40108` - `HAVAL-192 (3 passes)`
- [ ] `40109` - `HAVAL-192 (4 passes)`
- [ ] `40110` - `HAVAL-192 (5 passes)`
- [ ] `40111` - `HAVAL-224 (3 passes)`
- [ ] `40112` - `HAVAL-224 (4 passes)`
- [ ] `40113` - `HAVAL-224 (5 passes)`
- [ ] `40114` - `HAVAL-256 (3 passes)`
- [ ] `40115` - `HAVAL-256 (4 passes)`
- [ ] `40116` - `HAVAL-256 (5 passes)`
- [ ] `40117` - `BLAKE-224`
- [ ] `40118` - `BLAKE-256`
- [ ] `40119` - `BLAKE-384`
- [ ] `40120` - `BLAKE-512`
- [ ] `40121` - `BMW-224`
- [ ] `40122` - `BMW-256`
- [ ] `40123` - `BMW-384`
- [ ] `40124` - `BMW-512`
- [ ] `40125` - `CubeHash-224`
- [ ] `40126` - `CubeHash-256`
- [ ] `40127` - `CubeHash-384`
- [ ] `40128` - `CubeHash-512`
- [ ] `40129` - `ECHO-224`
- [ ] `40130` - `ECHO-256`
- [ ] `40131` - `ECHO-384`
- [ ] `40132` - `ECHO-512`
- [ ] `40133` - `Fugue-224`
- [ ] `40134` - `Fugue-256`
- [ ] `40135` - `Fugue-384`
- [ ] `40136` - `Fugue-512`
- [ ] `40137` - `Groestl-224`
- [ ] `40138` - `Groestl-256`
- [ ] `40139` - `Groestl-384`
- [ ] `40140` - `Groestl-512`
- [ ] `40141` - `Hamsi-224`
- [ ] `40142` - `Hamsi-256`
- [ ] `40143` - `Hamsi-384`
- [ ] `40144` - `Hamsi-512`
- [ ] `40145` - `JH-224`
- [ ] `40146` - `JH-256`
- [ ] `40147` - `JH-384`
- [ ] `40148` - `JH-512`
- [ ] `40149` - `Luffa-224`
- [ ] `40150` - `Luffa-256`
- [ ] `40151` - `Luffa-384`
- [ ] `40152` - `Luffa-512`
- [ ] `40153` - `Shabal-224`
- [ ] `40154` - `Shabal-256`
- [ ] `40155` - `Shabal-384`
- [ ] `40156` - `Shabal-512`
- [ ] `40157` - `SHAvite-3-224`
- [ ] `40158` - `SHAvite-3-256`
- [ ] `40159` - `SHAvite-3-384`
- [ ] `40160` - `SHAvite-3-512`
- [ ] `40161` - `SIMD-224`
- [ ] `40162` - `SIMD-256`
- [ ] `40163` - `SIMD-384`
- [ ] `40164` - `SIMD-512`
- [ ] `40165` - `HAS-160`
- [ ] `40166` - `EDON-R-256`
- [ ] `40167` - `EDON-R-512`
- [ ] `40168` - `MD6-128`
- [ ] `40170` - `MD6-512`
- [ ] `40171` - `RadioGatun[32] (first 128 bits)`
- [ ] `40172` - `RadioGatun[64]`
- [ ] `40173` - `RIPEMD (original)`
- [ ] `40174` - `Whirlpool-0`
- [ ] `40175` - `Whirlpool-T`

## John the Ripper formats

Initial source set: 264 entries (255 CPU labels plus
9 OpenCL-only labels; 100 `*-opencl` labels total,
with 91 grouped as aliases).

`*-opencl` variants are grouped with their CPU label and normally share the same
struct. Labels marked `OpenCL only` have no CPU equivalent in the source list.

### 0-9

- [ ] `7z` - OpenCL: `7z-opencl`

### A-C

- [ ] `adxcrypt`
- [ ] `AFS`
- [ ] `agilekeychain` - OpenCL: `agilekeychain-opencl`
- [ ] `andOTP`
- [ ] `AndroidBackup` - OpenCL: `AndroidBackup-opencl`
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
- [ ] `BitLocker` - OpenCL: `BitLocker-opencl`
- [ ] `bitshares`
- [ ] `Bitwarden` - OpenCL: `bitwarden-opencl`
- [ ] `BKS`
- [ ] `Blackberry-ES10`
- [ ] `Blockchain` - OpenCL: `blockchain-opencl`
- [ ] `bsdicrypt`
- [ ] `cardano`
- [ ] `chap`
- [ ] `Citrix_NS10`
- [ ] `Clipperz`
- [ ] `cloudkeychain` - OpenCL: `cloudkeychain-opencl`
- [ ] `cq`
- [ ] `CRC32`
- [ ] `crypt`
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
- [ ] `DPAPImk`
- [ ] `Drupal7`
- [ ] `eCryptfs`
- [ ] `eigrp`
- [ ] `electrum`
- [ ] `electrum-modern-opencl` - OpenCL only
- [ ] `EncFS` - OpenCL: `EncFS-opencl`
- [ ] `enpass` - OpenCL: `enpass-opencl`
- [ ] `EPiServer`
- [ ] `ethereum` - OpenCL: `ethereum-opencl`
- [ ] `ethereum-presale-opencl` - OpenCL only
- [ ] `fde`
- [ ] `FormSpring`
- [ ] `Fortigate`
- [ ] `Fortigate256`
- [ ] `FVDE` - OpenCL: `FVDE-opencl`

### G-I

- [ ] `geli` - OpenCL: `geli-opencl`
- [ ] `gost`
- [ ] `gost94crypt` - OpenCL: `gost94crypt-opencl`
- [ ] `gpg` - OpenCL: `gpg-opencl`
- [ ] `h3c`
- [ ] `has-160`
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
- [ ] `itunes-backup`
- [ ] `iwork` - OpenCL: `iwork-opencl`

### J-L

- [ ] `KeePass` - OpenCL: `KeePass-opencl`
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
- [ ] `mssql12`
- [ ] `multibit`
- [ ] `mysql-sha1` - OpenCL: `mysql-sha1-opencl`
- [ ] `mysqlna`
- [ ] `net-ah`
- [ ] `net-md5`
- [ ] `net-sha1`
- [ ] `nethalflm`
- [ ] `netlm`
- [ ] `netlmv2`
- [ ] `netntlm-naive`
- [ ] `netntlmv2`
- [ ] `nk`
- [ ] `notes` - OpenCL: `notes-opencl`
- [ ] `nsec3`
- [ ] `NT-long`
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
- [ ] `Panama`
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
- [ ] `PHPS`
- [ ] `PHPS2`
- [ ] `PKZIP`
- [ ] `po`
- [ ] `postgres`
- [ ] `PST`
- [ ] `PuTTY`
- [ ] `pwsafe` - OpenCL: `pwsafe-opencl`
- [ ] `qnx`
- [ ] `RACF`
- [ ] `RACF-KDFAES`
- [ ] `radius`
- [ ] `RAdmin`
- [ ] `RAKP-MD5` - OpenCL: `RAKP-MD5-opencl`
- [ ] `RAKP-SHA1` - OpenCL: `RAKP-SHA1-opencl`
- [ ] `RAKP-SHA256` - OpenCL: `RAKP-SHA256-opencl`
- [ ] `rar` - OpenCL: `rar-opencl`
- [ ] `RAR5` - OpenCL: `RAR5-opencl`
- [ ] `Raw-Keccak`
- [ ] `Raw-Keccak-256`
- [ ] `Raw-MD5-flat`
- [ ] `Raw-MD5u`
- [ ] `Raw-SHA1-Linkedin`
- [ ] `Raw-SHA3`
- [ ] `Raw-SHA384`
- [ ] `raw-SHA512-free-opencl` - OpenCL only
- [ ] `Raw-SM3`
- [ ] `restic`
- [ ] `rsvp`
- [ ] `RVARY`

### S-U

- [ ] `Salted-SHA1` - OpenCL: `salted-SHA1-opencl`
- [ ] `sapb`
- [ ] `sapg`
- [ ] `saph`
- [ ] `sappse` - OpenCL: `sappse-opencl`
- [ ] `SCRAM-PBKDF2-SHA1`
- [ ] `SCRAM-PBKDF2-SHA1-MongoDB`
- [ ] `SCRAM-PBKDF2-SHA256`
- [ ] `scrypt`
- [ ] `securezip`
- [ ] `sha1crypt` - OpenCL: `sha1crypt-opencl`
- [ ] `sha256crypt` - OpenCL: `sha256crypt-opencl`
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
- [ ] `tacacs-plus`
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
- [ ] `xsha`
- [ ] `xsha512`
- [ ] `XSHA512-free-opencl` - OpenCL only
- [ ] `zed` - OpenCL: `zed-opencl`
- [ ] `ZIP` - OpenCL: `ZIP-opencl`
- [ ] `ZipMonster`

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
- hashcat `2500`/`2501`: deprecated in hashcat 8.0.0 and replaced by `22000`/`22001`.
- John `dynamic` and `dynamic=`: dynamic compiler support is out of scope.
