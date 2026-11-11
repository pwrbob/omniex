# Extraction checklist

Working list of artifact formats to support. Each line is one logical artifact
format and names the target hash type or mode family where one already exists.
Check an entry when its extractor, probe, fixtures, and negative tests land. The
README badge counts checked lines in this file.

## OpenPGP and PGP

- [x] OpenPGP secret keys, armored and binary, including subkeys and ECC (`pgp`)
- [x] OpenPGP symmetrically encrypted files (`pgp`)
- [x] PGP Self-Decrypting Archive `.sda` (`pgpsda`)
- [x] PGP Whole Disk Encryption volume (`pgpwde`)
- [x] PGP Disk volume (`pgpdisk`)

## Windows

- [x] SAM hive local account NT hashes (`ntlm`)
- [x] SECURITY hive cached domain credentials (`dcc2`)
- [x] SECURITY hive DPAPI masterkeys (`dpapi`)
- [x] User DPAPI masterkey files (`dpapi`)
- [x] Windows Credential Manager vaults (`dpapi`)
- [x] Windows Hello PIN and container data (`windows-hello`)
- [x] BitLocker recovery keys and VMK material (`bitlocker`)

## Unix and directory credentials

- [x] IBM/Toshiba 4690 ADXCSOUF user database (`adxcrypt`)

- [x] Linux `/etc/shadow` (`descrypt`, `md5crypt`, `sha256crypt`, `sha512crypt`, `yescrypt`)
- [x] BSD `/etc/master.passwd` (`bsdicrypt`)
- [x] AIX `/etc/security/passwd` (`aix-smd5`, `ssha1-aix`, `ssha256-aix`, `ssha512-aix`)
- [x] AS/400 user profiles (`as400-des`, `as400-ssha1`)
- [x] RACF DES records (`racf`)
- [x] RACF KDFAES and passphrase records (`racf-kdfaes`, `racf-passphrase`, `racf-kdfaes-passphrase`)
- [x] LDAP password attributes (`ldap-sha1`, `ldap-ssha1`, `ldap-ssha256`, `ldap-ssha512`)
- [x] Apache htpasswd `$apr1$` hashes (`apr1`)
- [x] bcrypt password files (`bcrypt`)
- [x] Solaris shadow entries (`sunmd5`, `sha1crypt`)

## Apple and macOS

- [x] Login keychain (`apple-keychain`)
- [x] Secure Notes (`apple-secure-notes`)
- [x] macOS local account password plists (`macos-sha1`, `macos-sha512`, `macos-pbkdf2-sha512`)
- [x] iCloud keychain records
- [x] iOS keychain records from a backup (`keyring`, `iphone-passcode`)
- [x] iTunes and Finder iOS backups (`itunes-backup`)
- [x] Apple iWork 2013/2014 documents with an iwpv2 verifier (`iwork`)
- [x] Apple iWork 2009 documents (`iwork`)
- [x] Apple DMG encrcdsa v2 images (`dmg-payload`)
- [x] Apple DMG encrcdsa v3 images (`apple-dmg`)

## Disk and filesystem encryption

- [x] LUKS v1 header (`luks-v1`)
- [x] LUKS v2 header (`luks-v2`)
- [x] TrueCrypt volume header (`truecrypt`)
- [x] VeraCrypt volume header (`veracrypt`)
- [x] DiskCryptor volume (`diskcryptor`)
- [x] BitLocker volume metadata (`bitlocker`)
- [x] FileVault 2 volume (`filevault2`)
- [x] APFS volume (`apfs`)
- [x] FreeBSD GELI metadata (`geli`)
- [x] OpenBSD softraid metadata (`openbsd-softraid`)
- [x] Android FDE footer (`android-fde`)
- [x] Samsung Android FDE (`android-fde-samsung`)
- [x] eCryptfs version 2 wrapped passphrases (`ecryptfs`)
- [x] eCryptfs version 1 wrapped passphrases (`ecryptfs`)
- [x] Google fscrypt policy and key material (`fscrypt`)
- [x] EncFS configuration and key files (`encfs`)
- [x] VirtualBox VDI key stores from `.vbox` files (`vdi`)
- [x] VirtualBox hashcat disk metadata (`virtualbox`)
- [x] VMware VMX encryption keySafe (`vmx-keysafe`)
- [x] VMware VMX hashcat metadata (`vmware-vmx`)
- [x] Veeam backup metadata (`veeam`)
- [x] BestCrypt containers (`bestcrypt`, `bestcrypt-payload`)
- [x] ENCDataVault containers (`encdv`)

## Archives and documents

- [x] ZIP with ZipCrypto (`pkzip`)
- [x] ZIP with WinZip AES (`winzip`)
- [x] SecureZIP AES archives (`securezip`)
- [x] RAR3 archives (`rar3p`, `rar3hp`)
- [x] RAR5 archives (`rar5`)
- [x] 7-Zip archives (`sevenzip`)
- [x] MS Office 97-2003 documents (`oldoffice`)
- [x] MS Office 2007+ documents (`office`)
- [x] MS Office sheet protection (`office2016-sheetprotection`)
- [x] PDF user and owner passwords (`pdf`)
- [x] Encrypted OpenDocument packages (`odf`)
- [x] PST mail stores (`pst`)
- [x] SAP PSE files (`sappse`)
- [x] OpenSSL `enc` files (`openssl-enc`)
- [x] Ansible Vault files (`ansible-vault`)

## Keys and certificate containers

- [x] Hashed SSH known_hosts entries (`known-hosts`)

- [x] PKCS#12 and PFX bundles (`pkcs12`, `pfx`)
- [x] PKCS#8 and PEM private keys (`pem-private-key`)
- [x] PEM private keys in the John serialization (`pem`)
- [x] JKS and JCEKS private keys (`jks-private-key`)
- [x] OpenSSH private keys (`sshng`)
- [x] PuTTY private keys (`putty`)
- [x] XCA databases (`xca`)

## Password managers

- [x] MySQL user-table hash dumps (`mysql323`, `mysql-sha1`, `mysql-a`)
- [x] MSSQL database user hashes (`mssql-2000`, `mssql-2005`, `mssql-2012`, `mssql-2025`)
- [x] PostgreSQL SCRAM verifier dumps (`postgres-scram-sha256`)
- [x] Oracle H and T password hashes (`oracle-h`, `oracle-t`)

- [x] KeePass KDBX v2/v3 (`keepass`)
- [x] KeePass KDBX v4 (`keepass4`)
- [x] 1Password agilekeychain (`onepassword-agile`, `agilekeychain`)
- [x] 1Password cloudkeychain profiles (`cloudkeychain`)
- [x] 1Password cloudkeychain hashcat serialization (`onepassword-cloud`)
- [x] 1Password mobile keychain (`onepassword-mobile`)
- [x] Bitwarden encrypted export (`bitwarden`)
- [x] LastPass vault (`lastpass`)
- [x] LastPass CLI state (`lpcli`)
- [x] Password Safe v2 (`pwsafe-v2`)
- [x] Password Safe v3 (`pwsafe-v3`, `pwsafe`)
- [x] Legacy KDE KWallet files (`kwallet`)
- [x] Salted KDE KWallet 4.13+ files with `.salt` sidecars (`kwallet`)
- [x] Enpass databases (`enpass`)
- [x] Dashlane vaults (`dashlane`)
- [x] BKS keystores (`bks`)
- [x] Clipperz exports (`clipperz`)
- [x] cryptoSafe vaults (`cryptosafe`)
- [x] GNOME Keyring files (`keyring`)

## Browsers

- [x] Firefox `key4.db` master-password verifier (`mozilla-key4`)
- [x] Firefox `key3.db` master-password verifier (`mozilla-key3`)
- [x] Safari saved-password records in the login keychain

## Wallets and cryptocurrency stores

- [x] Bitcoin Core `wallet.dat` (`bitcoin-wallet`)
- [x] Electrum wallets (`electrum`)
- [x] MultiBit Classic `.key` (`multibit`)
- [x] MultiBit HD wallets (`multibit-hd`)
- [x] MultiBit Classic `.wallet` (`multibit-wallet`)
- [x] Ethereum keystore v3 JSON (`ethereum-pbkdf2`, `ethereum-scrypt`)
- [x] Ethereum presale wallets (`ethereum-presale`)
- [x] MetaMask extension vaults (`metamask`)
- [x] MetaMask mobile vaults (`metamask-mobile`)
- [x] Armory wallets (`armory`)
- [x] Blockchain.com wallet JSON (`blockchain`)
- [x] Blockchain.com second-password wallets (`blockchain-second`)
- [x] Dogechain wallets (`dogechain`)
- [x] Exodus wallets (`exodus`)
- [x] Bisq wallets (`bisq`)
- [x] Monero wallets (`monero`)
- [x] Tezos wallets (`tezos`)
- [x] Cardano wallets (`cardano-payload`)
- [x] Keplr wallets (`keplr`)
- [x] Stellar wallets (`stellar`)
- [x] Terra wallets (`terra`)
- [x] BitShares backup wallets (`bitshares-payload`)
- [x] BitShares SQLite and LevelDB wallets (`bitshares`)
- [x] Raw WIF private keys (`bitcoin-wif`)

## Mobile and application stores

- [x] Lotus Notes/Domino 5 user ID files (`lotus5`)
- [x] Lotus Notes/Domino 6/8 user ID files (`lotus-notes`)

- [x] FileZilla Server XML configuration (`filezilla-server`)

- [x] Android backups (`android-backup`)
- [x] Signal backups (`signal`)
- [x] Telegram local data (`telegram`)
- [x] SQLCipher databases (`sqlcipher`)
- [x] Fernet-encrypted application secrets (`fernet`)
- [x] Flask signed session cookies (`flask-session`)
- [x] JSON Web Tokens (`jwt`)

## Plain hash lists

- [x] MD5 hash lists (`md5`)
- [x] MD4 hash lists (`md4`)
- [x] NTLM hash lists (`ntlm`)
- [x] LM hash lists (`lm`)
- [x] SHA-1 hash lists (`sha1`)
- [x] RIPEMD hash lists (`ripemd`)
- [x] SHA-224 hash lists (`sha224`)
- [x] SHA-256 hash lists (`sha256`)
- [x] SHA-384 hash lists (`sha384`)
- [x] SHA-512 hash lists (`sha512`)
- [x] GOST hash lists (`gost`)
- [x] Keccak hash lists (`keccak`)
- [x] MD2 hash lists (`md2`)
- [x] SHA-0 hash lists (`sha0`)
- [x] SHA-3 hash lists (`sha3`)
- [x] SM3 hash lists (`sm3`)
- [x] Streebog hash lists (`streebog`)
- [x] Tiger hash lists (`tiger`)
- [x] Whirlpool hash lists (`whirlpool`)
- [x] Skein-512 hash lists (`skein-512`)
- [x] BLAKE2b-512 hash lists (`blake2b-512`)
- [x] BLAKE2b-256 hash lists (`blake2b-256`)
- [x] BLAKE2s-256 hash lists (`blake2s-256`)
- [x] Snefru hash lists (`snefru`)
- [x] MD6 hash lists (`md6`)
- [x] HAS-160 hash lists (`has-160`)
- [x] PANAMA hash lists (`panama`)
- [x] MDC-2 hash lists (`mdc2`)
- [x] RadioGatun hash lists (`radiogatun`)
- [x] EDON-R-256 hash lists (`edon-r-256`)
- [x] EDON-R-512 hash lists (`edon-r-512`)
- [x] Fugue hash lists (`fugue`)
- [x] Groestl hash lists (`groestl`)
- [x] Hamsi hash lists (`hamsi`)
- [x] JH hash lists (`jh`)
- [x] Luffa hash lists (`luffa`)
- [x] Shabal hash lists (`shabal`)
- [x] SHAvite-3 hash lists (`shavite3`)
- [x] SIMD hash lists (`simd`)

## Textual credential exports

- [x] AS/400 password hash exports (`as400-des`, `as400-ssha1`)
- [x] Lotus Notes/Domino 6/8 hash exports (`lotus-notes`)
- [x] OpenVMS password hash exports (`openvms`)
- [x] Oracle 11g, 12c, and OTM hash exports (`oracle11`, `oracle12c`, `oracle-otm`)
- [x] RACF KDFAES and passphrase exports (`racf-kdfaes`, `racf-passphrase`)
- [x] Sybase password hash exports (`sybase-prop`)

## Network captures

- [x] WPA/WPA2 EAPOL handshakes (`wpa-pmkid`)
- [x] WPA PMKID captures (`wpa-pmkid`)
- [x] Legacy WPA handshakes (`wpa-pmkid`)
- [x] Kerberos AS-REP, etype 23 (`krb5asrep23`)
- [x] Kerberos AS-REP, etype 17/18 (`krb5asrep-aes`)
- [x] Kerberos TGS-REP, etype 23 (`krb5tgs23`)
- [x] Kerberos TGS-REP, etype 17/18 (`krb5tgs17`, `krb5tgs18`)
- [x] Kerberos AS-REQ pre-authentication (`krb5pa23`, `krb5pa17`, `krb5pa18`)
- [x] Kerberos database extracts (`krb5db17`, `krb5db18`, `krb5db-old`)
- [x] Kerberos 4 exchanges (`krb4`)
- [x] NTLMSSP NetNTLMv1 (`netntlmv1`)
- [x] NTLMSSP NetNTLMv2 (`netntlmv2`)
- [x] MSCHAPv2 exchanges (`mschapv2-naive`, `chap`)
- [x] iSCSI CHAP exchanges (`iscsi-chap`)
- [x] SNMPv3 authenticated messages (`snmpv3`)
- [x] RADIUS shared-secret exchanges (`radius`)
- [x] TACACS+ exchanges (`tacacs-plus`)
- [x] SIP digest authentication (`sip-digest`)
- [x] IKE pre-shared-key exchanges (`ike-psk-md5`, `ike-psk-sha1`, `ike-payload`)
- [x] OSPFv2 and RIPv2 MD5 authentication (`ospf-md5`)
- [x] TCP MD5 signatures (`tcp-md5`)
- [x] HSRP authentication (`hsrp`)
- [x] EIGRP authentication (`eigrp`)
- [x] MS SNTP authenticated packets (`sntp-ms`)

## Excluded extraction targets

These artifacts do not currently map to a crackable hash serialization or cannot provide the material their hash type requires:

- SECURITY hive LSA secrets: not a single hash format. Recoverable records map to existing types such as `ntlm` or `dcc2`, while others are not password hashes.
- PKZIP master-key archives: the hash carries no artifact-derived salt or ciphertext.
- Chromium Login Data and Cookies: encrypted with OS-protected keys and no crackable verifier is present in the files.
- Firefox `logins.json` and `signons.sqlite`: encrypted login records contain no master-password verifier; use `mozilla-key4` or `mozilla-key3` instead.
