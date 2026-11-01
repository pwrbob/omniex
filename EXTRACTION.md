# Extraction checklist

Working list of artifact formats to support. Each line is one logical artifact
format and names the target hash type or mode family where one already exists.
Check an entry when its extractor, probe, fixtures, and negative tests land. The
README badge counts checked lines in this file.

## OpenPGP and PGP

- [x] OpenPGP secret keys, armored and binary, including subkeys and ECC (`gpg`)
- [ ] OpenPGP symmetrically encrypted files (`gpg`)
- [x] PGP Self-Decrypting Archive `.sda` (`pgpsda`)
- [ ] PGP Whole Disk Encryption volume (`pgpwde`)
- [ ] PGP Disk volume (`pgpdisk`)

## Windows

- [ ] SAM hive local account NT hashes (`ntlm`)
- [ ] SECURITY hive cached domain credentials (`dcc2`)
- [ ] SECURITY hive LSA secrets
- [ ] SECURITY hive DPAPI masterkeys (`dpapi`)
- [ ] User DPAPI masterkey files (`dpapi`)
- [ ] Windows Credential Manager vaults (`dpapi`)
- [ ] Windows Hello PIN and container data (`windows-hello`)
- [ ] BitLocker recovery keys and VMK material (`bitlocker`)

## Unix and directory credentials

- [ ] Linux `/etc/shadow` (`descrypt`, `md5crypt`, `sha256crypt`, `sha512crypt`, `yescrypt`)
- [ ] BSD `/etc/master.passwd` (`bsdicrypt`)
- [ ] AIX `/etc/security/passwd` (`aix-smd5`, `aix-ssha1`, `aix-ssha256`, `aix-ssha512`)
- [ ] AS/400 user profiles (`as400-des`, `as400-ssha1`)
- [ ] RACF database extracts (`racf`, `racf-kdfaes`, `racf-passphrase`, `racf-kdfaes-passphrase`)
- [ ] LDAP password attributes (`ldap-sha1`, `ldap-ssha1`, `ldap-ssha256`, `ldap-ssha512`)

## Apple and macOS

- [ ] Login keychain (`apple-keychain`)
- [ ] Secure Notes (`apple-secure-notes`)
- [ ] macOS local account password plists (`macos-sha1`, `macos-sha512`, `macos-pbkdf2-sha512`)
- [ ] iCloud keychain records
- [ ] iOS keychain records from a backup (`keyring`, `iphone-passcode`)
- [ ] iTunes and Finder iOS backups (`itunes-backup`)
- [x] Apple iWork 2013/2014 documents with an iwpv2 verifier (`iwork`)
- [ ] Apple iWork 2009 documents (`iwork`)
- [x] Apple DMG encrcdsa v2 images (`dmg-john`)
- [ ] Apple DMG encrcdsa v3 images (`apple-dmg`)

## Disk and filesystem encryption

- [ ] LUKS v1 header (`luks-v1`)
- [ ] LUKS v2 header (`luks-v2`)
- [ ] TrueCrypt volume header (`truecrypt`)
- [ ] VeraCrypt volume header (`veracrypt`)
- [ ] DiskCryptor volume (`diskcryptor`)
- [ ] BitLocker volume metadata (`bitlocker`)
- [ ] FileVault 2 volume (`filevault2`)
- [ ] APFS volume (`apfs`)
- [x] FreeBSD GELI metadata (`geli`)
- [x] OpenBSD softraid metadata (`openbsd-softraid`)
- [ ] Android FDE footer (`android-fde`)
- [ ] Samsung Android FDE (`android-fde-samsung`)
- [x] eCryptfs version 2 wrapped passphrases (`ecryptfs`)
- [ ] eCryptfs version 1 wrapped passphrases (`ecryptfs`)
- [ ] Google fscrypt policy and key material (`fscrypt`)
- [x] EncFS configuration and key files (`encfs`)
- [ ] VirtualBox disk images (`virtualbox`)
- [ ] VMware VMX and encrypted disk metadata (`vmware-vmx`, `vmx`)
- [ ] Veeam backup metadata (`veeam`)

## Archives and documents

- [ ] ZIP with ZipCrypto (`pkzip`)
- [x] ZIP with WinZip AES (`winzip`)
- [ ] SecureZIP AES archives (`securezip`)
- [ ] PKZIP master-key archives (`pkzip-master-key`)
- [ ] RAR3 archives (`rar3p`, `rar3hp`)
- [ ] RAR5 archives (`rar5`)
- [ ] 7-Zip archives (`sevenzip`)
- [ ] MS Office 97-2003 documents (`oldoffice`)
- [ ] MS Office 2007+ documents (`office`)
- [ ] MS Office sheet protection (`office2016-sheetprotection`)
- [ ] PDF user and owner passwords (`pdf`)
- [x] Encrypted OpenDocument packages (`odf`)
- [ ] PST mail stores (`pst`)
- [ ] SAP PSE files (`sappse`)
- [ ] OpenSSL `enc` files (`openssl-enc`)
- [x] Ansible Vault files (`ansible-vault`)

## Keys and certificate containers

- [x] Hashed SSH known_hosts entries (`known-hosts`)

- [ ] PKCS#12 and PFX bundles (`pkcs12`, `pfx`)
- [ ] PKCS#8 and PEM private keys (`pem-private-key`, `pem`)
- [ ] JKS and JCEKS private keys (`jks-private-key`)
- [ ] OpenSSH private keys (`sshng`)
- [ ] PuTTY private keys (`putty`)
- [ ] XCA databases (`xca`)

## Password managers

- [ ] KeePass KDBX v2/v3 (`keepass`)
- [ ] KeePass KDBX v4 (`keepass4`)
- [x] 1Password agilekeychain (`onepassword-agile`, `agilekeychain`)
- [ ] 1Password cloudkeychain (`onepassword-cloud`)
- [ ] 1Password mobile keychain (`onepassword-mobile`)
- [ ] Bitwarden encrypted export (`bitwarden`)
- [ ] LastPass vault (`lastpass`)
- [ ] LastPass CLI state (`lpcli`)
- [ ] Password Safe v2 (`pwsafe-v2`)
- [x] Password Safe v3 (`pwsafe-v3`, `pwsafe`)
- [x] Legacy KDE KWallet files (`kwallet`)
- [ ] Salted KDE KWallet 4.13+ files with `.salt` sidecars (`kwallet`)
- [x] Enpass databases (`enpass`)
- [x] Dashlane vaults (`dashlane`)
- [x] BKS keystores (`bks`)
- [ ] Clipperz exports (`clipperz`)
- [ ] cryptoSafe vaults (`cryptosafe`)
- [ ] GNOME Keyring files (`keyring`)

## Browsers

- [ ] Chromium Login Data with DPAPI or Linux keyring encryption
- [ ] Chromium Cookies with encrypted values
- [ ] Firefox `logins.json` and `key4.db` (`mozilla-key4`)
- [ ] Firefox `signons.sqlite` and `key3.db` (`mozilla-key3`)
- [ ] Safari saved-password records in the login keychain

## Wallets and cryptocurrency stores

- [ ] Bitcoin Core `wallet.dat` (`bitcoin-wallet`)
- [ ] Electrum wallets (`electrum`)
- [ ] MultiBit Classic `.key` (`multibit`)
- [ ] MultiBit HD wallets (`multibit-hd`)
- [ ] MultiBit Classic `.wallet` (`multibit-wallet`)
- [ ] Ethereum keystore v3 JSON (`ethereum-pbkdf2`, `ethereum-scrypt`)
- [ ] Ethereum presale wallets (`ethereum-presale`)
- [ ] MetaMask extension vaults (`metamask`)
- [ ] MetaMask mobile vaults (`metamask-mobile`)
- [ ] Armory wallets (`armory`)
- [ ] Blockchain.com wallets (`blockchain`, `blockchain-second`)
- [ ] Dogechain wallets (`dogechain`)
- [ ] Exodus wallets (`exodus`)
- [ ] Bisq wallets (`bisq`)
- [x] Monero wallets (`monero`)
- [ ] Tezos wallets (`tezos`)
- [ ] Cardano wallets (`cardano`)
- [ ] Keplr wallets (`keplr`)
- [ ] Stellar wallets (`stellar`)
- [ ] Terra wallets (`terra`)
- [ ] BitShares wallets (`bitshares`)
- [ ] Raw WIF private keys (`bitcoin-wif`)

## Mobile and application stores

- [x] FileZilla Server XML configuration (`filezilla-server`)

- [ ] Android backups (`android-backup`)
- [ ] Signal backups (`signal`)
- [ ] Telegram local data (`telegram`)
- [ ] SQLCipher databases (`sqlcipher`)
- [x] Fernet-encrypted application secrets (`fernet`)
- [ ] Flask signed session cookies (`flask-session`)
- [x] JSON Web Tokens (`jwt`)

## Network captures

- [ ] WPA/WPA2 EAPOL handshakes (`wpa-pmkid`)
- [ ] WPA PMKID captures (`wpa-pmkid`)
- [ ] Legacy WPA handshakes (`wpa-pmkid-legacy`)
- [ ] Kerberos AS-REP, etype 23 (`krb5asrep23`)
- [ ] Kerberos AS-REP, etype 17/18 (`krb5asrep-aes`)
- [ ] Kerberos TGS-REP, etype 23 (`krb5tgs23`)
- [ ] Kerberos TGS-REP, etype 17/18 (`krb5tgs17`, `krb5tgs18`)
- [ ] Kerberos AS-REQ pre-authentication (`krb5pa23`, `krb5pa17`, `krb5pa18`)
- [ ] Kerberos database extracts (`krb5db17`, `krb5db18`, `krb5db-old`)
- [ ] Kerberos 4 exchanges (`krb4`)
- [ ] NTLMSSP NetNTLMv1 (`netntlmv1`)
- [ ] NTLMSSP NetNTLMv2 (`netntlmv2`)
- [ ] MSCHAPv2 exchanges (`mschapv2-naive`, `chap`)
- [ ] iSCSI CHAP exchanges (`iscsi-chap`)
- [ ] SNMPv3 authenticated messages (`snmpv3`)
- [ ] RADIUS shared-secret exchanges (`radius`)
- [ ] TACACS+ exchanges (`tacacs-plus`)
- [ ] SIP digest authentication (`sip-digest`)
- [ ] IKE pre-shared-key exchanges (`ike-psk-md5`, `ike-psk-sha1`, `ike-john`)
- [ ] OSPFv2 and RIPv2 MD5 authentication (`ospf-md5`)
- [ ] TCP MD5 signatures (`tcp-md5`)
- [ ] HSRP authentication (`hsrp`)
- [ ] EIGRP authentication (`eigrp`)
- [ ] MS SNTP authenticated packets (`sntp-ms`)
