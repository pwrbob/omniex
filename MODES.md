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


### 7000-7999


### 8000-8999


### 9000-9999


### 10000-10999


### 11000-11999


### 12000-12999


### 13000-13999


### 14000-14999

- [ ] `14600` - `LUKS v1 (legacy)`

### 15000-15999


### 16000-16999


### 17000-17999


### 18000-18999


### 19000-19999


### 20000-20999


### 21000-21999


### 22000-22999


### 23000-23999

### 24000-24999


### 25000-25999


### 26000-26999

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

### 30000-30999


### 31000-31999


### 32000-32999


### 33000-33999


### 34000-34999

- [ ] `34100` - `LUKS v2 argon2 + SHA-256 + AES`

### 35000-35999


### 36000-36999


### 37000-37999


### 38000-38999


### 40000-40099


### 40100-40199


## John the Ripper formats

Initial source set: 264 entries (255 CPU labels plus
9 OpenCL-only labels; 100 `*-opencl` labels total,
with 91 grouped as aliases).

`*-opencl` variants are grouped with their CPU label and normally share the same
struct. Labels marked `OpenCL only` have no CPU equivalent in the source list.

### 0-9


### A-C

- [ ] `axcrypt2-opencl` - OpenCL only

### D-F

- [ ] `diskcryptor-aes-opencl` - OpenCL only
- [ ] `electrum-modern-opencl` - OpenCL only
- [ ] `ethereum-presale-opencl` - OpenCL only

### G-I


### J-L

- [ ] `krb5asrep-aes-opencl` - OpenCL only
- [ ] `LUKS`

### M-O

- [ ] `ntlmv2-opencl` - OpenCL only

### P-R

- [ ] `raw-SHA512-free-opencl` - OpenCL only

### S-U

- [ ] `TrueCrypt-opencl` - OpenCL only

### V-Z

- [ ] `XSHA512-free-opencl` - OpenCL only



## hashcat bridged modes

These duplicate an existing hash type and usually need no separate struct.
Remove each entry together with the base mode it duplicates.

- [ ] `73000` - `Generic Hash [Bridged: Python]`
- [ ] `74000` - `Generic Hash [Bridged: Rust]`

## Excluded

- hashcat `99999` - `Plaintext`: not a hash.
- John `plaintext`: not a hash.
- hashcat `2000` - `STDOUT`: not a hash.
- hashcat `4000` - `Hash Recipe`: not a hash.
- hashcat `2500`/`2501`: deprecated in hashcat 8.0.0 and replaced by `22000`/`22001`.
- John `dynamic` and `dynamic=`: dynamic compiler support is out of scope.