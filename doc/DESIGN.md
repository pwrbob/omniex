# Design Document for omniex

## Principles

- Every hash type has its own struct.
- Different use cases are mapped to traits.
- Each hash mode should contain documentation, specifically on the meaning of each parameter.
- Each hash type knows which john/hashcat modes can attack it

## Use Cases

### 1. Output of hash function

Example: md5(..) gives an output, typically given as a hex string. It has a fixed size, and there exist many hashcat modes that could attack it.

In this case, we want to accept the hash as either:
- a string (`omniex <hex_str_here>`)
- a file containing one or more such strings

The output should be the hashcat / john hash string. In this case, it could in principle be the same as the input. The advantage of this tool is that it parses the hex string and renders it again, preventing problems (and throwing an error message) when e.g. one letter was omitted.

### 2. Encrypted Files

In this case, there are often multiple parameters that need to be extracted from a file and packed into the hash string.

The struct would have an entry per parameter, including a description that can be shown with `--verbose` (or a similar flag). That way, users can easily understand what each parameter means.

Furthermore, there must be some extraction logic that takes as input the file and returns an instance of the struct (in a `Result`, since many things can go wrong).
This should be described by a trait, e.g. `Extractable` or similar (follow rust naming conventions for traits when deciding on the name).

This case should of course also allow parsing of existing hashes, to allow verification and explanation of parameters.

If differences exist between hashcat and john hash strings, the flag `--format` can be used to specify either `hashcat` or `john` formats (default to hashcat).

### 3. Undetectable Things

Ex: veracrypt, truecrypt volumes, which are just binary blobs.

In this case, the user must specify the type at extraction time (e.g. veracrypt). The exact mode could then be detected in some cases depending on the exact parameters it finds.

### 4. Disk images

A user should be able to specify the path to a disk image (or partition like `/dev/sda1`). The program would then detect e.g. LUKS headers and find the type, or, in the case of veracrypt where the type is given at extraction time, simply extract directly from the disk. In this case, the input is not a binary blob, but a disk or disk image.

### 5. Forensic Artifacts

The program should know about file types that could be encountered in forensic investigations (shadow files, windows images, keepass containers, crypto wallets) and automatically extract the corresponding hashes. It should not do any iteration over filesystems (that would be another tool that orchestrates things), the input is always one artifact.



## Advanced Features

Consider these advanced features when creating the implementation plan:

- hashcat may change the hash format over time. Consider allowing a `--hc-version` flag that generates the hash in the exact format that version uses. Automate testing of this by iterating over hashcat version in the unit tests.


