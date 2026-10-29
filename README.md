# omniex

The extractor for everything.


## Goal

The goal of this project is to create a tool called `omniex` that extracts hashes from many different file types for use in password forensics.
The main motivation is that the current state of affairs is horrible- many different scripts in different repositories, that are often incomplete, unmaintained and/or buggy.

This tool should:
- support all hash modes that hashcat and john the ripper support
- have extensive integration tests (CI) that test extraction for compatibility with hashcat and john
- have integration tests per hash type that test all different cases that are possible (parameter values, ...)
- have an intermediate, strongly typed format that can be rendered as json or shown in a user-friendly CLI to provide more easily understandable information about the hash format
- have a flag that describes a hash in human-readable, nice output. consider a CLI with colors (original hash string where the different components are color-coded, with a description per component below)
- support extracting hashes from original files
- support parsing hashes in hashcat and JtR format into the intermediate format ("reverse parsing")
- support outputting which john or hashcat modes can be used to attack a specific hash (e.g. input is an encrypted pdf, output is the hash and exact hashcat mode to use)
- support hash lists, e.g. files containing one hash per line of the same type


## How to build this

- Use Rust.
- Read the DESIGN.md document and think about the open questions. Propose solutions and ask me for my opinion on points that are not obvious or clear.
- Start by building a serious integration testing framework. Integration tests should be executable locally before committing / pushing, as well as via github CI.
- Integration testing should be hashcat-version-aware (tests compare to a given, fixed hashcat version, as well as the master branch).
- Parsing of hash strings ("reverse parsing"): Compile in hashcat parsing functions from all modes via ffi. This can be used for testing to ensure binary equivalence. This gives a first source of truth before migrating parsing to Rust. Migrate one function after the other to Rust, the goal is to have no C in the project source once things work. You may keep C in the repo for unit testing and testing equivalence to hashcat.
- Each hash type should have its own Rust struct (strong typing). Each member should have a description of its meaning (iteration count, salt, ...). This should be easily declarable via macros.
- Don't clone hashcat or add it as a submodule. Unit tests should clone it and checkout certain version to test against. Hash modes should be rebuilt / linked against on each new test (e.g. when testing reverse parsing)



