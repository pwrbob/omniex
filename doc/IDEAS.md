# Ideas

Feature ideas that are not implemented yet. Each entry describes the problem,
the intended interface, and the open questions to settle before building it.

## `omniex example`

Given a type, print a valid example hash. Useful for documentation, for
checking a target tool's serialization, and for smoke-testing a build.

```bash
omniex example salted-md5          # by type slug
omniex example 0                   # by hashcat mode
omniex example salted-md5 --format john
omniex example 10 --mode          # also print the selected mode
omniex examples                    # maybe: one example per registered type
```

A positional selector accepts either a type slug or a decimal hashcat mode.
Slugs are matched first; a bare number is always a hashcat mode. Ambiguous or
unknown selectors fail with the usual usage error.

The example should be stable across builds so it can be used in docs and
tests. Each hash type would declare canonical sample field values (digest,
salt, key, iteration count, and so on), and the command would render those
through the normal `render` path rather than hard-coding a hash string. That
keeps the output honest: if rendering changes, the example changes with it.
`--format` selects hashcat (default) or John, and the value-dependent modes of
a type should be exercised by rendering the serialization for the requested
mode.

Open questions:

- Where do sample values live: a new field in `HashTypeDescriptor`, an
  associated constant on each type, or a separate table?
- How should a scalar digest be chosen? A fixed vector (for example the digest
  of `omniex`) is reproducible but must still parse, and some modes require
  value-dependent checks such as a prefix or length.
- How to address a mode whose serialization differs from the type's default,
  and how to name John-only formats when no hashcat mode exists.
- Whether to add `examples` (all types) now or only the single-type command.
