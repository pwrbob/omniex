//! Table-driven coverage checks that need no reference tools.

mod common;

use common::{VECTORS, vector_for, vector_modes};
use omniex::{Mode, ParseOptions, RenderOptions, Tool, registry};

#[test]
fn every_registered_type_has_a_vector() {
    for descriptor in registry::all() {
        assert!(
            vector_for(descriptor).is_some(),
            "no conformance vector for `{}`",
            descriptor.slug
        );
    }
}

#[test]
fn every_declared_mode_has_a_vector() {
    for descriptor in registry::all() {
        let vector = vector_for(descriptor).expect("vector exists");
        let covered = vector_modes(vector);

        for mode in descriptor.all_modes {
            assert!(
                covered.contains(mode),
                "mode {mode:?} for `{}` has no conformance vector",
                descriptor.slug
            );
        }
    }
}

#[test]
fn every_vector_names_a_registered_type() {
    for vector in VECTORS {
        assert!(
            registry::by_slug(vector.slug).is_some(),
            "vector `{}` does not name a registered type",
            vector.slug
        );
    }
}

#[test]
fn hashcat_vectors_round_trip_and_report_their_mode() {
    for vector in VECTORS {
        let descriptor = registry::by_slug(vector.slug).expect("registered");
        let opts = ParseOptions {
            tool: Tool::Hashcat,
            ..ParseOptions::default()
        };
        let render_opts = RenderOptions {
            tool: Tool::Hashcat,
            ..RenderOptions::default()
        };

        for entry in vector.hashcat {
            let value = registry::parse(descriptor, entry.hash, &opts).unwrap_or_else(|error| {
                panic!(
                    "`{}` failed to parse the mode {} vector: {error}",
                    vector.slug, entry.mode
                )
            });

            assert_eq!(
                value.render(&render_opts),
                entry.hash,
                "`{}` did not round-trip for hashcat mode {}",
                vector.slug,
                entry.mode
            );
            assert!(
                value.modes().contains(&Mode::Hashcat(entry.mode)),
                "`{}` parsed the mode {} vector but did not report that mode: {:?}",
                vector.slug,
                entry.mode,
                value.modes()
            );
        }
    }
}

#[test]
fn john_vectors_round_trip_and_report_their_format() {
    for vector in VECTORS {
        let descriptor = registry::by_slug(vector.slug).expect("registered");

        for entry in vector.john {
            let opts = ParseOptions {
                tool: Tool::John,
                ..ParseOptions::default()
            };
            let render_opts = RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            };

            let value = registry::parse(descriptor, entry.hash, &opts).unwrap_or_else(|error| {
                panic!(
                    "`{}` failed to parse the {} vector: {error}",
                    vector.slug, entry.format
                )
            });

            assert_eq!(
                value.render(&render_opts),
                entry.hash,
                "`{}` did not round-trip for John format {}",
                vector.slug,
                entry.format
            );
            assert!(
                value.modes().contains(&Mode::John(entry.format)),
                "`{}` parsed the {} vector but did not report that format: {:?}",
                vector.slug,
                entry.format,
                value.modes()
            );
        }
    }
}

#[test]
fn vector_modes_are_a_subset_of_declared_modes() {
    for vector in VECTORS {
        let descriptor = registry::by_slug(vector.slug).expect("registered");

        for mode in vector_modes(vector) {
            assert!(
                descriptor.all_modes.contains(&mode),
                "`{}` vector names undeclared mode {mode:?}",
                vector.slug
            );
        }
    }
}
