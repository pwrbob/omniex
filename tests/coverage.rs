//! Table-driven coverage checks that need no reference tools.

mod common;

use common::{VECTORS, vector_for, vector_modes};
use omniex::{ParseOptions, RenderOptions, Tool, registry};

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
fn vectors_round_trip_for_both_tools() {
    for vector in VECTORS {
        let descriptor = registry::by_slug(vector.slug).expect("registered");

        for tool in [Tool::Hashcat, Tool::John] {
            let parse_opts = ParseOptions {
                tool,
                ..ParseOptions::default()
            };
            let render_opts = RenderOptions {
                tool,
                ..RenderOptions::default()
            };

            let value = registry::parse(descriptor, vector.hash, &parse_opts)
                .unwrap_or_else(|error| panic!("`{}` failed to parse: {error}", vector.slug));
            assert_eq!(
                value.render(&render_opts),
                vector.hash,
                "`{}` did not round-trip for {tool:?}",
                vector.slug
            );
        }
    }
}

#[test]
fn vector_modes_are_a_subset_of_declared_modes() {
    for vector in VECTORS {
        let descriptor = registry::by_slug(vector.slug).expect("registered");
        let value = registry::parse(descriptor, vector.hash, &ParseOptions::default())
            .expect("vector parses");
        let modes = value.modes();

        for mode in &modes {
            assert!(
                descriptor.all_modes.contains(mode),
                "`{}` reported undeclared mode {mode:?}",
                vector.slug
            );
        }
        for mode in vector_modes(vector) {
            assert!(
                modes.contains(&mode),
                "`{}` did not report vector mode {mode:?}",
                vector.slug
            );
        }
    }
}
