#[test]
fn derive_rejects_invalid_declarations() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
