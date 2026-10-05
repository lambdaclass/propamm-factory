//! `e2e/downstream/` is a crate outside the workspace that depends on the library the way
//! another repository would. Its `main.rs` is `examples/tilted.rs` byte for byte, so the
//! downstream build proves the public API is enough for that example and nothing else.

#[test]
fn the_downstream_crate_is_the_tilted_example_byte_for_byte() {
    let example = include_str!("../examples/tilted.rs");
    let downstream = include_str!("../../e2e/downstream/src/main.rs");
    assert_eq!(
        downstream, example,
        "e2e/downstream/src/main.rs must equal quote-updater/examples/tilted.rs"
    );
}
