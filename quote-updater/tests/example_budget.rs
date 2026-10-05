//! The example is the measure of how easy the API is: a complete custom binary in about
//! 30 lines, importing one prelude. If a change makes it longer, the API got wider.

#[test]
fn the_custom_pricer_example_stays_within_its_budget() {
    let source = include_str!("../examples/custom_pricer.rs");
    let code: Vec<&str> = source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect();
    assert!(
        code.len() <= 30,
        "{} lines of code, budget 30:\n{}",
        code.len(),
        code.join("\n")
    );
    let imports: Vec<&&str> = code
        .iter()
        .filter(|line| line.starts_with("use quote_updater"))
        .collect();
    assert_eq!(imports, [&"use quote_updater::prelude::*;"]);
}
