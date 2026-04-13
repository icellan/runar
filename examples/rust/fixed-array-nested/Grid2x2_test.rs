//! Unit tests for the nested Grid2x2 FixedArray contract.
//!
//! Ensures the Rust compiler successfully compiles a contract with a
//! nested `[[Bigint; 2]; 2]` property and the assembler regroups the
//! four synthetic leaves back into a single nested state field.

use runar_compiler_rust::compile_from_source_str;

const SOURCE: &str = include_str!("Grid2x2.v2.runar.rs");

#[test]
fn test_grid2x2_compile_check() {
    runar::compile_check(SOURCE, "Grid2x2.v2.runar.rs").unwrap();
}

#[test]
fn test_grid2x2_compiles() {
    let artifact = compile_from_source_str(SOURCE, Some("Grid2x2.v2.runar.rs"))
        .expect("grid2x2 compile");
    assert!(!artifact.script.is_empty());
}

#[test]
fn test_grid2x2_state_field_is_nested_fixed_array() {
    let artifact = compile_from_source_str(SOURCE, Some("Grid2x2.v2.runar.rs"))
        .expect("grid2x2 compile");
    let grid = artifact
        .state_fields
        .iter()
        .find(|f| f.name == "grid")
        .expect("grid state field must exist");
    assert_eq!(grid.field_type, "FixedArray<FixedArray<bigint, 2>, 2>");
    let fa = grid
        .fixed_array
        .as_ref()
        .expect("grid must carry fixed_array metadata");
    assert_eq!(fa.length, 2);
    assert_eq!(fa.element_type, "FixedArray<bigint, 2>");
    assert_eq!(
        fa.synthetic_names,
        vec![
            "grid__0__0".to_string(),
            "grid__0__1".to_string(),
            "grid__1__0".to_string(),
            "grid__1__1".to_string(),
        ]
    );
}
