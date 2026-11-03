//! Unit tests for the nested Grid2x2 FixedArray contract.
//!
//! Ensures the Rust compiler successfully compiles a contract with a
//! nested `[[Bigint; 2]; 2]` property and the assembler regroups the
//! four synthetic leaves back into a single nested state field.
//!
//! N-122: `Grid2x2` is already `pub struct` with `pub` fields, so beyond the
//! compile checks below it is also run as native Rust via `#[path] mod
//! contract;` to exercise the actual literal-index writes.

#[path = "Grid2x2.v2.runar.rs"]
mod contract;

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

// N-122: the tests above only prove the COMPILED artifact's shape. These run
// the contract as native Rust: each literal-index setter must write its own
// cell and leave the other three untouched, and `init` must reset all four.
#[test]
fn native_literal_index_writes_touch_only_their_own_cell() {
    let mut c = contract::Grid2x2 { grid: [[0, 0], [0, 0]], tx_preimage: vec![] };
    c.set00(5);
    assert_eq!(c.grid, [[5, 0], [0, 0]]);
    c.set01(6);
    assert_eq!(c.grid, [[5, 6], [0, 0]]);
    c.set10(7);
    assert_eq!(c.grid, [[5, 6], [7, 0]]);
    c.set11(8);
    assert_eq!(c.grid, [[5, 6], [7, 8]]);
    // read00 asserts grid[0][0] == grid[0][0] -- must not panic and must not
    // mutate.
    c.read00();
    assert_eq!(c.grid, [[5, 6], [7, 8]]);
}

#[test]
fn native_init_resets_every_cell() {
    let mut c = contract::Grid2x2 { grid: [[5, 6], [7, 8]], tx_preimage: vec![] };
    c.init();
    assert_eq!(c.grid, [[0, 0], [0, 0]]);
}
