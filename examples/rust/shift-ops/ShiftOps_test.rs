#[path = "ShiftOps.runar.rs"]
mod contract;

use contract::*;

#[test]
fn test_shift() {
    let c = ShiftOps { a: 16 };
    c.test_shift();
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("ShiftOps.runar.rs"),
        "ShiftOps.runar.rs",
    )
    .unwrap();
}
