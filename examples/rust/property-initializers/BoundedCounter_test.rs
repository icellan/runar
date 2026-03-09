#[path = "BoundedCounter.runar.rs"]
mod contract;

use contract::*;

// NOTE: Contracts with property initializers define an `init()` method that sets
// default values (e.g., count = 0, active = true). In native Rust tests, you must
// call `init()` after constructing the struct to apply these defaults — the Rust
// struct literal requires all fields, but `init()` overwrites them with the
// intended initial values. At compile time, the Rúnar compiler bakes these
// defaults directly into the Bitcoin Script.

#[test]
fn test_default_initializers() {
    let mut c = BoundedCounter { count: 0, max_count: 10, active: false };
    // Call init() to apply property initializer defaults
    c.init();
    assert_eq!(c.count, 0);
    assert_eq!(c.active, true);
    c.increment(1);
    assert_eq!(c.count, 1);
}

#[test]
fn test_increment() {
    let mut c = BoundedCounter { count: 0, max_count: 10, active: false };
    c.init();
    c.increment(3);
    assert_eq!(c.count, 3);
}

#[test]
#[should_panic]
fn test_rejects_increment_beyond_max() {
    let mut c = BoundedCounter { count: 0, max_count: 5, active: false };
    c.init();
    c.increment(6);
}

#[test]
fn test_reset() {
    let mut c = BoundedCounter { count: 0, max_count: 10, active: false };
    c.init();
    c.increment(7);
    assert_eq!(c.count, 7);
    c.reset();
    assert_eq!(c.count, 0);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("BoundedCounter.runar.rs"), "BoundedCounter.runar.rs").unwrap();
}
