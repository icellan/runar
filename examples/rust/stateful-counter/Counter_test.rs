#[path = "Counter.runar.rs"]
mod contract;

use contract::*;

#[test]
fn test_increment() {
    let mut c = Counter { count: 0 };
    c.increment();
    assert_eq!(c.count, 1);
}

#[test]
fn test_increment_multiple() {
    let mut c = Counter { count: 0 };
    for _ in 0..10 { c.increment(); }
    assert_eq!(c.count, 10);
}

#[test]
fn test_decrement() {
    let mut c = Counter { count: 5 };
    c.decrement();
    assert_eq!(c.count, 4);
}

#[test]
fn test_decrement_to_zero() {
    let mut c = Counter { count: 1 };
    c.decrement();
    assert_eq!(c.count, 0);
}

#[test]
#[should_panic]
fn test_decrement_at_zero_fails() {
    Counter { count: 0 }.decrement();
}

#[test]
fn test_increment_then_decrement() {
    let mut c = Counter { count: 0 };
    c.increment();
    c.increment();
    c.increment();
    c.decrement();
    assert_eq!(c.count, 2);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("Counter.runar.rs"), "Counter.runar.rs").unwrap();
}
