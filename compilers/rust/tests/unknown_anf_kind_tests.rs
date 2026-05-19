//! F-003 regression guard for the Rust tier.
//!
//! `ANFValue` in the Rust tier is a closed `enum` with `#[serde(tag =
//! "kind")]`, so the failure mode the TS / Go / Python tiers face — a
//! silent `default:` arm in a dispatcher swallowing a brand-new kind —
//! cannot exist by construction:
//!
//!   * **Serde deserialisation** rejects unknown JSON `"kind"` tags at
//!     load time (see `ir::loader::tests::test_load_ir_unknown_kind_in_json`).
//!   * **Pattern matching** on the closed enum is exhaustive — every
//!     dispatcher (`collect_refs`, `lower_binding`, `fold_value`,
//!     `collect_refs_from_value`, `remap_value_refs`, `kind_name`) lists
//!     each variant explicitly; adding a new variant breaks the build
//!     until the developer wires it through every site.
//!   * **Filter-style predicates** (`has_side_effect`,
//!     `is_side_effect_free`) use `matches!(...)` over the side-effecting
//!     subset with a `_ => false` default — but `false` is the SAFE
//!     default here (a new variant is treated as side-effecting / not
//!     pure, so DCE and branch-flattening never silently discard it).
//!
//! The shared `UnknownAnfKindError` type still ships in the Rust tier
//! for two reasons:
//!
//!   1. Cross-tier diagnostic parity: any future Rust dispatcher that
//!      cannot use the closed enum (e.g. an `IR -> JSON` round-trip
//!      that bypasses serde) needs the same error name + Display string
//!      as the TS `UnknownANFKindError`.
//!   2. Documentation: the error type's doc comment is the canonical
//!      record of WHY exhaustive matches are the Rust tier's primary
//!      F-003 mechanism.
//!
//! This test file pins the public API of `UnknownAnfKindError` so any
//! drift between the seven tiers' diagnostic surfaces is caught here.

use runar_compiler_rust::ir::UnknownAnfKindError;

const SYNTHETIC_KIND: &str = "synthetic_test_kind_for_regression_only";

#[test]
fn unknown_anf_kind_error_display_carries_kind_and_location() {
    let err = UnknownAnfKindError::new(SYNTHETIC_KIND, "unit-test.location");
    let msg = format!("{}", err);
    assert!(
        msg.contains(SYNTHETIC_KIND),
        "message should name the kind, got: {msg}"
    );
    assert!(
        msg.contains("unit-test.location"),
        "message should name the location, got: {msg}"
    );
    assert!(
        msg.contains("Adding a New ANF Value Kind"),
        "message should reference the developer recipe, got: {msg}"
    );
}

#[test]
fn unknown_anf_kind_error_constructor_accepts_owned_strings() {
    let err = UnknownAnfKindError::new(SYNTHETIC_KIND.to_string(), "x".to_string());
    assert_eq!(err.kind, SYNTHETIC_KIND);
    assert_eq!(err.location, "x");
}

#[test]
fn unknown_anf_kind_error_constructor_accepts_str_slices() {
    let err = UnknownAnfKindError::new(SYNTHETIC_KIND, "anf-lower.remapValueRefs");
    assert_eq!(err.kind, SYNTHETIC_KIND);
    assert_eq!(err.location, "anf-lower.remapValueRefs");
}

#[test]
fn unknown_anf_kind_error_implements_std_error() {
    let err = UnknownAnfKindError::new(SYNTHETIC_KIND, "x");
    // Boxing into `dyn Error` proves the trait is satisfied.
    let boxed: Box<dyn std::error::Error> = Box::new(err);
    assert!(format!("{}", boxed).contains(SYNTHETIC_KIND));
}

#[test]
fn unknown_anf_kind_error_implements_clone_and_debug() {
    let err = UnknownAnfKindError::new(SYNTHETIC_KIND, "x");
    let cloned = err.clone();
    assert_eq!(cloned.kind, err.kind);
    assert_eq!(cloned.location, err.location);
    let dbg = format!("{:?}", err);
    assert!(dbg.contains(SYNTHETIC_KIND), "Debug should include kind, got: {dbg}");
}

#[test]
fn unknown_anf_kind_error_panic_payload_round_trip() {
    // Documents the canonical way the Rust tier raises this error: panic
    // with the typed error as the payload. Mirrors how the TS tier throws
    // `new UnknownANFKindError(kind, location)`.
    let result = std::panic::catch_unwind(|| {
        panic!(
            "{}",
            UnknownAnfKindError::new(SYNTHETIC_KIND, "anf-optimize.has_side_effect")
        );
    });
    let payload = result.expect_err("expected panic");
    let msg = if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else {
        panic!("unexpected panic payload type");
    };
    assert!(msg.contains(SYNTHETIC_KIND), "panic msg should name kind, got: {msg}");
    assert!(
        msg.contains("anf-optimize.has_side_effect"),
        "panic msg should name dispatch site, got: {msg}"
    );
    assert!(
        msg.contains("Adding a New ANF Value Kind"),
        "panic msg should reference the developer recipe, got: {msg}"
    );
}
