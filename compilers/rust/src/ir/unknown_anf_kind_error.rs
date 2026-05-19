//! Typed error raised by ANF / Stack-IR / constant-fold dispatch sites when
//! they encounter an `ANFValue` kind they don't recognize.
//!
//! In the Rust tier, `ANFValue` is a closed `enum`, so exhaustive `match`
//! arms are already a compile-time guard against an unhandled variant.
//! However, several dispatchers in `frontend/anf_optimize.rs` and
//! `frontend/anf_lower.rs` historically used `matches!(...)` as a positive
//! filter for a small subset of variants with a silent `_ => false` default.
//! That pattern compiles cleanly even when a new variant is added, so an
//! unrecognised kind would silently fall into the default and corrupt
//! dead-binding elimination / branch-flattening decisions.
//!
//! Every former silent default in these dispatchers is now an exhaustive
//! `match` whose unknown-kind arm panics with this error. The error name +
//! location mirror the TS `UnknownANFKindError` (see
//! `packages/runar-ir-schema/src/unknown-anf-kind-error.ts`) so the
//! cross-tier regression guard ships the same diagnostic surface.

use std::fmt;

/// Typed error for an unrecognised ANF value kind seen at a dispatch site.
#[derive(Debug, Clone)]
pub struct UnknownAnfKindError {
    pub kind: String,
    pub location: String,
}

impl UnknownAnfKindError {
    pub fn new(kind: impl Into<String>, location: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            location: location.into(),
        }
    }
}

impl fmt::Display for UnknownAnfKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown ANF kind '{}' encountered in {} — if you added a new ANFValue variant, update all dispatch sites (see CLAUDE.md § Adding a New ANF Value Kind)",
            self.kind, self.location
        )
    }
}

impl std::error::Error for UnknownAnfKindError {}
