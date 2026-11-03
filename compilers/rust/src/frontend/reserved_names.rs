//! N-065 / N-060 — compiler-reserved names.
//!
//! Several passes mint names into the SAME namespace user identifiers live in,
//! and every later pass resolves a name by string equality, so a user name
//! spelled like a minted one aliases two different values (a local `t2`
//! shadowed by the ANF temp `t2` accepted a spend the source rejects).
//! Mirrors packages/runar-compiler/src/passes/reserved-names.ts exactly: the
//! same families and one sentence shared verbatim by all seven tiers.
//!
//!   ANF lowering        t<digits>, __merge$<digits>
//!   fixed-array expand  <name>__<digits>, __idx_<digits>, __val_<digits>
//!   stack lowering      _codePart, __param_<name>, __shadowed_<n>_<name>, _pub_<digits>
//!   auto-injected       _changePKH, _changeAmount, _newAmount, _serialisedOutputs,
//!                       _prevOutScript_<digits>, txPreimage (StatefulSmartContract only)
//!
//! Not reserved: `<name>@<n>` (no surface has `@` in identifiers), EC-optimizer
//! names (F-086 allocates them collision-free), codegen-private tracker names.

/// The diagnostic, shared verbatim by all seven tiers (source and --ir).
pub fn reserved_name_message(name: &str) -> String {
    format!("'{}' is reserved for compiler-generated names and cannot be used as an identifier", name)
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn prefix_digits(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).map_or(false, all_digits)
}

fn is_stack_lowering_reserved(name: &str) -> bool {
    name == "_codePart"
        || name.starts_with("__param_")
        || name.starts_with("__shadowed_")
        || prefix_digits(name, "_pub_")
}

fn is_anf_binding_reserved(name: &str) -> bool {
    prefix_digits(name, "t") || prefix_digits(name, "__merge$")
}

/// `^.+__[0-9]+$` — a FixedArray slot name.
fn is_array_slot_name(name: &str) -> bool {
    let head = name.trim_end_matches(|c: char| c.is_ascii_digit());
    head.len() < name.len() && head.len() > 2 && head.ends_with("__")
}

fn is_source_only_reserved(name: &str) -> bool {
    is_array_slot_name(name)
        || prefix_digits(name, "__idx_")
        || prefix_digits(name, "__val_")
        || matches!(name, "_changePKH" | "_changeAmount" | "_newAmount" | "_serialisedOutputs")
        || prefix_digits(name, "_prevOutScript_")
}

/// True if a SOURCE program may not declare `name` (after name mapping).
pub fn is_reserved_source_name(name: &str, stateful: bool) -> bool {
    is_stack_lowering_reserved(name)
        || is_anf_binding_reserved(name)
        || is_source_only_reserved(name)
        || (stateful && name == "txPreimage")
}

/// `--ir` rule: every position refuses stack lowering's slot names; a
/// declaration (property / method / parameter / loop variable, and the name a
/// load_param / load_prop / update_prop addresses) also refuses the ANF
/// binding families. Binding names and binding references may be ANF temps.
pub fn is_reserved_ir_name(name: &str, declaration: bool) -> bool {
    is_stack_lowering_reserved(name) || (declaration && is_anf_binding_reserved(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families() {
        for n in ["t0", "t12", "__merge$3", "x__0", "___5", "__idx_1", "__val_2", "_codePart",
                  "__param_x", "__shadowed_0_p", "_pub_4", "_changePKH", "_changeAmount",
                  "_newAmount", "_serialisedOutputs", "_prevOutScript_0"] {
            assert!(is_reserved_source_name(n, false), "{}", n);
        }
        for n in ["t", "ta", "t1a", "T1", "__5", "x__", "x_0", "__merge$", "__idx_", "_pub_",
                  "txPreimage", "codePart", "__while_no_init", "sum_"] {
            assert!(!is_reserved_source_name(n, false), "{}", n);
        }
        assert!(is_reserved_source_name("txPreimage", true));
        assert!(!is_reserved_ir_name("t3", false));
        assert!(is_reserved_ir_name("t3", true));
        assert!(!is_reserved_ir_name("__merge$0", false));
        assert!(is_reserved_ir_name("_codePart", false));
        assert!(!is_reserved_ir_name("txPreimage", true));
    }
}
