//! N-321: typecheck diagnostics must not echo an unbounded type text.
//!
//! What this proves: a 1 MB flat type name yields typecheck diagnostics capped
//! at 1024 bytes plus the `...(N more bytes elided)` marker, and an ordinary
//! type is echoed verbatim. What it does NOT prove: the other tiers
//! (conformance/negatives/n321-diagnostic-type-echo-parity.test.ts) nor each
//! echo site individually (the cap sits at the diagnostic sink).

use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::typecheck::typecheck;

const HEAD: &str = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint) {\n let q: {T} = a;\n assert(q == this.t);\n }\n}\n";

fn messages(typ: &str) -> Vec<String> {
    let res = parse_source(&HEAD.replace("{T}", typ), Some("P.runar.ts"));
    let mut out: Vec<String> = res.errors.iter().map(|d| d.format_message()).collect();
    if let Some(c) = res.contract.as_ref() {
        out.extend(typecheck(c).error_strings());
    }
    out
}

#[test]
fn huge_type_text_is_elided() {
    let msgs = messages(&"T".repeat(1 << 20));
    let echoing: Vec<_> = msgs.iter().filter(|m| m.contains("TTTT")).collect();
    assert!(!echoing.is_empty(), "no diagnostic echoed the type: {:?}", msgs.len());
    for m in echoing {
        assert!(m.len() < 1100, "diagnostic is {} bytes", m.len());
        assert!(m.ends_with("more bytes elided)") && m.contains("...("), "no marker");
    }
}

#[test]
fn ordinary_type_text_is_unchanged() {
    assert!(messages("ByteString").join("\n").contains("'ByteString'"));
}
