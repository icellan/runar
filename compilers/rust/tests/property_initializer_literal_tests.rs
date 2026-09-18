//! Audit C3 — property initializers are restricted to literal values.
//!
//! `ts`, `go` and `java` enforced this; `rust`, `zig`, `python` and `ruby` did
//! not — they compiled e.g. `p: bigint = 1n + 2n;` and emitted a deployable
//! locking script for a program the language does not define.
//!
//! Mirrors `packages/runar-compiler/src/__tests__/property-initializer-literal.test.ts`.

use runar_compiler_rust::frontend_validate;

/// The cross-tier diagnostic substring.
const NON_LITERAL_INIT: &str = "initializer must be a literal value";

fn errors_of(source: &str) -> Vec<String> {
    let (errors, _warnings) = frontend_validate(source, Some("test.runar.ts"));
    errors
}

#[test]
fn rejects_arithmetic_property_initializer() {
    let source = r#"
import { StatefulSmartContract, Addr } from 'runar-lang';

class Bad extends StatefulSmartContract {
    count: bigint = 1n + 2n;
    readonly owner: Addr;

    constructor(owner: Addr) {
        super(owner);
        this.owner = owner;
    }

    public bump() {
        this.count = this.count + 1n;
    }
}
"#;
    let errors = errors_of(source);
    assert!(
        errors.iter().any(|e| e.contains(NON_LITERAL_INIT)),
        "expected a non-literal-initializer error, got: {errors:?}"
    );
}

#[test]
fn rejects_call_expression_property_initializer() {
    let source = r#"
import { StatefulSmartContract, Addr } from 'runar-lang';

class Bad2 extends StatefulSmartContract {
    count: bigint = abs(-3n);
    readonly owner: Addr;

    constructor(owner: Addr) {
        super(owner);
        this.owner = owner;
    }

    public bump() {
        this.count = this.count + 1n;
    }
}
"#;
    let errors = errors_of(source);
    assert!(
        errors.iter().any(|e| e.contains(NON_LITERAL_INIT)),
        "expected a non-literal-initializer error, got: {errors:?}"
    );
}

#[test]
fn accepts_literal_property_initializers() {
    let source = r#"
import { StatefulSmartContract, Addr, ByteString } from 'runar-lang';

class Good extends StatefulSmartContract {
    count: bigint = 7n;
    flag: boolean = true;
    tag: ByteString = 'deadbeef';
    offset: bigint = -3n;
    readonly owner: Addr;

    constructor(owner: Addr) {
        super(owner);
        this.owner = owner;
    }

    public bump() {
        this.count = this.count + 1n;
    }
}
"#;
    let errors = errors_of(source);
    assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
}

// ---------------------------------------------------------------------------
// `toByteString('<hex>')` IS the ByteStringLiteral production — see
// spec/grammar.md section 11:
//
//     ByteStringLiteral = 'toByteString' '(' StringLiteral ')' ;
//
// 0e192af6 folded it in ANF lowering, which covers every EXPRESSION position.
// A property INITIALIZER is not one: the validator runs on the AST, BEFORE ANF
// lowering, and still saw a call node. This tier needs the spelling most — the
// Rust DSL writes initializers as assignments inside `init()` that the parser
// LIFTS into `PropertyNode.initializer`, and a bare `"1976a914"` is a `&str`
// that cannot be assigned to a `ByteString` (`Vec<u8>`).
//
// Both halves are asserted: accepting it in the validator alone yields a
// property that validates and then loses its default, because
// `extract_literal_value` returns `None` for a call node.
// ---------------------------------------------------------------------------

const TO_BYTE_STRING_INIT: &str = r#"
import { SmartContract, Addr, ByteString, toByteString, assert } from 'runar-lang';

class Wrapped extends SmartContract {
    readonly prefix: ByteString = toByteString('1976a914');
    readonly owner: Addr;

    constructor(owner: Addr) {
        super(owner);
        this.owner = owner;
    }

    public unlock(x: ByteString) {
        assert(x === this.prefix);
    }
}
"#;

#[test]
fn accepts_to_byte_string_literal_property_initializer() {
    let errors = errors_of(TO_BYTE_STRING_INIT);
    assert!(
        errors.is_empty(),
        "expected no validation errors, got: {errors:?}"
    );
}

#[test]
fn unwraps_to_byte_string_literal_initializer_in_anf() {
    let wrapped = runar_compiler_rust::compile_source_str_to_ir(
        TO_BYTE_STRING_INIT,
        Some("test.runar.ts"),
    )
    .expect("wrapped spelling must compile to IR");

    let bare_source = TO_BYTE_STRING_INIT.replace("toByteString('1976a914')", "'1976a914'");
    let bare = runar_compiler_rust::compile_source_str_to_ir(&bare_source, Some("test.runar.ts"))
        .expect("bare spelling must compile to IR");

    // Half two: a bare value, not a call node and not a dropped default.
    assert_eq!(
        wrapped.properties[0].initial_value,
        Some(serde_json::Value::String("1976a914".to_string())),
        "expected the initializer to unwrap to a bare ByteString value"
    );

    // ...and the whole program is indistinguishable from the bare spelling,
    // which is what keeps expected-ir.json from moving.
    assert_eq!(
        serde_json::to_string(&wrapped).unwrap(),
        serde_json::to_string(&bare).unwrap(),
        "wrapped ANF must be byte-identical to the bare-literal ANF"
    );
}

#[test]
fn rejects_to_byte_string_non_literal_property_initializer() {
    // Not the ByteStringLiteral production — a real call, and a call is not a
    // literal. Guards the accept from widening into "any toByteString call".
    let source = r#"
import { SmartContract, Addr, ByteString, toByteString, assert } from 'runar-lang';

class Bad3 extends SmartContract {
    readonly prefix: ByteString = toByteString(someIdent);
    readonly owner: Addr;

    constructor(owner: Addr) {
        super(owner);
        this.owner = owner;
    }

    public unlock(x: ByteString) {
        assert(x === this.prefix);
    }
}
"#;
    let errors = errors_of(source);
    assert!(
        errors.iter().any(|e| e.contains(NON_LITERAL_INIT)),
        "expected a non-literal-initializer error, got: {errors:?}"
    );
}
