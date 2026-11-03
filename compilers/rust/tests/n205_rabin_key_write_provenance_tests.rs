//! N-205 (a) — a stateful method must not write a spender-supplied value into
//! a MUTABLE property that verifyRabinSig uses as its public key.
//!
//! A mutable key property is state the previous spend chose: `this.key =
//! newKey` (or `newKey` in the key's `addOutput` slot) lets a spender set the
//! next UTXO's modulus to 1 and forge any message one spend later. Rule (user
//! decision R80, TS reference `checkRabinPubKeyProvenance`): properties whose
//! value reaches a verifyRabinSig 4th argument are KEY properties, closed
//! under "is written into a key property"; outside the constructor a mutable
//! key property may only be written (assignment, compound assignment, ++/--,
//! addOutput slot) with a value F-286 trusts.
//!
//! What this proves: the Rust tier's validator refuses the write shapes below
//! with the TS reference's exact text and accepts the deployer-fixed shapes,
//! on the TS surface, the .runar.rs surface and the bare-name Solidity write.
//! What it does NOT prove: the other tiers, or the `--ir` path (the loader's
//! rule is covered by conformance/negatives/ir-rabin-key-provenance.test.ts
//! and the unit tests in src/ir/rabin_key_provenance.rs).

use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::validator::validate;

fn msg(prop: &str) -> String {
    format!(
        "verifyRabinSig public key property '{}' may only be assigned a contract property or a literal \
outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature",
        prop
    )
}

fn errors(src: &str, file: &str) -> Vec<String> {
    let parsed = parse_source(src, Some(file));
    assert!(parsed.errors.is_empty(), "unexpected parse errors in {}: {:?}", file, parsed.errors);
    let contract = parsed.contract.expect("expected a contract node");
    validate(&contract).errors.iter().map(|d| d.message.clone()).collect()
}

fn wrap(rotate_body: &str, extra_methods: &str, settle_check: &str) -> String {
    format!(
        "import {{ StatefulSmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig }} from 'runar-lang';

class C extends StatefulSmartContract {{
  key: RabinPubKey;
  other: RabinPubKey;
  count: bigint;
  readonly backup: RabinPubKey;

  constructor(key: RabinPubKey, other: RabinPubKey, count: bigint, backup: RabinPubKey) {{
    super(key, other, count, backup);
    this.key = key;
    this.other = other;
    this.count = count;
    this.backup = backup;
  }}

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {{
    assert({});
  }}

  public rotate(newKey: RabinPubKey, n: bigint) {{
{}
    assert(true);
  }}
{}
}}
",
        settle_check, rotate_body, extra_methods
    )
}

const DIRECT: &str = "verifyRabinSig(msg, sig, padding, this.key)";

const SETTER: &str = "
  private setKey(v: RabinPubKey): void {
    this.key = v;
  }";

const CHECK: &str = "
  private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }";

#[test]
fn n205_refuses_spender_chosen_key_writes() {
    let cases: Vec<(&str, String, &str)> = vec![
        ("assigned a public parameter", wrap("    this.key = newKey;", "", DIRECT), "key"),
        ("assigned a const alias of a parameter", wrap("    const k = newKey;\n    this.key = k;", "", DIRECT), "key"),
        ("compound assignment from a parameter", wrap("    this.key += n;", "", DIRECT), "key"),
        ("incremented", wrap("    this.key++;", "", DIRECT), "key"),
        ("assigned inside an if", wrap("    if (n > 0n) {\n      this.key = newKey;\n    }", "", DIRECT), "key"),
        (
            "passed a parameter in its addOutput slot",
            wrap("    this.addOutput(1000n, newKey, this.other, this.count);", "", DIRECT),
            "key",
        ),
        ("written by a private setter fed a parameter", wrap("    this.setKey(newKey);", SETTER, DIRECT), "key"),
        (
            "key reached through a private helper, then written from a parameter",
            wrap("    this.key = newKey;", CHECK, "this.check(msg, sig, padding, this.key)"),
            "key",
        ),
        (
            "a property that feeds the key is itself written from a parameter",
            wrap("    this.key = this.other;\n    this.other = newKey;", "", DIRECT),
            "other",
        ),
    ];
    for (label, src, prop) in cases {
        let errs = errors(&src, "C.runar.ts");
        assert!(errs.iter().any(|e| *e == msg(prop)), "{}: expected the N-205 refusal, got {:?}", label, errs);
    }
}

#[test]
fn n205_accepts_deployer_fixed_key_writes() {
    let cases: Vec<(&str, String)> = vec![
        ("assigned a bigint literal", wrap("    this.key = 1000003n;", "", DIRECT)),
        ("assigned a readonly property", wrap("    this.key = this.backup;", "", DIRECT)),
        (
            "assigned another property that is only written from literals",
            wrap("    this.key = this.other;\n    this.other = 7n;", "", DIRECT),
        ),
        ("non-key state written from a parameter", wrap("    this.count = this.count + n;", "", DIRECT)),
        ("non-Rabin mutable property written from a parameter", wrap("    this.other = newKey;", "", DIRECT)),
        ("the key in its own addOutput slot", wrap("    this.addOutput(1000n, this.key, this.other, n);", "", DIRECT)),
        ("private setter fed a property at every call site", wrap("    this.setKey(this.backup);", SETTER, DIRECT)),
    ];
    for (label, src) in cases {
        let errs = errors(&src, "C.runar.ts");
        assert!(errs.is_empty(), "{}: expected no errors, got {:?}", label, errs);
    }
}

fn rs_contract(value: &str) -> String {
    format!(
        "use runar::prelude::*;

#[runar::stateful_contract]
pub struct C {{
    pub key: RabinPubKey,
}}

impl C {{
    pub fn settle(&self, msg: ByteString, sig: RabinSig, padding: ByteString) {{
        assert!(verify_rabin_sig(&msg, sig, padding, &self.key));
    }}
    pub fn rotate(&mut self, new_key: RabinPubKey) {{
        self.key = {};
        assert!(true);
    }}
}}
",
        value
    )
}

#[test]
fn n205_rust_surface_literal_accepted_parameter_refused() {
    assert!(errors(&rs_contract("1000003"), "C.runar.rs").is_empty());
    let errs = errors(&rs_contract("new_key"), "C.runar.rs");
    assert!(errs.iter().any(|e| *e == msg("key")), "got {:?}", errs);
}

fn sol_contract(lhs: &str, value: &str) -> String {
    format!(
        "pragma runar ^0.1.0;
contract C is StatefulSmartContract {{
    RabinPubKey key;
    constructor(RabinPubKey _key) {{ key = _key; }}
    function settle(bytes msg, RabinSig sig, bytes padding) public {{
        require(verifyRabinSig(msg, sig, padding, this.key));
    }}
    function rotate(RabinPubKey newKey) public {{
        {} = {};
        require(true);
    }}
}}",
        lhs, value
    )
}

#[test]
fn n205_sol_surface_this_and_bare_writes() {
    for lhs in ["this.key", "key"] {
        assert!(errors(&sol_contract(lhs, "1000003"), "C.runar.sol").is_empty(), "{} literal", lhs);
        let errs = errors(&sol_contract(lhs, "newKey"), "C.runar.sol");
        assert!(errs.iter().any(|e| *e == msg("key")), "{} = newKey: got {:?}", lhs, errs);
    }
}
