//! F-286 — verifyRabinSig's public key (4th argument) must come from the
//! contract, not the spender.
//!
//! A spender who picks the Rabin modulus forges any message (`n = 1`,
//! `sig = 0` passes real `Spend`). The rule (user decision R78): the 4th
//! argument must be a contract property or a bigint literal, followed through
//! local aliases (init + every assignment) and through private helpers whose
//! parameter is bound to such a value at EVERY call site. Anything else is
//! refused with the one diagnostic every tier emits.
//!
//! What this proves: the Rust tier's validator refuses the spender-chosen
//! shapes below and accepts the deployer-fixed shapes, with the TS reference's
//! exact text, on the TS surface, the .runar.rs surface, and every one of the
//! nine conformance/negatives fixtures N220-N228.
//! What it does NOT prove: the other tiers (their own suites and the
//! cross-tier rejection-parity gate cover that), or that a hostile `--ir`
//! JSON cannot name a parameter as the modulus (`--ir` skips the frontend).

use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::validator::validate;

const MSG: &str = "verifyRabinSig public key (4th argument) must be a contract property or a literal; \
a spender-supplied Rabin modulus lets anyone forge a signature";

fn errors(src: &str, file: &str) -> Vec<String> {
    let parsed = parse_source(src, Some(file));
    assert!(parsed.errors.is_empty(), "unexpected parse errors in {}: {:?}", file, parsed.errors);
    let contract = parsed.contract.expect("expected a contract node");
    validate(&contract).errors.iter().map(|d| d.message.clone()).collect()
}

const HELPER: &str = "
  private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }";

const CHAIN: &str = "
  private outer(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    const kk = k;
    return this.inner(m, s, p, kk);
  }
  private inner(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }";

fn wrap(extra_params: &str, body: &str, extra_methods: &str) -> String {
    format!(
        "import {{ SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig }} from 'runar-lang';

class C extends SmartContract {{
  readonly pk: RabinPubKey;
  readonly pk2: RabinPubKey;

  constructor(pk: RabinPubKey, pk2: RabinPubKey) {{
    super(pk, pk2);
    this.pk = pk;
    this.pk2 = pk2;
  }}

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString{}) {{
{}
  }}
{}
}}
",
        extra_params, body, extra_methods
    )
}

#[test]
fn f286_refuses_spender_chosen_modulus_shapes() {
    let p = ", n: RabinPubKey";
    let cases: Vec<(&str, String)> = vec![
        ("public method parameter", wrap(p, "    assert(verifyRabinSig(msg, sig, padding, n));", "")),
        ("const alias of a parameter", wrap(p, "    const k = n;\n    assert(verifyRabinSig(msg, sig, padding, k));", "")),
        (
            "let alias reassigned from a parameter",
            wrap(p, "    let k = this.pk;\n    k = n;\n    assert(verifyRabinSig(msg, sig, padding, k));", ""),
        ),
        ("helper bound to a public parameter", wrap(p, "    assert(this.check(msg, sig, padding, n));", HELPER)),
        (
            "helper bound to a property at one site and a parameter at another",
            wrap(
                p,
                "    assert(this.check(msg, sig, padding, this.pk));\n    assert(this.check(msg, sig, padding, n));",
                HELPER,
            ),
        ),
        ("ternary", wrap(p, "    assert(verifyRabinSig(msg, sig, padding, sig > 0n ? this.pk : n));", "")),
        ("arithmetic on a property", wrap("", "    assert(verifyRabinSig(msg, sig, padding, this.pk + 1n));", "")),
        (
            "parameter in a for loop nested in an if",
            wrap(
                p,
                "    if (sig > 0n) {\n      for (let i = 0n; i < 2n; i++) {\n        assert(verifyRabinSig(msg, sig, padding, n));\n      }\n    }\n    assert(true);",
                "",
            ),
        ),
    ];
    for (label, src) in cases {
        let errs = errors(&src, "C.runar.ts");
        assert!(errs.iter().any(|e| e == MSG), "{}: expected the F-286 refusal, got {:?}", label, errs);
    }
}

#[test]
fn f286_accepts_deployer_fixed_modulus_shapes() {
    let cases: Vec<(&str, String)> = vec![
        ("this.<prop>", wrap("", "    assert(verifyRabinSig(msg, sig, padding, this.pk));", "")),
        ("bigint literal", wrap("", "    assert(verifyRabinSig(msg, sig, padding, 1000003n));", "")),
        ("const alias of a property", wrap("", "    const k = this.pk;\n    assert(verifyRabinSig(msg, sig, padding, k));", "")),
        (
            "let alias reassigned only from properties",
            wrap(
                "",
                "    let k = this.pk;\n    if (sig > 0n) {\n      k = this.pk2;\n    }\n    assert(verifyRabinSig(msg, sig, padding, k));",
                "",
            ),
        ),
        (
            "helper bound to a property at every call site",
            wrap(
                "",
                "    assert(this.check(msg, sig, padding, this.pk));\n    assert(this.check(msg, sig, padding, this.pk2));",
                HELPER,
            ),
        ),
        ("two-level helper chain", wrap("", "    assert(this.outer(msg, sig, padding, this.pk));", CHAIN)),
    ];
    for (label, src) in cases {
        let errs = errors(&src, "C.runar.ts");
        assert!(errs.is_empty(), "{}: expected no errors, got {:?}", label, errs);
    }
}

fn rs_contract(params: &str, key: &str) -> String {
    format!(
        "use runar::prelude::*;

#[runar::contract]
pub struct C {{
    #[readonly]
    pub pk: RabinPubKey,
}}

impl C {{
    pub fn settle(&self, msg: ByteString, sig: RabinSig, padding: ByteString{}) {{
        assert!(verify_rabin_sig(&msg, sig, padding, &{}));
    }}
}}
",
        params, key
    )
}

#[test]
fn f286_rust_surface_property_accepted_parameter_refused() {
    assert!(errors(&rs_contract("", "self.pk"), "C.runar.rs").is_empty());
    let errs = errors(&rs_contract(", n: RabinPubKey", "n"), "C.runar.rs");
    assert!(errs.iter().any(|e| e == MSG), "got {:?}", errs);
}

#[test]
fn f286_every_surface_negative_fixture_is_refused() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/negatives");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).expect("negatives dir") {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.contains("-rabin-pubkey-param.runar.") {
            continue;
        }
        seen += 1;
        let src = std::fs::read_to_string(&path).unwrap();
        let errs = errors(&src, &name);
        assert!(errs.iter().any(|e| e == MSG), "{}: expected the F-286 refusal, got {:?}", name, errs);
    }
    assert_eq!(seen, 9, "expected the nine N220-N228 fixtures");
}
