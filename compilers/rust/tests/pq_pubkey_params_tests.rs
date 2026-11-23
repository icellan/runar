//! PQ-F1: the artifact lists every constructor param passed directly as the
//! public key of verifyWOTS / verifySLHDSA_SHA2_*, with the exact byte length
//! that verifier needs, so every SDK can refuse a wrong-length key before
//! deploying (stateless artifacts carry no ANF to walk).
//!
//! Proves: the exact JSON text of `pqPubKeyParams` (key order included) for a
//! stateless WOTS contract, an SLH-DSA-192f contract, and a key behind a local
//! alias plus a key read in a private helper; absent for a key passed as a
//! method argument.
//! Does not prove: cross-tier equality (conformance/negatives/artifact-flag-parity.test.ts).

use runar_compiler_rust::compile_from_source_str;

fn pq_json(src: &str) -> Option<String> {
    let art = compile_from_source_str(src, Some("C.runar.ts")).expect("compile");
    // Serialize the artifact itself (not via serde_json::Value, which sorts
    // keys) so the key order the CLI writes is what is checked.
    let text = serde_json::to_string(&art).unwrap();
    let start = text.find("\"pqPubKeyParams\":")? + "\"pqPubKeyParams\":".len();
    let end = start + text[start..].find(']')? + 1;
    Some(text[start..end].to_string())
}

#[test]
fn pq_f1_stateless_wots() {
    assert_eq!(
        pq_json(r#"import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
class C extends SmartContract {
  readonly pk: ByteString;
  constructor(pk: ByteString) { super(pk); this.pk = pk; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pk)); }
}"#).as_deref(),
        Some(r#"[{"index":0,"name":"pk","scheme":"verifyWOTS","length":64}]"#)
    );
}

#[test]
fn pq_f1_slh_192f() {
    assert_eq!(
        pq_json(r#"import { SmartContract, ByteString, assert, verifySLHDSA_SHA2_192f } from 'runar-lang';
class C extends SmartContract {
  readonly pk: ByteString;
  constructor(pk: ByteString) { super(pk); this.pk = pk; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifySLHDSA_SHA2_192f(msg, sig, this.pk)); }
}"#).as_deref(),
        Some(r#"[{"index":0,"name":"pk","scheme":"verifySLHDSA_SHA2_192f","length":48}]"#)
    );
}

#[test]
fn pq_f1_alias_and_helper() {
    assert_eq!(
        pq_json(r#"import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
class C extends SmartContract {
  readonly tag: bigint;
  readonly a: ByteString;
  readonly b: ByteString;
  constructor(tag: bigint, a: ByteString, b: ByteString) { super(tag, a, b); this.tag = tag; this.a = a; this.b = b; }
  private checkB(msg: ByteString, sig: ByteString): boolean { return verifyWOTS(msg, sig, this.b); }
  public spend(msg: ByteString, sig: ByteString, sig2: ByteString) {
    assert(this.checkB(msg, sig2));
    const k = this.a;
    assert(verifyWOTS(msg, sig, k));
    assert(this.tag > 0n);
  }
}"#).as_deref(),
        Some(r#"[{"index":1,"name":"a","scheme":"verifyWOTS","length":64},{"index":2,"name":"b","scheme":"verifyWOTS","length":64}]"#)
    );
}

#[test]
fn pq_f1_key_as_method_arg_is_absent() {
    assert_eq!(
        pq_json(r#"import { SmartContract, ByteString, Sha256, assert, sha256, verifyWOTS } from 'runar-lang';
class C extends SmartContract {
  readonly h: Sha256;
  constructor(h: Sha256) { super(h); this.h = h; }
  public spend(msg: ByteString, sig: ByteString, pk: ByteString) { assert(sha256(pk) === this.h); assert(verifyWOTS(msg, sig, pk)); }
}"#),
        None
    );
}
