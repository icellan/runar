//! #180 / #213 / D13: a public method's fixed-width parameter is pinned to its
//! declared width at entry (`<copy> OP_SIZE <w> OP_NUMEQUALVERIFY OP_DROP`),
//! except a PubKey that only ever reaches checkSig / checkMultiSig / hash160.
//! Port of the TypeScript reference pins (05-stack-lower.ts,
//! emitFixedWidthParamGate / paramNeedsWidthGate). The expected bytes are the
//! TS tier's output for the same sources, in both fold modes.

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

const LOCK_SRC: &str = r#"import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { Point } from 'runar-lang';
class Lock extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public lock(p: Point) {
    this.addRawOutput(1000n, cat(cat(toByteString('40'), p), toByteString('87')));
    this.n = this.n + 1n;
    this.addOutput(100000n, this.n);
  }
}
"#;

const PAY_TO_KEY_SRC: &str = r#"import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { PubKey } from 'runar-lang';
class PayToKey extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public pay(pk: PubKey) {
    this.addRawOutput(1000n, cat(cat(toByteString('21'), pk), toByteString('ac')));
    this.n = this.n + 1n;
    this.addOutput(100000n, this.n);
  }
}
"#;

const P2PKH_SRC: &str = r#"import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';
class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;
  constructor(pubKeyHash: Addr) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
"#;

const HELPER_P2PKH_SRC: &str = r#"import { SmartContract, assert, checkSig, hash160 } from 'runar-lang';
import type { PubKey, Sig, Addr } from 'runar-lang';
class HelperP2PKH extends SmartContract {
  readonly pkh: Addr;
  constructor(pkh: Addr) { super(pkh); this.pkh = pkh; }
  private verify(s: Sig, k: PubKey): boolean { return checkSig(s, k); }
  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pkh);
    assert(this.verify(sig, pubKey));
  }
}
"#;

fn hex(src: &str, file_name: &str, disable_fold: bool) -> String {
    let opts = CompileOptions { disable_constant_folding: disable_fold, ..Default::default() };
    compile_from_source_str_with_options(src, Some(file_name), &opts)
        .unwrap_or_else(|e| panic!("{file_name} (disable_fold={disable_fold}): {e}"))
        .script
        .to_lowercase()
}

/// Occurrences of `sub` that start on a byte boundary.
fn count_aligned(h: &str, sub: &str) -> usize {
    (0..h.len().saturating_sub(sub.len()) + 1)
        .step_by(2)
        .filter(|&i| &h[i..i + sub.len()] == sub)
        .count()
}

#[test]
fn prb_point_param_and_change_pkh_are_width_gated() {
    for disable in [true, false] {
        let h = hex(LOCK_SRC, "Lock.runar.ts", disable);
        assert!(
            h.contains(concat!("5379820140", "9d75", "5279820114", "9d75")),
            "disable_fold={disable}: missing Point + _changePKH entry gates: {h}"
        );
        for gate in ["8201409d", "8201149d"] {
            assert_eq!(count_aligned(&h, gate), 1, "disable_fold={disable}: {gate} count in {h}");
        }
    }
}

#[test]
fn prb_spliced_pubkey_is_width_gated() {
    for disable in [true, false] {
        let h = hex(PAY_TO_KEY_SRC, "PayToKey.runar.ts", disable);
        assert!(
            h.contains(concat!("5379820121", "9d75")),
            "disable_fold={disable}: missing PubKey entry gate: {h}"
        );
        assert_eq!(count_aligned(&h, "8201219d"), 1, "disable_fold={disable}: {h}");
    }
}

#[test]
fn prb_p2pkh_stays_on_standard_template() {
    for disable in [true, false] {
        assert_eq!(hex(P2PKH_SRC, "P2PKH.runar.ts", disable), "76a90088ac", "disable_fold={disable}");
    }
}

#[test]
fn prb_pubkey_verified_through_private_helper_is_not_gated() {
    for disable in [true, false] {
        let h = hex(HELPER_P2PKH_SRC, "HelperP2PKH.runar.ts", disable);
        assert!(!h.contains("8201219d"), "disable_fold={disable}: verified-only PubKey gated: {h}");
    }
}

const PICK_KEY_SRC: &str = r#"import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { PubKey } from 'runar-lang';
class PickKey extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public pay(pick: boolean, a: PubKey, b: PubKey) {
    const k = pick ? a : b;
    this.addRawOutput(1000n, cat(cat(toByteString('21'), k), toByteString('ac')));
    this.n = this.n + 1n;
    this.addOutput(100000n, this.n);
  }
}
"#;

const ID_KEY_SRC: &str = r#"import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { PubKey } from 'runar-lang';
class IdKey extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  private id(k: PubKey): PubKey { return k; }
  public pay(pk: PubKey) {
    this.addRawOutput(1000n, cat(cat(toByteString('21'), this.id(pk)), toByteString('ac')));
    this.n = this.n + 1n;
    this.addOutput(100000n, this.n);
  }
}
"#;

#[test]
fn prb_pubkey_through_ternary_arm_is_width_gated() {
    for disable in [true, false] {
        let h = hex(PICK_KEY_SRC, "PickKey.runar.ts", disable);
        assert_eq!(count_aligned(&h, "8201219d"), 2, "disable_fold={disable}: {h}");
    }
}

#[test]
fn prb_pubkey_returned_by_private_helper_is_width_gated() {
    for disable in [true, false] {
        let h = hex(ID_KEY_SRC, "IdKey.runar.ts", disable);
        assert_eq!(count_aligned(&h, "8201219d"), 1, "disable_fold={disable}: {h}");
    }
}

const MERGED_KEY_SRC: &str = r#"import { StatefulSmartContract, assert } from 'runar-lang';
import type { PubKey } from 'runar-lang';
class MergedKey extends StatefulSmartContract {
  closed: bigint = 0n;
  k: PubKey = "000000000000000000000000000000000000000000000000000000000000000000" as PubKey;
  amt: bigint = 0n;
  constructor(seed: bigint) { super(seed); this.closed = seed; }
  public bid(bidderKey: PubKey, bidAmount: bigint) {
    assert(this.closed === 0n);
    let nk = this.k;
    let namt = this.amt;
    if (this.amt === 0n) { nk = bidderKey; namt = bidAmount; }
    else { nk = bidderKey; namt = bidAmount + 1n; }
    this.addOutput(bidAmount, this.closed, nk, namt);
  }
}
"#;

#[test]
fn prb_cyclic_merged_local_alias_terminates_and_is_gated() {
    for disable in [true, false] {
        let h = hex(MERGED_KEY_SRC, "MergedKey.runar.ts", disable);
        assert!(h.contains(concat!("5479820121", "9d75")), "disable_fold={disable}: {h}");
        assert_eq!(count_aligned(&h, "8201219d"), 2, "disable_fold={disable}: {h}");
    }
}
