//! NULLFAIL multi-method stateful contract regression test.
//!
//! Reproduces the BSV NULLFAIL (BIP 146) rule scenario: a stateful contract
//! where some public methods use `checkSig` and others don't. After UTXO
//! chain spends of the non-checkSig method, the transaction must still be
//! accepted — the dispatch shim must zero out the unused sig param so
//! OP_CHECKSIG sees an empty byte string when its branch is not taken.
//!
//! Mirrors `integration/ts/nullfail-multimethod.test.ts`. Compile + script-
//! integrity checks run by default; full chain-spend deploy/call is gated
//! on the `regtest` feature.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

const SOURCE: &str = r#"
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class MultiMethodContract extends StatefulSmartContract {
  stateRoot: ByteString;
  blockNumber: bigint;
  frozen: bigint;
  readonly governanceKey: PubKey;

  constructor(stateRoot: ByteString, blockNumber: bigint, frozen: bigint, governanceKey: PubKey) {
    super(stateRoot, blockNumber, frozen, governanceKey);
    this.stateRoot = stateRoot;
    this.blockNumber = blockNumber;
    this.frozen = frozen;
    this.governanceKey = governanceKey;
  }

  // Method 0: no checkSig — authorized by proof data
  public advanceState(newStateRoot: ByteString, newBlockNumber: bigint) {
    assert(this.frozen === 0n);
    assert(newBlockNumber > this.blockNumber);
    this.stateRoot = newStateRoot;
    this.blockNumber = newBlockNumber;
  }

  // Method 1: uses checkSig — governance-gated freeze
  public freeze(governanceSig: Sig) {
    assert(this.frozen === 0n);
    assert(checkSig(governanceSig, this.governanceKey));
    this.frozen = 1n;
  }
}
"#;

#[test]
fn test_nullfail_multimethod_compiles() {
    let artifact = compile_source(SOURCE, "MultiMethodContract.runar.ts");
    assert_eq!(artifact.contract_name, "MultiMethodContract");
    assert!(!artifact.script.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_nullfail_multimethod_chain_spends() {
    skip_if_no_node();

    let artifact = compile_source(SOURCE, "MultiMethodContract.runar.ts");

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);
    let governance = create_wallet();

    let initial_root = "00".repeat(32);
    let mut contract = RunarContract::new(
        artifact,
        vec![
            SdkValue::Bytes(initial_root),
            SdkValue::Int(0),
            SdkValue::Int(0),
            SdkValue::Bytes(governance.pub_key_hex.clone()),
        ],
    );

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 50_000,
            change_address: None,
        })
        .expect("deploy failed");

    // Chain three advanceState calls — these go through the non-checkSig
    // method, which is exactly the path that historically tripped the
    // NULLFAIL rule when the dispatch shim left the sig param non-empty.
    for i in 1..=3 {
        let new_root = format!("{:02x}", i).repeat(32);
        let (txid, _) = contract
            .call(
                "advanceState",
                &[
                    SdkValue::Bytes(new_root),
                    SdkValue::Int(i as i64),
                ],
                &mut provider,
                &*signer,
                None,
            )
            .unwrap_or_else(|e| panic!("advanceState #{i} failed: {e:?}"));
        assert!(!txid.is_empty(), "advanceState #{i}: empty txid");
    }
}
