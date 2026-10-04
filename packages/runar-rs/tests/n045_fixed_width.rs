//! N-045 (EXT-2 WideHash), SDK side — defence in depth only.
//!
//! The on-chain state reader slices each fixed-width byte field at its
//! declared width, so a wrong-width value in a state section shifts every
//! later field. The consensus defence is the covenant's own
//! `OP_SIZE <width> OP_NUMEQUALVERIFY` before each continuation commit (proved
//! under strict Spend in
//! packages/runar-testing/src/__tests__/n045-state-fixed-width-spend.test.ts).
//! These tests pin the off-chain refusals: `serialize_state` and
//! `prepare_call` reject a wrong-width fixed-width value. (Constructor args are
//! deliberately NOT checked: `from_utxo` builds its contract with placeholder
//! constructor args. A mutable field's deploy-time value still goes through
//! `serialize_state`.) They prove nothing on chain.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use runar_lang::sdk::state::serialize_state;
use runar_lang::sdk::types::{Abi, AbiConstructor, AbiMethod, AbiParam, RunarArtifact, StateField};
use runar_lang::sdk::{MockProvider, MockSigner, RunarContract, SdkValue, Utxo};

const TYPES: &[(&str, usize)] = &[
    ("PubKey", 33), ("Sha256", 32), ("Ripemd160", 20), ("Addr", 20),
    ("Point", 64), ("P256Point", 64), ("P384Point", 96),
];

fn panic_message<F: FnOnce() -> R, R>(f: F) -> Option<String> {
    let r = catch_unwind(AssertUnwindSafe(f));
    match r {
        Ok(_) => None,
        Err(e) => Some(
            e.downcast_ref::<String>().cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default(),
        ),
    }
}

fn field(t: &str) -> Vec<StateField> {
    vec![StateField { name: "k".into(), field_type: t.into(), index: 0, initial_value: None, fixed_array: None }]
}

#[test]
fn serialize_state_refuses_wrong_width() {
    for &(t, width) in TYPES {
        for bad in [width - 1, width + 1] {
            let mut v = HashMap::new();
            v.insert("k".to_string(), SdkValue::Bytes("ab".repeat(bad)));
            let msg = panic_message(|| serialize_state(&field(t), &v));
            assert!(
                msg.as_deref().is_some_and(|m| m.contains(&format!("must be exactly {width} bytes"))),
                "{t}: {bad} bytes not refused: {msg:?}"
            );
        }
        let mut v = HashMap::new();
        v.insert("k".to_string(), SdkValue::Bytes("zz".repeat(width)));
        let msg = panic_message(|| serialize_state(&field(t), &v));
        assert!(msg.as_deref().is_some_and(|m| m.contains("non-hex")), "{t}: non-hex not refused: {msg:?}");

        let mut v = HashMap::new();
        v.insert("k".to_string(), SdkValue::Bytes("ab".repeat(width)));
        assert_eq!(serialize_state(&field(t), &v), "ab".repeat(width), "{t}: exact width");
    }
}

fn root_artifact() -> RunarArtifact {
    let p = |n: &str, t: &str| AbiParam { name: n.into(), param_type: t.into(), fixed_array: None };
    RunarArtifact {
        version: "runar-v0.1.0".to_string(),
        contract_name: "N045Root".to_string(),
        parent_class: None,
        abi: Abi {
            constructor: AbiConstructor { params: vec![p("root", "Sha256")] },
            methods: vec![AbiMethod {
                name: "updateRoot".to_string(),
                params: vec![
                    p("nextRoot", "Sha256"),
                    p("_changePKH", "Ripemd160"),
                    p("_changeAmount", "bigint"),
                    p("txPreimage", "SigHashPreimage"),
                ],
                is_public: true,
                is_terminal: None,
                uses_code_part: None,
                sig_hash_type: None,
            }],
        },
        script: "51".to_string(),
        asm: None,
        state_fields: Some(field("Sha256").into_iter().map(|mut f| { f.name = "root".into(); f }).collect()),
        constructor_slots: None,
        code_sep_index_slots: None,
        code_separator_index: Some(0),
        code_separator_indices: None,
        anf: None,
        unsound_primitives: None,
    }
}

#[test]
fn prepare_call_refuses_wrong_width_sha256_arg() {
    for bad in [31usize, 33, 66] {
        // Reconnect to a (never broadcast) deployed output: the refusal must
        // fire before any UTXO is touched.
        let template = RunarContract::new(root_artifact(), vec![SdkValue::Bytes("11".repeat(32))]);
        let utxo = Utxo {
            txid: "bb".repeat(32),
            output_index: 0,
            satoshis: 10_000,
            script: template.get_locking_script(),
        };
        let mut contract = RunarContract::from_utxo(root_artifact(), &utxo).unwrap();
        let signer = MockSigner::new();
        let mut provider = MockProvider::new("testnet");
        let err = contract
            .prepare_call("updateRoot", &[SdkValue::Bytes("22".repeat(bad))], &mut provider, &signer, None)
            .expect_err("a wrong-width nextRoot must be refused");
        assert!(
            err.contains("arg 'nextRoot' (index 0)") && err.contains("must be exactly 32 bytes"),
            "{bad}-byte nextRoot: unexpected error {err}"
        );
    }
}
