//! N-320: the state-reading paths must refuse a hostile script with an
//! error, never panic, hang or fabricate state.
//!
//! Replays `conformance/sdk-matches-artifact/hostile-state.json` — the N-317
//! hostile scripts of `hostile.json` with expected outcomes for
//! `extract_state_from_script`, `from_utxo` and `from_txid` (replayed by all
//! 7 SDKs) — plus `find_last_op_return` called directly on the non-ASCII
//! scripts, which sliced `&str` by byte index and panicked off a UTF-8 char
//! boundary.
//!
//! Proves: for each of the 30 scripts, `extract_state_from_script` on the
//! stateful artifact returns exactly the expected `Ok(Some(state))` /
//! `Ok(None)` / `Err`, and `from_utxo` and `from_txid` either reconnect or
//! return `Err` (never a panic) — an odd-length, non-hex or non-ASCII script
//! is refused before any reader runs, and a stateful artifact over a script
//! with no state section is refused (C10, as in TS) instead of carrying
//! constructor-initial state; `find_last_op_return` never panics on any of
//! the scripts; the replay stays inside a process-CPU budget.
//! Does NOT prove: on-chain spendability of a reconnected contract; artifact
//! shapes beyond the fixture's two; WHICH error text `Err` carries (this tier
//! has one error type, `String`).

use runar_lang::sdk::provider::MockProvider;
use runar_lang::sdk::types::{RunarArtifact, SdkValue, TransactionData, TxOutput, Utxo};
use runar_lang::sdk::{extract_state_from_script, find_last_op_return, RunarContract};
use serde_json::Value;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    fn clock_gettime(clk: i32, tp: *mut Timespec) -> i32;
}

#[cfg(target_os = "macos")]
const CLOCK_PROCESS_CPUTIME_ID: i32 = 12;
#[cfg(not(target_os = "macos"))]
const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;

fn process_cpu_secs() -> f64 {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let rc = unsafe { clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime failed");
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

const BUDGET_SECS: f64 = 20.0;

fn fixture(name: &str) -> Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../conformance/sdk-matches-artifact");
    p.push(name);
    serde_json::from_slice(&std::fs::read(p).expect("read fixture")).expect("parse fixture")
}

fn script_of(c: &Value) -> String {
    let repeat = c["repeat"].as_str().unwrap_or("");
    let count = c["count"].as_u64().unwrap_or(0) as usize;
    format!("{}{}{}", c["prefix"].as_str().unwrap(), repeat.repeat(count), c["suffix"].as_str().unwrap_or(""))
}

fn reconnected<T>(r: std::thread::Result<Result<T, String>>) -> String {
    match r {
        Ok(Ok(_)) => "ok".to_string(),
        Ok(Err(_)) => "malformed".to_string(),
        Err(_) => "panic".to_string(),
    }
}

fn replay() -> Vec<String> {
    let fx = fixture("hostile.json");
    let sfx = fixture("hostile-state.json");
    let cases = fx["cases"].as_array().expect("cases");
    let want = sfx["cases"].as_array().expect("cases");
    assert!(!cases.is_empty() && cases.len() == want.len(), "fixture mismatch");
    let artifact = |name: &str| -> RunarArtifact {
        serde_json::from_value(fx["artifacts"][name].clone()).expect("artifact")
    };
    let stateful = artifact("stateful");
    let mut provider = MockProvider::testnet();
    let mut diffs = Vec::new();
    for (i, (c, w)) in cases.iter().zip(want).enumerate() {
        let name = c["name"].as_str().unwrap();
        assert_eq!(w["name"].as_str(), Some(name), "case order");
        let script = script_of(c);
        let txid = format!("{:02x}", i).repeat(32);
        provider.add_transaction(TransactionData {
            txid: txid.clone(),
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput { satoshis: 1000, script: script.clone() }],
            locktime: 0,
            raw: None,
        });

        let state = match catch_unwind(AssertUnwindSafe(|| extract_state_from_script(&stateful, &script))) {
            Ok(Ok(None)) => Value::Null,
            Ok(Ok(Some(s))) => Value::Object(
                s.into_iter()
                    .map(|(k, v)| {
                        let v = match v {
                            SdkValue::Int(n) => n.to_string(),
                            SdkValue::BigInt(n) => n.to_string(),
                            other => format!("{other:?}"),
                        };
                        (k, Value::String(v))
                    })
                    .collect(),
            ),
            Ok(Err(_)) => Value::String("malformed".into()),
            Err(_) => Value::String("panic".into()),
        };
        if state != w["state"] {
            diffs.push(format!("extract_state_from_script {name}: want {}, got {state}", w["state"]));
        }

        let a = artifact(c["artifact"].as_str().unwrap());
        let utxo = Utxo { txid: txid.clone(), output_index: 0, satoshis: 1000, script: script.clone() };
        let got = reconnected(catch_unwind(AssertUnwindSafe(|| RunarContract::from_utxo(a.clone(), &utxo))));
        if got != w["fromUtxo"].as_str().unwrap() {
            diffs.push(format!("from_utxo {name}: want {}, got {got}", w["fromUtxo"]));
        }
        let got = reconnected(catch_unwind(AssertUnwindSafe(|| RunarContract::from_txid(a.clone(), &txid, 0, &provider))));
        if got != w["fromUtxo"].as_str().unwrap() {
            diffs.push(format!("from_txid {name}: want {}, got {got}", w["fromUtxo"]));
        }

        if catch_unwind(AssertUnwindSafe(|| find_last_op_return(&script))).is_err() {
            diffs.push(format!("find_last_op_return {name}: panicked"));
        }
    }
    diffs
}

#[test]
fn hostile_state_paths_n320() {
    let start = process_cpu_secs();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(replay());
    });
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(diffs) => {
                let used = process_cpu_secs() - start;
                assert!(used < BUDGET_SECS, "replay used {used:.2} s CPU (budget {BUDGET_SECS} s)");
                assert!(diffs.is_empty(), "{}", diffs.join("\n"));
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let used = process_cpu_secs() - start;
                assert!(used < BUDGET_SECS, "replay still running after {used:.2} s CPU (budget {BUDGET_SECS} s)");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!("replay thread died"),
        }
    }
}
