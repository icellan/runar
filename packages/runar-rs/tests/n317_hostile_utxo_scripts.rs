//! N-317: one hostile UTXO script must not take `TokenWallet::get_utxos`
//! down, and `matches_artifact` must agree with the TS SDK on every malformed
//! shape.
//!
//! Replays the shared cross-tier vector
//! `conformance/sdk-matches-artifact/hostile.json` (also replayed by the TS,
//! Go, Python, Zig, Ruby and Java SDKs): odd-length and non-hex scripts,
//! non-ASCII chars straddling a byte window, truncated OP_PUSHDATA1/2/4,
//! OP_PUSHDATA4 lengths with the high bit set, a push running past the slot,
//! empty and short scripts and ~1 MiB scripts, beside SDK-built genuine
//! instances.
//!
//! Proves: `matches_artifact` gives exactly the fixture's outcome per vector
//! (Ok(true) / Ok(false) / Err, never a panic); `get_utxos` keeps exactly the
//! genuine instances for a stateful and a stateless artifact and neither
//! errors nor panics; the replay stays inside a process-CPU budget
//! (clock_gettime, polled while a thread replays, as in the N-181 tests).
//! Does NOT prove: on-chain spendability of the kept UTXOs, artifact shapes
//! beyond the fixture's two, or anything about a forged codeSepIndex element
//! (N-318).

use runar_lang::sdk::matches_artifact;
use runar_lang::sdk::provider::MockProvider;
use runar_lang::sdk::signer::MockSigner;
use runar_lang::sdk::types::{RunarArtifact, Utxo};
use runar_lang::sdk::{Signer, TokenWallet};
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

/// Measured: well under a second of CPU after the fix (debug build).
const BUDGET_SECS: f64 = 20.0;

fn script_of(c: &Value) -> String {
    let repeat = c["repeat"].as_str().unwrap_or("");
    let count = c["count"].as_u64().unwrap_or(0) as usize;
    format!("{}{}{}", c["prefix"].as_str().unwrap(), repeat.repeat(count), c["suffix"].as_str().unwrap_or(""))
}

fn replay() -> Vec<String> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../conformance/sdk-matches-artifact/hostile.json");
    let fx: Value = serde_json::from_slice(&std::fs::read(p).expect("read fixture")).expect("parse fixture");
    let cases = fx["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    let artifact = |name: &str| -> RunarArtifact {
        serde_json::from_value(fx["artifacts"][name].clone()).expect("artifact")
    };
    let mut diffs = Vec::new();
    for c in cases {
        let a = artifact(c["artifact"].as_str().unwrap());
        let script = script_of(c);
        let got = match catch_unwind(AssertUnwindSafe(|| matches_artifact(&a, &script))) {
            Ok(Ok(true)) => "match".to_string(),
            Ok(Ok(false)) => "no_match".to_string(),
            Ok(Err(_)) => "malformed".to_string(),
            Err(_) => "panic".to_string(),
        };
        if got != c["matches"].as_str().unwrap() {
            diffs.push(format!("{}: want {}, got {}", c["name"].as_str().unwrap(), c["matches"], got));
        }
    }
    for name in fx["artifacts"].as_object().unwrap().keys() {
        let mut provider = MockProvider::testnet();
        let signer = MockSigner::new();
        let addr = signer.get_address().unwrap();
        let mut want = Vec::new();
        for (i, c) in cases.iter().enumerate() {
            if c["artifact"].as_str() != Some(name) || c["wallet"].is_null() {
                continue;
            }
            let txid = format!("{:02x}", i).repeat(32);
            provider.add_utxo(&addr, Utxo { txid: txid.clone(), output_index: 0, satoshis: 1000, script: script_of(c) });
            if c["wallet"].as_bool() == Some(true) {
                want.push(txid);
            }
        }
        let wallet = TokenWallet::new(artifact(name), Box::new(provider), Box::new(signer));
        match catch_unwind(AssertUnwindSafe(|| wallet.get_utxos())) {
            Ok(Ok(utxos)) => {
                let kept: Vec<String> = utxos.into_iter().map(|u| u.txid).collect();
                if kept != want {
                    diffs.push(format!("get_utxos ({}): want {:?}, got {:?}", name, want, kept));
                }
            }
            Ok(Err(e)) => diffs.push(format!("get_utxos ({}): {}", name, e)),
            Err(_) => diffs.push(format!("get_utxos ({}) panicked", name)),
        }
    }
    diffs
}

#[test]
fn hostile_utxo_scripts_n317() {
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
