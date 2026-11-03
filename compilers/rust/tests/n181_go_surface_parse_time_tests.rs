//! N-181: the .runar.go surface parses adversarial sources under
//! MAX_SOURCE_BYTES in time linear in their size.
//!
//! `int[][]…[] q;` used to be quadratic: every failed statement skipped one
//! token, and the next statement, starting at the following `[`, re-ran the
//! composite-literal lookahead (`[N]…[N]T{`) over the whole remaining `[]`
//! chain. Measured on the release CLI: 40k `[]` 3.1 s, 160k `[]` 49.6 s CPU;
//! the 4 MiB shape (~2.1M `[]`) extrapolates to hours.
//!
//! `a = a = …;` and `a ? a : a ? …` were reported by the F-213 refuter as
//! quadratic too; at this commit's parent they already took 1.6 s / 1.8 s CPU
//! at 4 MiB (release), so they are kept here as guards, not as the red proof.
//!
//! What this proves: each shape, filling MAX_SOURCE_BYTES, is refused with a
//! parse error within a fixed CPU budget (debug build, CLOCK_PROCESS_CPUTIME_ID
//! polled while a worker thread parses; one #[test] so no other test in this
//! binary shares the process clock). What it does NOT prove: anything about the
//! other eight surfaces or the other six tiers, or about passes after parsing.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use runar_compiler_rust::frontend::diagnostic::Severity;
use runar_compiler_rust::frontend::parser::parse_source;

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

const CAP: usize = 4 * 1024 * 1024 - 4096;

fn go_source(stmt: &str, expr: &str) -> String {
    format!(
        "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype P struct {{\n\trunar.SmartContract\n\tT runar.Int `runar:\"readonly\"`\n}}\n\nfunc (c *P) Verify(a runar.Int, b runar.Int) {{\n{}\n\tr := {}\n\trunar.Assert(r == c.T)\n}}\n",
        stmt, expr
    )
}

/// CPU budget per shape. After the fix (debug build, loaded dev host) the
/// shapes take 1.6 s / 2.2 s / 2.6 s; before it the `[]` shape was still
/// running when this budget expired (and 160k `[]` took 49.6 s on release).
const BUDGET_SECS: f64 = 30.0;

#[test]
fn go_surface_adversarial_shapes_parse_within_cpu_budget() {
    let shapes: Vec<(&str, String)> = vec![
        ("int[][]…[] q;", go_source(&format!("int{} q;", "[]".repeat(CAP / 2)), "a")),
        ("a = a = …;", go_source(&format!("a{};", " = a".repeat(CAP / 4)), "a")),
        ("a ? a : a ? …", go_source("", &format!("{}a", "a ? a : ".repeat(CAP / 8)))),
    ];
    for (name, src) in shapes {
        assert!(src.len() <= 4 * 1024 * 1024, "{}: {} bytes is over MAX_SOURCE_BYTES", name, src.len());
        let (tx, rx) = mpsc::channel();
        let start = process_cpu_secs();
        thread::spawn(move || {
            let r = parse_source(&src, Some("P.runar.go"));
            let errs: Vec<String> =
                r.errors.iter().filter(|d| d.severity == Severity::Error).map(|d| d.message.clone()).collect();
            let _ = tx.send(errs);
        });
        let errs = loop {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(errs) => break errs,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let used = process_cpu_secs() - start;
                    assert!(used <= BUDGET_SECS, "{}: still parsing after {:.1}s CPU (budget {}s): not linear", name, used, BUDGET_SECS);
                }
                Err(e) => panic!("{}: parser thread died: {:?}", name, e),
            }
        };
        let used = process_cpu_secs() - start;
        eprintln!("{}: {:.2}s CPU, {} errors", name, used, errs.len());
        assert!(used <= BUDGET_SECS, "{}: {:.1}s CPU (budget {}s)", name, used, BUDGET_SECS);
        assert!(!errs.is_empty(), "{}: malformed source accepted", name);
        assert!(
            !errs.iter().any(|m| m.contains("MAX_SOURCE_BYTES")),
            "{}: refused by the size cap, so the parser never ran",
            name
        );
    }
}
