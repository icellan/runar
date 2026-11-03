//! N-285 — `catch_refusal`'s one-time hook install (see `refusal.rs`) is
//! `take_hook()` followed by a *separate* `set_hook()`. Between those two
//! calls the process-wide hook is transiently the stdlib default, not
//! whatever the embedder had installed. The lazy install inside
//! `catch_refusal` only runs that two-step sequence the first time any
//! thread calls it, so an unrelated panic on ANOTHER thread landing in that
//! gap, during the first concurrent `catch_refusal` call, bypasses the
//! embedder's hook and prints the stdlib default banner instead (R-108; the
//! f158 test's warm-up call hides this from that test rather than closing
//! it).
//!
//! What this proves: `refusal::init()` lets an embedder (or the CLI's
//! `main`, which calls it) run that one-time install explicitly, solo, on
//! the main thread, before any concurrency exists. Once that solo call has
//! completed, the install's `Once` is marked done process-wide, so EVERY
//! later call — lazy (via `catch_refusal`) or explicit (via `init()` again)
//! — just observes the `Once` as already complete and never re-enters
//! `take_hook`/`set_hook`. The gap only ever exists once, during that first
//! solo call, and nothing else in the process can be panicking at that
//! moment because nothing else has been spawned yet. A deliberately widened
//! version of the gap (via the `arm_install_window_probe` test seam, since
//! the real gap is "on the order of a couple of machine instructions" and
//! not reliably hittable by thread-scheduling luck alone) demonstrates the
//! gap is real on the solo call, and demonstrates it can no longer be
//! entered on any later call once `init()` has completed.
//!
//! What this does NOT prove: it does not prove `init()` closes the gap for
//! an embedder who calls a compile entry point from several threads
//! SIMULTANEOUSLY as their very first call into this crate without ever
//! calling `init()` themselves first — that caller still races the lazy
//! path exactly as before (see `refusal::init`'s doc comment). It also does
//! not replace the f158 test, which covers overlapping `catch_refusal` calls
//! racing each other AFTER the one-time install (a different, already-fixed
//! bug, F-158 / CL-BUG-027 / CX-BUG-094).
//!
//! Why there is no pre-fix-vs-post-fix BEHAVIORAL red/green pair here:
//! `init()` does not remove the lazy path inside `catch_refusal` — it can't,
//! short of the unstable `panic::update_hook` (rust-lang issue #92649) — it
//! only gives callers a way to run the SAME one-time install earlier, when
//! it is safe. A probe panic fired inside the gap is swallowed by the
//! stdlib default hook identically before and after this fix; the fix is
//! additive (a new function), not a change to existing behavior. The
//! deterministic red for this item is therefore a compile error: before the
//! fix, `refusal::init` and `refusal::arm_install_window_probe` do not
//! exist, so this file fails to build with `error[E0425]` /
//! `error[E0433]` (no function named `init`/`arm_install_window_probe`
//! found in module `refusal`) — which is itself the direct evidence that no
//! documented eager-install entry point existed, only the ad hoc
//! dummy-panic warm-up the f158 test used internally.

use runar_compiler_rust::refusal::{self, arm_install_window_probe, catch_refusal};
use std::panic;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;

/// Counts invocations of the sentinel hook installed below (the stand-in for
/// "the embedder's own panic hook").
static SENTINEL_FIRED: AtomicUsize = AtomicUsize::new(0);

/// Counts how many times the install-window probe actually ran — i.e. how
/// many times `install_suppressing_hook_once`'s `Once::call_once` closure
/// was entered. Must be 1 after the solo `init()` call, and must NOT
/// increase afterward, however many later calls (lazy or explicit) happen.
static PROBE_FIRED: AtomicUsize = AtomicUsize::new(0);

/// Guards against another `#[test]` in this (or another) binary in the same
/// process installing/inspecting the one process-global panic hook
/// concurrently with this test, for reasons unrelated to N-285. Same
/// pattern as f158's `TEST_HOOK_LOCK`.
static TEST_HOOK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[test]
fn eager_init_closes_the_install_window_for_every_call_after_it() {
    let _guard = TEST_HOOK_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap();

    SENTINEL_FIRED.store(0, Ordering::SeqCst);
    PROBE_FIRED.store(0, Ordering::SeqCst);
    panic::set_hook(Box::new(|_info| {
        SENTINEL_FIRED.fetch_add(1, Ordering::SeqCst);
    }));

    // Arm the probe that runs INSIDE install_suppressing_hook_once, between
    // take_hook() and set_hook() — i.e. exactly in the gap N-285 is about.
    // The probe panics deliberately to prove the gap is live: at the moment
    // it runs, the active process hook is the stdlib default (take_hook()
    // already removed our sentinel above), so this panic must NOT reach
    // SENTINEL_FIRED. It is wrapped in catch_unwind: a panic escaping
    // Once::call_once's closure would poison the Once for the rest of the
    // process, which would corrupt every later call in this binary, not
    // just this test.
    arm_install_window_probe(|| {
        PROBE_FIRED.fetch_add(1, Ordering::SeqCst);
        eprintln!(
            "n285: install-window probe panicking deliberately inside the \
             take_hook()/set_hook() gap — the following default-hook banner \
             on stderr is expected, not a test crash"
        );
        let _ = panic::catch_unwind(|| panic!("n285 install-window probe payload"));
    });

    // The ONE call in this whole test (and, in production, in the whole
    // process) that actually runs install_suppressing_hook_once's
    // call_once closure: solo, on this thread, before any other thread
    // exists. This is exactly what main() does in src/main.rs and what
    // every leaf compile entry point in src/lib.rs does on a caller's
    // behalf.
    refusal::init();

    assert_eq!(
        PROBE_FIRED.load(Ordering::SeqCst),
        1,
        "the solo init() call must be the one that actually installs the \
         hook, i.e. must enter the take_hook()/set_hook() gap exactly once"
    );
    assert_eq!(
        SENTINEL_FIRED.load(Ordering::SeqCst),
        0,
        "the probe's panic fired strictly inside the gap, while the active \
         hook was transiently the stdlib default — it must NOT have reached \
         the sentinel hook that was installed before init() ran. (This is \
         the N-285 gap itself, demonstrated deterministically rather than by \
         timing luck; it is why init() must be called before any concurrency \
         exists, not why this fix removes the gap.)"
    );

    // Calling init() again — the documented idempotent contract — must be a
    // no-op: the Once is already complete, so the probe must not fire
    // again, however many more times init() is called.
    refusal::init();
    refusal::init();
    assert_eq!(
        PROBE_FIRED.load(Ordering::SeqCst),
        1,
        "init() must be idempotent: a second and third call must not \
         re-enter the take_hook()/set_hook() gap"
    );

    // Now prove the actual fix: with the one-time install already complete
    // (because init() ran solo, above), race a catch_refusal call (which
    // would have been "the first concurrent catch_refusal call" in a
    // process that never called init()) against an unrelated panic on
    // another thread, synchronized to start together. Re-arm the probe so
    // we would catch it firing again if the Once were somehow re-entered.
    arm_install_window_probe(|| {
        PROBE_FIRED.fetch_add(1, Ordering::SeqCst);
    });
    SENTINEL_FIRED.store(0, Ordering::SeqCst);
    PROBE_FIRED.store(0, Ordering::SeqCst);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let b1 = std::sync::Arc::clone(&barrier);
    let refusal_handle = thread::spawn(move || {
        b1.wait();
        catch_refusal("n285 test", || panic!("n285 refusal payload")).is_err()
    });
    let b2 = std::sync::Arc::clone(&barrier);
    let unrelated_handle = thread::spawn(move || {
        b2.wait();
        panic::catch_unwind(|| panic!("n285 unrelated panic")).is_err()
    });

    assert!(
        refusal_handle
            .join()
            .expect("refusal thread must not itself panic"),
        "catch_refusal must still surface the refusal as Err"
    );
    assert!(
        unrelated_handle
            .join()
            .expect("unrelated thread must not itself panic"),
        "the unrelated panic must still unwind to an Err"
    );

    assert_eq!(
        PROBE_FIRED.load(Ordering::SeqCst),
        0,
        "with the one-time install already complete via init(), neither \
         thread's call should have re-entered take_hook()/set_hook() at all"
    );
    assert_eq!(
        SENTINEL_FIRED.load(Ordering::SeqCst),
        1,
        "with the install window already closed by the prior init() call, \
         the unrelated panic racing catch_refusal's first-ever concurrent \
         call must reach the embedder's hook exactly once — the testable \
         assertion this item is about"
    );

    // Leave the process hook in a known state for any test that runs after
    // this one in the same process (same cleanup f158 does).
    let _ = panic::take_hook();
}
