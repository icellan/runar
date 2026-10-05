//! F-158 / CL-BUG-027 / CX-BUG-094 — `catch_refusal` swaps the process-global
//! panic hook without synchronization, so two overlapping compiles can race:
//! one thread's `take_hook` / `set_hook(no-op)` / `set_hook(previous)`
//! sequence can interleave with another's and either (a) suppress a panic
//! that has nothing to do with the refusal, or (b) leave the wrong hook (the
//! no-op, or a stale default) installed process-wide once both calls return.
//!
//! What this proves: with a sentinel hook installed before any `catch_refusal`
//! call, running many refusal-triggering threads concurrently with many
//! threads that panic OUTSIDE `catch_refusal` (via a bare `catch_unwind`)
//! shows the sentinel's fire-count falling short of the unrelated-panic count
//! (an unrelated panic got swallowed by the no-op the race left installed),
//! and/or the sentinel no longer being the active hook once every thread has
//! joined (a `set_hook(previous)` lost the race and left some other hook
//! behind). Both are direct instances of CX-BUG-094's complaint.
//!
//! What this does NOT prove: it does not prove the race is impossible to miss
//! on a slower or single-core machine — the two groups of threads are only
//! synchronized to start together via a `Barrier`, not to interleave at the
//! exact instruction granularity of the hook swap. Many rounds across many
//! threads are run to make a miss on a multi-core machine very unlikely, not
//! to make this a timing-independent proof.

use runar_compiler_rust::refusal::catch_refusal;
use std::panic;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, OnceLock};
use std::thread;

/// Counts invocations of the sentinel hook installed below. `static` so the
/// `Box<dyn Fn>` passed to `panic::set_hook` (which requires `'static`) can
/// close over it.
static SENTINEL_FIRED: AtomicUsize = AtomicUsize::new(0);

/// Guards against two `#[test]` functions in this (or another) binary racing
/// to install/inspect the one process-global panic hook at the same time.
/// Rust runs `#[test]`s on a thread pool by default, so without this a second
/// test in the same process could install its own hook mid-run and corrupt
/// this test's sentinel count for reasons unrelated to F-158.
static TEST_HOOK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[test]
fn concurrent_catch_refusal_does_not_corrupt_or_suppress_unrelated_panic_hook() {
    let _guard = TEST_HOOK_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap();

    SENTINEL_FIRED.store(0, Ordering::SeqCst);
    panic::set_hook(Box::new(|_info| {
        SENTINEL_FIRED.fetch_add(1, Ordering::SeqCst);
    }));

    const ROUNDS: usize = 100;
    const REFUSAL_THREADS: usize = 8;
    const UNRELATED_THREADS: usize = 8;

    let mut refusal_err_count = 0usize;

    for _round in 0..ROUNDS {
        let total_threads = REFUSAL_THREADS + UNRELATED_THREADS;
        let barrier = Arc::new(Barrier::new(total_threads));

        let refusal_handles: Vec<_> = (0..REFUSAL_THREADS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    catch_refusal("f158 test", || panic!("f158 refusal payload")).is_err()
                })
            })
            .collect();

        let unrelated_handles: Vec<_> = (0..UNRELATED_THREADS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    // Deliberately NOT routed through catch_refusal: this panic
                    // has nothing to do with any refusal, so the installed
                    // hook must fire for it exactly like it would have if no
                    // concurrent catch_refusal call existed at all.
                    panic::catch_unwind(|| panic!("f158 unrelated panic")).is_err()
                })
            })
            .collect();

        for h in refusal_handles {
            if h.join().expect("refusal thread must not itself panic") {
                refusal_err_count += 1;
            }
        }
        for h in unrelated_handles {
            assert!(
                h.join().expect("unrelated thread must not itself panic"),
                "the unrelated panic must still unwind to an Err regardless of \
                 any concurrent catch_refusal call"
            );
        }
    }

    assert_eq!(
        refusal_err_count,
        ROUNDS * REFUSAL_THREADS,
        "every catch_refusal call must surface its panic as Err"
    );

    let fired_during = SENTINEL_FIRED.load(Ordering::SeqCst);
    // eprintln!, unlike the panic message below, is not routed through the
    // panic hook, so this diagnostic survives even when the bug under test
    // makes the hook swallow the panic message itself.
    eprintln!(
        "f158: sentinel fired {fired_during} times for {} unrelated panics",
        ROUNDS * UNRELATED_THREADS
    );
    assert_eq!(
        fired_during,
        ROUNDS * UNRELATED_THREADS,
        "the pre-installed sentinel hook must run once per unrelated panic; a \
         lower count means a concurrent catch_refusal call's no-op hook \
         suppressed a panic that had nothing to do with it"
    );

    // After every thread has joined, the sentinel must still be the active
    // process hook — not the no-op, and not some other hook a lost
    // `set_hook(previous)` race left behind.
    let before = SENTINEL_FIRED.load(Ordering::SeqCst);
    let _ = panic::catch_unwind(|| panic!("f158 post-check panic"));
    let after = SENTINEL_FIRED.load(Ordering::SeqCst);
    eprintln!("f158: sentinel count before post-check panic={before}, after={after}");
    assert_eq!(
        after,
        before + 1,
        "the sentinel hook installed before any catch_refusal call must still \
         be the active hook once all concurrent calls have returned"
    );

    // Leave the process hook in a known state for any test that runs after
    // this one in the same process.
    let _ = panic::take_hook();
}
