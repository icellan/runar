//! Turning a lowering-pass refusal into a diagnostic — quietly.
//!
//! Passes 4 and 5 refuse a construct they must not emit by panicking, and both
//! wrap themselves in `catch_unwind` so the refusal reaches the caller as an
//! `Err` instead of unwinding out of the compiler. That much already matched
//! the other six tiers.
//!
//! What did NOT match is what the USER sees. Rust's default panic hook writes
//!
//! ```text
//! thread 'main' panicked at src/codegen/stack.rs:1350:13:
//! <the diagnostic>
//! note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
//! ```
//!
//! to stderr *before* `catch_unwind` ever gets the payload. So a refusal the
//! TS / Go / Python / Zig / Ruby / Java tiers report as one clean line came out
//! of the Rust tier as a compiler crash report with a source location inside
//! the compiler and an invitation to collect a backtrace — reading, to anyone
//! holding a contract that will not compile, like a bug in Rúnar rather than a
//! diagnosis of their contract. The `Err` was then printed a second time.
//!
//! `catch_refusal` silences the hook for exactly the duration of the guarded
//! call, so the payload surfaces once, as a diagnostic. Genuine unexpected
//! panics still surface — they arrive as the same `Err` and are still printed
//! by the caller; only the hook's banner is suppressed, and only inside a
//! boundary that already treats every panic as a diagnostic.
//!
//! The hook IS process-global, but the swap is not: `catch_refusal` never
//! calls `panic::take_hook` / `panic::set_hook` itself (F-158 / CL-BUG-027 /
//! CX-BUG-094 — doing that on every call raced two overlapping callers
//! against each other, e.g. one call's `take_hook` could observe the OTHER
//! call's in-flight "no-op" hook as "the previous hook" and restore that
//! no-op process-wide once both calls returned, or could leave an unrelated
//! panic on another thread suppressed for the brief window the no-op was
//! installed). Instead, ONE hook is installed, once, via `Once`, the first
//! time `catch_refusal` runs; it delegates to whichever hook was already
//! installed at that moment unless the CURRENT THREAD is inside a
//! `catch_refusal` call, which it tracks with a thread-local flag. Only that
//! flag is toggled per call — per-thread state, so overlapping calls on
//! different threads never race each other, and a panic on a thread that is
//! not inside `catch_refusal` always reaches the delegate hook.
use std::cell::{Cell, RefCell};
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;

use crate::frontend::ast::SourceLocation;

thread_local! {
    /// Set for the duration of this thread's `catch_refusal` call so the
    /// process-wide hook installed by `install_suppressing_hook_once` knows
    /// to swallow a panic on THIS thread without affecting any other thread.
    static SUPPRESS_ON_THIS_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// Installs the one process-wide panic hook `catch_refusal` ever needs, the
/// first time any thread calls `catch_refusal`. The hook it replaces (the
/// default hook, or whatever the embedder installed before compiling) is
/// captured once and delegated to for every panic except one that happens on
/// a thread currently inside `catch_refusal`.
fn install_suppressing_hook_once() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let delegate = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            let suppress = SUPPRESS_ON_THIS_THREAD.with(|c| c.get());
            if !suppress {
                delegate(info);
            }
        }));
    });
}

/// RAII guard that marks the current thread as "inside `catch_refusal`" for
/// its lifetime, restoring whatever the flag held before (so nested calls on
/// the same thread behave correctly) when it is dropped — including when the
/// call panics, since `catch_unwind` below only unwinds the FRAMES INSIDE
/// IT; this guard lives in `catch_refusal`'s own frame, outside that
/// boundary, so its `Drop` still runs normally once `catch_unwind` returns.
struct SuppressGuard {
    previous: bool,
}

impl SuppressGuard {
    fn new() -> Self {
        let previous = SUPPRESS_ON_THIS_THREAD.with(|c| c.replace(true));
        SuppressGuard { previous }
    }
}

impl Drop for SuppressGuard {
    fn drop(&mut self) {
        SUPPRESS_ON_THIS_THREAD.with(|c| c.set(self.previous));
    }
}

thread_local! {
    /// Where the pass currently is (R-138).
    ///
    /// Passes 4 and 5 refuse by panicking with a plain string, across 44 sites
    /// (10 in `frontend/anf_lower.rs`, 34 in `codegen/stack.rs`). Threading a
    /// `SourceLocation` through all of them would be 44 edits and would miss
    /// the 45th. Instead each pass PUBLISHES where it is at the one choke point
    /// that already holds the answer — `lower_binding`, which has the
    /// `ANFBinding` and therefore its `source_loc`, and the ANF lowerer's
    /// statement dispatch — and `catch_refusal` reads it on the error path.
    ///
    /// Thread-local, not global: each thread running its own `catch_refusal`
    /// call publishes and reads only its own location, so concurrent calls on
    /// different threads never see each other's in-flight position.
    static REFUSAL_LOCATION: RefCell<Option<SourceLocation>> = const { RefCell::new(None) };
}

/// Publish the location the current pass is working at. Cheap enough to call
/// per binding / per statement; the cost is one `RefCell` write.
pub fn set_refusal_location(loc: Option<SourceLocation>) {
    REFUSAL_LOCATION.with(|c| *c.borrow_mut() = loc);
}

fn take_refusal_location() -> Option<SourceLocation> {
    REFUSAL_LOCATION.with(|c| c.borrow_mut().take())
}

/// A refusal from pass 4 or 5: the diagnostic text, plus where in the CONTRACT
/// it was raised when the pass had published a position.
///
/// `Display` renders exactly the string this function used to return, so every
/// caller that only formats the error is unchanged; callers building a
/// `Diagnostic` read `loc` instead of passing `None`.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub message: String,
    pub loc: Option<SourceLocation>,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<Refusal> for String {
    fn from(r: Refusal) -> String {
        r.message
    }
}

/// Derefs to the message, so every `&str` method a caller used on the old
/// `String` error — `contains`, `starts_with`, `len` — keeps working. This is
/// what makes R-138 additive: the payload gained a field, and no existing
/// caller or test had to change to keep reading the text.
impl std::ops::Deref for Refusal {
    type Target = str;

    fn deref(&self) -> &str {
        &self.message
    }
}

/// Run `f`, converting a panic into `Err(Refusal { message: "{prefix}: {payload}", loc })`
/// without letting the default panic hook print its banner first.
pub fn catch_refusal<T>(prefix: &str, f: impl FnOnce() -> T) -> Result<T, Refusal> {
    set_refusal_location(None);
    install_suppressing_hook_once();
    let _guard = SuppressGuard::new();
    let outcome = panic::catch_unwind(AssertUnwindSafe(f));

    outcome.map_err(|e| {
        let message = if let Some(s) = e.downcast_ref::<String>() {
            format!("{}: {}", prefix, s)
        } else if let Some(s) = e.downcast_ref::<&str>() {
            format!("{}: {}", prefix, s)
        } else {
            format!("{}: internal error", prefix)
        };
        Refusal {
            message,
            loc: take_refusal_location(),
        }
    })
}
