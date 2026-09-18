//! H2 (#131): locktime soundness warning.
//!
//! A method that reads `extractLocktime(preimage)` only enforces a timelock if
//! the covenant ALSO asserts the spending tx is non-final
//! (`extractSequence(preimage) < 0xffffffff`). Without that, a hand-built
//! all-final-sequence transaction bypasses the locktime gate. The compiler
//! emits an advisory WARNING (non-fatal) when a public method reads
//! `extractLocktime` but does not (transitively) assert a sequence-finality
//! guard.
//!
//! Mirrors `remediation-h2-locktime-sequence-warning.test.ts`.

use runar_compiler_rust::frontend_validate;

const WARNING_NEEDLE: &str = "does not assert extractSequence";

/// `frontend_validate` splits diagnostics into `(errors, warnings)` and only
/// the *warning* channel is inspected here — so any hit already proves
/// `severity == warning`.
fn warnings_of(source: &str) -> Vec<String> {
    let (errors, warnings) = frontend_validate(source, Some("test.runar.ts"));
    assert!(
        errors.is_empty(),
        "source should validate without errors; got: {errors:?}"
    );
    warnings
}

fn has_locktime_warning(warnings: &[String]) -> bool {
    warnings.iter().any(|w| w.contains(WARNING_NEEDLE))
}

#[test]
fn warns_when_method_reads_locktime_without_sequence_guard() {
    let source = r#"
import { StatefulSmartContract } from 'runar-lang';

class TimeLock extends StatefulSmartContract {
    count: bigint;
    readonly deadline: bigint;
    constructor(count: bigint, deadline: bigint) {
        super(count, deadline);
        this.count = count;
        this.deadline = deadline;
    }
    public unlock() {
        assert(extractLocktime(this.txPreimage) >= this.deadline);
        this.count++;
    }
}
"#;
    let warnings = warnings_of(source);
    assert!(
        has_locktime_warning(&warnings),
        "expected a locktime-without-sequence-guard warning; got: {warnings:?}"
    );
    // The warning names the method and points at the fix.
    let w = warnings
        .iter()
        .find(|x| x.contains(WARNING_NEEDLE))
        .unwrap();
    assert!(w.contains("unlock"), "warning should name the method; got: {w}");
    assert!(
        w.contains("0xffffffff"),
        "warning should mention the finality sentinel; got: {w}"
    );
}

#[test]
fn no_warn_when_method_asserts_extract_sequence_below_final() {
    let source = r#"
import { StatefulSmartContract } from 'runar-lang';

class TimeLock extends StatefulSmartContract {
    count: bigint;
    readonly deadline: bigint;
    constructor(count: bigint, deadline: bigint) {
        super(count, deadline);
        this.count = count;
        this.deadline = deadline;
    }
    public unlock() {
        assert(extractSequence(this.txPreimage) < 0xffffffffn);
        assert(extractLocktime(this.txPreimage) >= this.deadline);
        this.count++;
    }
}
"#;
    let warnings = warnings_of(source);
    assert!(
        !has_locktime_warning(&warnings),
        "should NOT warn when a sequence-finality guard is present; got: {warnings:?}"
    );
}

#[test]
fn still_warns_when_sequence_comparison_is_negated() {
    let source = r#"
import { StatefulSmartContract } from 'runar-lang';

class TimeLock extends StatefulSmartContract {
    count: bigint;
    readonly deadline: bigint;
    constructor(count: bigint, deadline: bigint) {
        super(count, deadline);
        this.count = count;
        this.deadline = deadline;
    }
    public unlock() {
        assert(!(extractSequence(this.txPreimage) !== 0xffffffffn));
        assert(extractLocktime(this.txPreimage) >= this.deadline);
        this.count++;
    }
}
"#;
    let warnings = warnings_of(source);
    assert!(
        has_locktime_warning(&warnings),
        "negated sequence comparison must not count as a guard; got: {warnings:?}"
    );
}

#[test]
fn no_warn_when_method_never_reads_locktime() {
    let source = r#"
import { StatefulSmartContract } from 'runar-lang';

class Counter extends StatefulSmartContract {
    count: bigint;
    constructor(count: bigint) {
        super(count);
        this.count = count;
    }
    public increment() {
        this.count++;
    }
}
"#;
    let warnings = warnings_of(source);
    assert!(
        !has_locktime_warning(&warnings),
        "should NOT warn for a method that never reads locktime; got: {warnings:?}"
    );
}

#[test]
fn no_warn_when_sequence_guard_supplied_by_private_helper() {
    let source = r#"
import { StatefulSmartContract } from 'runar-lang';

class TimeLock extends StatefulSmartContract {
    count: bigint;
    readonly deadline: bigint;
    constructor(count: bigint, deadline: bigint) {
        super(count, deadline);
        this.count = count;
        this.deadline = deadline;
    }
    private requireNonFinal() {
        assert(extractSequence(this.txPreimage) < 0xffffffffn);
    }
    public unlock() {
        this.requireNonFinal();
        assert(extractLocktime(this.txPreimage) >= this.deadline);
        this.count++;
    }
}
"#;
    let warnings = warnings_of(source);
    assert!(
        !has_locktime_warning(&warnings),
        "guard supplied transitively through a private helper should suppress the warning; got: {warnings:?}"
    );
}

#[test]
fn warns_when_locktime_read_in_private_helper_without_guard() {
    let source = r#"
import { StatefulSmartContract } from 'runar-lang';

class TimeLock extends StatefulSmartContract {
    count: bigint;
    readonly deadline: bigint;
    constructor(count: bigint, deadline: bigint) {
        super(count, deadline);
        this.count = count;
        this.deadline = deadline;
    }
    private checkDeadline() {
        assert(extractLocktime(this.txPreimage) >= this.deadline);
    }
    public unlock() {
        this.checkDeadline();
        this.count++;
    }
}
"#;
    let warnings = warnings_of(source);
    assert!(
        has_locktime_warning(&warnings),
        "a locktime read reached transitively through a private helper (with no guard) should warn; got: {warnings:?}"
    );
}

#[test]
fn warns_when_comparison_is_assigned_not_asserted() {
    let source = r#"
import { StatefulSmartContract } from 'runar-lang';

class TimeLock extends StatefulSmartContract {
    count: bigint;
    readonly deadline: bigint;
    constructor(count: bigint, deadline: bigint) {
        super(count, deadline);
        this.count = count;
        this.deadline = deadline;
    }
    public unlock() {
        const ok: boolean = extractSequence(this.txPreimage) !== 0xffffffffn;
        assert(extractLocktime(this.txPreimage) >= this.deadline);
        this.count++;
    }
}
"#;
    let warnings = warnings_of(source);
    assert!(
        has_locktime_warning(&warnings),
        "assigned comparison must not silence the warning; got: {warnings:?}"
    );
}

#[test]
fn warns_for_vacuous_strict_bound() {
    let source = r#"
import { StatefulSmartContract } from 'runar-lang';

class TimeLock extends StatefulSmartContract {
    count: bigint;
    readonly deadline: bigint;
    constructor(count: bigint, deadline: bigint) {
        super(count, deadline);
        this.count = count;
        this.deadline = deadline;
    }
    public unlock() {
        assert(extractSequence(this.txPreimage) < 0n);
        assert(extractLocktime(this.txPreimage) >= this.deadline);
        this.count++;
    }
}
"#;
    let warnings = warnings_of(source);
    assert!(
        has_locktime_warning(&warnings),
        "extractSequence < 0n is not a finality guard; got: {warnings:?}"
    );
}
