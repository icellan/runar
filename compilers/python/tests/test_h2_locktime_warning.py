"""H2 (#131): locktime soundness warning.

A method that reads ``extract_locktime(self.tx_preimage)`` only enforces a
timelock if the covenant ALSO asserts the spending tx is non-final
(``extract_sequence(self.tx_preimage) < 0xffffffff``). Without that, a
hand-built all-final-sequence transaction bypasses the locktime gate. The
compiler emits an advisory WARNING (non-fatal) when a public method reads the
tx locktime -- directly or transitively through a private helper -- but never
asserts a sequence-finality guard.

Contracts are written in Python format; the parser lowers snake_case names to
camelCase (``extract_locktime`` -> ``extractLocktime``,
``extract_sequence`` -> ``extractSequence``,
``current_block_height`` -> ``currentBlockHeight``) so the warning matches the
camelCase intrinsic names in the AST.
"""

from __future__ import annotations

from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import ValidationResult, validate


WARNING_NEEDLE = "does not assert extractSequence"


def _validate_source(source: str) -> ValidationResult:
    pr = parse_source(source, "TimeLock.runar.py")
    assert not pr.errors, f"parse errors: {pr.errors}"
    return validate(pr.contract)


def _has_locktime_warning(result: ValidationResult) -> bool:
    return any(WARNING_NEEDLE in w.message for w in result.warnings)


def test_warns_when_method_reads_locktime_without_sequence_guard() -> None:
    source = """
from runar import (
    StatefulSmartContract, Bigint, Readonly,
    public, assert_, extract_locktime,
)


class TimeLock(StatefulSmartContract):
    deadline: Readonly[Bigint]
    count: Bigint

    def __init__(self, deadline: Bigint, count: Bigint):
        super().__init__(deadline, count)
        self.deadline = deadline
        self.count = count

    @public
    def unlock(self):
        assert_(extract_locktime(self.tx_preimage) >= self.deadline)
        self.count = self.count + 1
"""
    result = _validate_source(source)
    assert _has_locktime_warning(result)
    warning = next(w for w in result.warnings if WARNING_NEEDLE in w.message)
    assert warning.severity == "warning"
    assert "unlock" in warning.message
    assert "0xffffffff" in warning.message


def test_no_warn_when_method_asserts_sequence_below_final() -> None:
    source = """
from runar import (
    StatefulSmartContract, Bigint, Readonly,
    public, assert_, extract_locktime, extract_sequence,
)


class TimeLock(StatefulSmartContract):
    deadline: Readonly[Bigint]
    count: Bigint

    def __init__(self, deadline: Bigint, count: Bigint):
        super().__init__(deadline, count)
        self.deadline = deadline
        self.count = count

    @public
    def unlock(self):
        assert_(extract_sequence(self.tx_preimage) < 0xffffffff)
        assert_(extract_locktime(self.tx_preimage) >= self.deadline)
        self.count = self.count + 1
"""
    result = _validate_source(source)
    assert not _has_locktime_warning(result)


def test_warns_when_sequence_comparison_is_negated() -> None:
    source = """
from runar import (
    StatefulSmartContract, Bigint, Readonly,
    public, assert_, extract_locktime, extract_sequence,
)


class TimeLock(StatefulSmartContract):
    deadline: Readonly[Bigint]
    count: Bigint

    def __init__(self, deadline: Bigint, count: Bigint):
        super().__init__(deadline, count)
        self.deadline = deadline
        self.count = count

    @public
    def unlock(self):
        assert_(not (extract_sequence(self.tx_preimage) != 0xffffffff))
        assert_(extract_locktime(self.tx_preimage) >= self.deadline)
        self.count = self.count + 1
"""
    result = _validate_source(source)
    assert _has_locktime_warning(result)


def test_no_warn_when_method_never_reads_locktime() -> None:
    source = """
from runar import StatefulSmartContract, Bigint, public


class Counter(StatefulSmartContract):
    count: Bigint

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    @public
    def increment(self):
        self.count = self.count + 1
"""
    result = _validate_source(source)
    assert not _has_locktime_warning(result)


def test_no_warn_when_sequence_guard_supplied_transitively() -> None:
    source = """
from runar import (
    StatefulSmartContract, Bigint, Readonly,
    public, assert_, extract_locktime, extract_sequence,
)


class TimeLock(StatefulSmartContract):
    deadline: Readonly[Bigint]
    count: Bigint

    def __init__(self, deadline: Bigint, count: Bigint):
        super().__init__(deadline, count)
        self.deadline = deadline
        self.count = count

    def require_non_final(self):
        assert_(extract_sequence(self.tx_preimage) < 0xffffffff)

    @public
    def unlock(self):
        self.require_non_final()
        assert_(extract_locktime(self.tx_preimage) >= self.deadline)
        self.count = self.count + 1
"""
    result = _validate_source(source)
    assert not _has_locktime_warning(result)


def test_warns_when_locktime_read_in_private_helper_but_no_guard() -> None:
    source = """
from runar import (
    StatefulSmartContract, Bigint, Readonly,
    public, assert_, extract_locktime,
)


class TimeLock(StatefulSmartContract):
    deadline: Readonly[Bigint]
    count: Bigint

    def __init__(self, deadline: Bigint, count: Bigint):
        super().__init__(deadline, count)
        self.deadline = deadline
        self.count = count

    def check_deadline(self):
        assert_(extract_locktime(self.tx_preimage) >= self.deadline)

    @public
    def unlock(self):
        self.check_deadline()
        self.count = self.count + 1
"""
    result = _validate_source(source)
    assert _has_locktime_warning(result)


def test_warns_when_comparison_is_assigned_not_asserted() -> None:
    source = """
from runar import (
    StatefulSmartContract, Bigint, Readonly,
    public, assert_, extract_locktime, extract_sequence,
)


class TimeLock(StatefulSmartContract):
    deadline: Readonly[Bigint]
    count: Bigint

    def __init__(self, deadline: Bigint, count: Bigint):
        super().__init__(deadline, count)
        self.deadline = deadline
        self.count = count

    @public
    def unlock(self):
        ok = extract_sequence(self.tx_preimage) != 0xffffffff
        assert_(extract_locktime(self.tx_preimage) >= self.deadline)
        self.count = self.count + 1
"""
    result = _validate_source(source)
    assert _has_locktime_warning(result)


def test_warns_for_vacuous_strict_bound() -> None:
    source = """
from runar import (
    StatefulSmartContract, Bigint, Readonly,
    public, assert_, extract_locktime, extract_sequence,
)


class TimeLock(StatefulSmartContract):
    deadline: Readonly[Bigint]
    count: Bigint

    def __init__(self, deadline: Bigint, count: Bigint):
        super().__init__(deadline, count)
        self.deadline = deadline
        self.count = count

    @public
    def unlock(self):
        assert_(extract_sequence(self.tx_preimage) < 0)
        assert_(extract_locktime(self.tx_preimage) >= self.deadline)
        self.count = self.count + 1
"""
    result = _validate_source(source)
    assert _has_locktime_warning(result)
