"""Type checking pass for the Runar compiler.

Verifies type consistency of a validated Runar AST.
Direct port of ``compilers/go/frontend/typecheck.go``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from runar_compiler.frontend.ast_nodes import (
    ArrayLiteralExpr,
    AssignmentStmt,
    BigIntLiteral,
    BinaryExpr,
    BoolLiteral,
    ByteStringLiteral,
    CallExpr,
    ContractNode,
    CustomType,
    DecrementExpr,
    Expression,
    ExpressionStmt,
    FixedArrayType,
    ForStmt,
    Identifier,
    IfStmt,
    IncrementExpr,
    IndexAccessExpr,
    MemberExpr,
    MethodNode,
    PrimitiveType,
    PropertyAccessExpr,
    ReturnStmt,
    SourceLocation,
    Statement,
    TernaryExpr,
    TypeNode,
    UnaryExpr,
    VariableDeclStmt,
)
from runar_compiler.frontend.diagnostic import Diagnostic, Severity
from runar_compiler.frontend.side_effect_summary import (
    MethodEffects,
    compute_side_effect_summary,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class TypeCheckResult:
    """Output of the type checking pass."""

    contract: ContractNode | None = None
    errors: list[Diagnostic] = field(default_factory=list)

    def error_strings(self) -> list[str]:
        """Return formatted error messages as plain strings."""
        return [d.format_message() for d in self.errors]


# N-321: cap on a typecheck message; mirrored in every tier.
MAX_DIAGNOSTIC_CHARS = 1024


def type_check(contract: ContractNode) -> TypeCheckResult:
    """Type-check a Runar AST. Returns the same AST plus any errors."""
    checker = _TypeChecker(contract)

    checker.check_property_initializers()
    checker.check_constructor()
    for method in contract.methods:
        checker.check_method(method)

    return TypeCheckResult(contract=contract, errors=checker.errors)


# ---------------------------------------------------------------------------
# Built-in function signatures
# ---------------------------------------------------------------------------

@dataclass
class FuncSig:
    """Signature of a function: parameter types and return type."""

    params: list[str]
    return_type: str


# Builtins the Go tier implements and this one deliberately does not (R-258 /
# R-259). They belong to the proof-system families root CLAUDE.md scopes to the
# Go reference compiler, so their absence here is policy rather than a gap — but
# reporting them as "unknown function" told the author a real Runar builtin does
# not exist, which sends them looking for a typo or a missing import. The Java
# tier already names the policy for the families it skips; this is the same
# sentence.
#
# Keyed by builtin name, valued by the family to name in the diagnostic.
GO_ONLY_BUILTINS: dict[str, str] = {
    "assertGroth16WitnessAssisted": "BN254 + Groth16",
    "assertGroth16WitnessAssistedWithMSM": "BN254 + Groth16",
    "groth16PublicInput": "BN254 + Groth16",
    "bn254Pairing": "BN254 pairing",
    "bn254MultiPairing3": "BN254 pairing",
    "bn254MultiPairing4": "BN254 pairing",
    "merkleRootPoseidon2KB": "Poseidon2 Merkle",
    "verifySP1FRI": "SP1 FRI",
}

BUILTIN_FUNCTIONS: dict[str, FuncSig] = {
    "sha256":            FuncSig(params=["ByteString"], return_type="Sha256"),
    "ripemd160":         FuncSig(params=["ByteString"], return_type="Ripemd160"),
    "hash160":           FuncSig(params=["ByteString"], return_type="Ripemd160"),
    "hash256":           FuncSig(params=["ByteString"], return_type="Sha256"),
    "checkSig":          FuncSig(params=["Sig", "PubKey"], return_type="boolean"),
    "checkMultiSig":     FuncSig(params=["Sig[]", "PubKey[]"], return_type="boolean"),
    "assert":            FuncSig(params=["boolean"], return_type="void"),
    "len":               FuncSig(params=["ByteString"], return_type="bigint"),
    "cat":               FuncSig(params=["ByteString", "ByteString"], return_type="ByteString"),
    "substr":            FuncSig(params=["ByteString", "bigint", "bigint"], return_type="ByteString"),
    "num2bin":           FuncSig(params=["bigint", "bigint"], return_type="ByteString"),
    "bin2num":           FuncSig(params=["ByteString"], return_type="bigint"),
    "checkPreimage":     FuncSig(params=["SigHashPreimage"], return_type="boolean"),
    "verifyRabinSig":    FuncSig(params=["ByteString", "RabinSig", "ByteString", "RabinPubKey"], return_type="boolean"),
    "verifyWOTS":        FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "verifySLHDSA_SHA2_128s": FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "verifySLHDSA_SHA2_128f": FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "verifySLHDSA_SHA2_192s": FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "verifySLHDSA_SHA2_192f": FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "verifySLHDSA_SHA2_256s": FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "verifySLHDSA_SHA2_256f": FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "ecAdd":              FuncSig(params=["Point", "Point"], return_type="Point"),
    "ecMul":              FuncSig(params=["Point", "bigint"], return_type="Point"),
    "ecMulGen":           FuncSig(params=["bigint"], return_type="Point"),
    "ecNegate":           FuncSig(params=["Point"], return_type="Point"),
    "ecOnCurve":          FuncSig(params=["Point"], return_type="boolean"),
    "ecModReduce":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "ecEncodeCompressed": FuncSig(params=["Point"], return_type="ByteString"),
    "ecMakePoint":        FuncSig(params=["bigint", "bigint"], return_type="Point"),
    "ecPointX":           FuncSig(params=["Point"], return_type="bigint"),
    "ecPointY":           FuncSig(params=["Point"], return_type="bigint"),
    # Elliptic curve operations (P-256 / NIST P-256 / secp256r1)
    "p256Add":              FuncSig(params=["P256Point", "P256Point"], return_type="P256Point"),
    "p256Mul":              FuncSig(params=["P256Point", "bigint"], return_type="P256Point"),
    "p256MulGen":           FuncSig(params=["bigint"], return_type="P256Point"),
    "p256Negate":           FuncSig(params=["P256Point"], return_type="P256Point"),
    "p256OnCurve":          FuncSig(params=["P256Point"], return_type="boolean"),
    "p256EncodeCompressed": FuncSig(params=["P256Point"], return_type="ByteString"),
    "verifyECDSA_P256":     FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    # Elliptic curve operations (P-384 / NIST P-384 / secp384r1)
    "p384Add":              FuncSig(params=["P384Point", "P384Point"], return_type="P384Point"),
    "p384Mul":              FuncSig(params=["P384Point", "bigint"], return_type="P384Point"),
    "p384MulGen":           FuncSig(params=["bigint"], return_type="P384Point"),
    "p384Negate":           FuncSig(params=["P384Point"], return_type="P384Point"),
    "p384OnCurve":          FuncSig(params=["P384Point"], return_type="boolean"),
    "p384EncodeCompressed": FuncSig(params=["P384Point"], return_type="ByteString"),
    "verifyECDSA_P384":     FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "sha256Compress":    FuncSig(params=["ByteString", "ByteString"], return_type="ByteString"),
    "sha256Finalize":    FuncSig(params=["ByteString", "ByteString", "bigint"], return_type="ByteString"),
    "blake3Compress":    FuncSig(params=["ByteString", "ByteString"], return_type="ByteString"),
    "blake3Hash":        FuncSig(params=["ByteString"], return_type="ByteString"),
    "bbFieldAdd":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "bbFieldSub":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "bbFieldMul":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "bbFieldInv":        FuncSig(params=["bigint"], return_type="bigint"),
    "bbExt4Mul0":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Mul1":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Mul2":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Mul3":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Inv0":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Inv1":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Inv2":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Inv3":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    # KoalaBear field arithmetic (p = 2130706433)
    "kbFieldAdd":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "kbFieldSub":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "kbFieldMul":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "kbFieldInv":        FuncSig(params=["bigint"], return_type="bigint"),
    # KoalaBear quartic extension field (W = 3)
    "kbExt4Mul0":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Mul1":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Mul2":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Mul3":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Inv0":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Inv1":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Inv2":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Inv3":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    # BN254 field arithmetic
    "bn254FieldAdd":     FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "bn254FieldSub":     FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "bn254FieldMul":     FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "bn254FieldInv":     FuncSig(params=["bigint"], return_type="bigint"),
    "bn254FieldNeg":     FuncSig(params=["bigint"], return_type="bigint"),
    # BN254 G1 curve operations
    "bn254G1Add":        FuncSig(params=["Point", "Point"], return_type="Point"),
    "bn254G1ScalarMul":  FuncSig(params=["Point", "bigint"], return_type="Point"),
    "bn254G1Negate":     FuncSig(params=["Point"], return_type="Point"),
    "bn254G1OnCurve":    FuncSig(params=["Point"], return_type="boolean"),
    "merkleRootSha256":  FuncSig(params=["ByteString", "ByteString", "bigint", "bigint"], return_type="ByteString"),
    "merkleRootHash256": FuncSig(params=["ByteString", "ByteString", "bigint", "bigint"], return_type="ByteString"),
    "abs":               FuncSig(params=["bigint"], return_type="bigint"),
    "min":               FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "max":               FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "within":            FuncSig(params=["bigint", "bigint", "bigint"], return_type="boolean"),
    "safediv":           FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "safemod":           FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "clamp":             FuncSig(params=["bigint", "bigint", "bigint"], return_type="bigint"),
    "sign":              FuncSig(params=["bigint"], return_type="bigint"),
    "pow":               FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "mulDiv":            FuncSig(params=["bigint", "bigint", "bigint"], return_type="bigint"),
    "percentOf":         FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "sqrt":              FuncSig(params=["bigint"], return_type="bigint"),
    "gcd":               FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "divmod":            FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "log2":              FuncSig(params=["bigint"], return_type="bigint"),
    "bool":              FuncSig(params=["bigint"], return_type="boolean"),
    "reverseBytes":      FuncSig(params=["ByteString"], return_type="ByteString"),
    "left":              FuncSig(params=["ByteString", "bigint"], return_type="ByteString"),
    "right":             FuncSig(params=["ByteString", "bigint"], return_type="ByteString"),
    "int2str":           FuncSig(params=["bigint", "bigint"], return_type="ByteString"),
    "toByteString":      FuncSig(params=["ByteString"], return_type="ByteString"),
    "exit":              FuncSig(params=["boolean"], return_type="void"),
    "pack":              FuncSig(params=["bigint"], return_type="ByteString"),
    "unpack":            FuncSig(params=["ByteString"], return_type="bigint"),
    "extractVersion":       FuncSig(params=["SigHashPreimage"], return_type="bigint"),
    "extractHashPrevouts":  FuncSig(params=["SigHashPreimage"], return_type="Sha256"),
    "extractHashSequence":  FuncSig(params=["SigHashPreimage"], return_type="Sha256"),
    "extractOutpoint":      FuncSig(params=["SigHashPreimage"], return_type="ByteString"),
    "extractInputIndex":    FuncSig(params=["SigHashPreimage"], return_type="bigint"),
    "extractScriptCode":    FuncSig(params=["SigHashPreimage"], return_type="ByteString"),
    "extractAmount":        FuncSig(params=["SigHashPreimage"], return_type="bigint"),
    "extractSequence":      FuncSig(params=["SigHashPreimage"], return_type="bigint"),
    "extractOutputHash":    FuncSig(params=["SigHashPreimage"], return_type="Sha256"),
    "extractOutputs":       FuncSig(params=["SigHashPreimage"], return_type="Sha256"),
    "extractLocktime":      FuncSig(params=["SigHashPreimage"], return_type="bigint"),
    "extractSigHashType":   FuncSig(params=["SigHashPreimage"], return_type="bigint"),
    "split":                FuncSig(params=["ByteString", "bigint"], return_type="ByteString"),
    "buildChangeOutput":    FuncSig(params=["ByteString", "bigint"], return_type="ByteString"),
    # Intent sub-covenant intrinsics (BSVM Phase 13). Witness-bridge wrappers
    # that compile down to standard primitives + auto-injected method params.
    # See docs/cross-covenant-pattern.md.
    #
    # First arg of extractPrevOutputScript / requireOutputP2PKH MUST be an
    # integer literal — enforced as a special case in _check_call_args.
    "extractPrevOutputScript": FuncSig(params=["bigint", "ByteString"], return_type="ByteString"),
    "requireOutputP2PKH":      FuncSig(params=["bigint", "ByteString", "bigint"], return_type="void"),
    "currentBlockHeight":      FuncSig(params=[], return_type="bigint"),
    # F-024 (R14): read-only view of the auto-injected ``_newAmount`` -- the
    # satoshis of the default single-output state continuation.
    "continuationAmount":      FuncSig(params=[], return_type="bigint"),
}

# F-024 (R14): the one diagnostic every tier emits for a write to continuationAmount().
CONTINUATION_AMOUNT_READ_ONLY = "continuationAmount() is read-only and cannot be assigned"


# ---------------------------------------------------------------------------
# Subtyping
# ---------------------------------------------------------------------------

_BYTESTRING_SUBTYPES: frozenset[str] = frozenset({
    "ByteString",
    "PubKey",
    "Sig",
    "Sha256",
    "Ripemd160",
    "Addr",
    "SigHashPreimage",
    "Point",
    "P256Point",
    "P384Point",
})

# Names that are legal without being a local, a builtin or a property: the
# `SigHash` namespace object and the three secp256k1 constants from runar-lang.
# Every frontend hands them to the typechecker as bare identifiers. They used to
# be carried by the "<unknown>" fall-through; once that fall-through raises they
# have to be listed, exactly as the TS reference tier lists them in
# KNOWN_GLOBALS.
KNOWN_GLOBALS: dict[str, str] = {
    "SigHash": "<namespace>",
    "EC_P": "bigint",
    "EC_N": "bigint",
    "EC_G": "Point",
}

_BIGINT_SUBTYPES: frozenset[str] = frozenset({
    "bigint",
    "RabinSig",
    "RabinPubKey",
})


def is_subtype(actual: str, expected: str) -> bool:
    """Return True if a value of type *actual* may be used where *expected* is
    required.

    The port of ``isSubtype`` in
    ``packages/runar-compiler/src/passes/03-typecheck.ts``; it must stay
    clause-for-clause identical to it.

    N-104: this tier used to carry only the ``subtype -> base`` direction of
    each family, so assignment inside a family worked one way and not the
    other -- ``const b: ByteString = pkh`` compiled and ``const h: Sha256 =
    pkh`` did not, while the reference tier accepted both. Measured as a full
    bidirectional matrix over every ordered pair of family members in all seven
    tiers, 85 of 196 cells disagreed. The asymmetry was already known to be
    wrong at the callsites that tripped over it -- this module used to carry a
    private ``_output_state_value_matches`` that re-added the missing clauses
    just for ``addOutput``'s state values, and four tiers had independently
    grown the same patch. The general predicate carries them now, and the
    patches are gone.

    Cross-family moves (a ByteString into a bigint slot or the reverse) are
    still refused, in every tier; that is what ``conformance/negatives``
    N02/N16/N17/N19/N21 pin.
    """
    if actual == expected:
        return True
    # <inferred> and <unknown> are compatible with anything
    if actual in ("<inferred>", "<unknown>"):
        return True
    if expected in ("<inferred>", "<unknown>"):
        return True
    # ByteString subtypes. BIDIRECTIONAL, and both-in-family -- an Addr value
    # satisfies a Ripemd160 slot and vice versa.
    if expected == "ByteString" and actual in _BYTESTRING_SUBTYPES:
        return True
    if actual == "ByteString" and expected in _BYTESTRING_SUBTYPES:
        return True
    if actual in _BYTESTRING_SUBTYPES and expected in _BYTESTRING_SUBTYPES:
        return True
    # bigint subtypes -- same shape.
    if expected == "bigint" and actual in _BIGINT_SUBTYPES:
        return True
    if actual == "bigint" and expected in _BIGINT_SUBTYPES:
        return True
    if actual in _BIGINT_SUBTYPES and expected in _BIGINT_SUBTYPES:
        return True
    if expected.endswith("[]") and actual.endswith("[]"):
        return is_subtype(actual[:-2], expected[:-2])
    return False


def _expanded_state_slots(properties) -> list[tuple[str, object]]:
    """The mutable state as ``addOutput`` sees it: one ``(name, type)`` entry per
    value the state continuation carries.

    N-107: ``expand_fixed_arrays`` (pass 3b) runs after the typechecker and
    splits a FixedArray property into one scalar sibling per element, so the
    DECLARED property list is not the emitted state. The flattening mirrors that
    pass's own naming (``<root>__<i>``, recursing through nested arrays) so a
    diagnostic names the synthetic property the next pass will create.

    A non-positive length is already a parse/validate error; the property is
    kept whole in that case so this rule never fires on a contract that is going
    to be rejected for a better reason.
    """
    slots: list[tuple[str, object]] = []

    def push(name: str, t) -> None:
        if isinstance(t, FixedArrayType) and t.length > 0:
            for i in range(t.length):
                push(f"{name}__{i}", t.element)
            return
        slots.append((name, t))

    for p in properties:
        if not p.readonly:
            push(p.name, p.type)
    return slots


def is_bigint_family(t: str) -> bool:
    """Return True if *t* belongs to the bigint type family."""
    return t in _BIGINT_SUBTYPES


def is_byte_family(t: str) -> bool:
    """Return True if *t* belongs to the ByteString type family.

    Public (no leading underscore) because ``expand_fixed_arrays`` needs the
    question answered for N-133 and must not keep a second copy of the list.
    """
    return t in _BYTESTRING_SUBTYPES


# ---------------------------------------------------------------------------
# Type environment
# ---------------------------------------------------------------------------

class _TypeEnv:
    """Scoped type environment with push/pop semantics."""

    def __init__(self) -> None:
        self._scopes: list[dict[str, str]] = [{}]

    def push_scope(self) -> None:
        self._scopes.append({})

    def pop_scope(self) -> None:
        if self._scopes:
            self._scopes.pop()

    def define(self, name: str, typ: str) -> None:
        self._scopes[-1][name] = typ

    def lookup(self, name: str) -> tuple[str, bool]:
        for scope in reversed(self._scopes):
            if name in scope:
                return scope[name], True
        return "", False

    def scope_index_of(self, name: str) -> int:
        """Index of the innermost scope binding ``name``, or -1 if none does."""
        for i in range(len(self._scopes) - 1, -1, -1):
            if name in self._scopes[i]:
                return i
        return -1

    @property
    def depth(self) -> int:
        """Index the next ``push_scope()`` will occupy."""
        return len(self._scopes)


def _loop_may_run_twice(stmt: ForStmt) -> bool:
    """F-110: whether a for-statement may execute its body two or more times.
    Mirrors the trip count ``_extract_loop_shape`` (anf_lower) unrolls; a shape
    it cannot resolve is refused elsewhere and is treated as repeating here."""
    def literal(e) -> int | None:
        if isinstance(e, BigIntLiteral):
            return e.value
        if isinstance(e, UnaryExpr) and e.op == "-":
            inner = literal(e.operand)
            return None if inner is None else -inner
        return None

    init = stmt.init.init if isinstance(stmt.init, VariableDeclStmt) else None
    start = literal(init) if init is not None else None
    cond = stmt.condition
    if start is None or not isinstance(cond, BinaryExpr):
        return True
    bound = literal(cond.right)
    if bound is None:
        return True
    if cond.op == "<":
        count = bound - start
    elif cond.op == "<=":
        count = bound - start + 1
    elif cond.op == ">":
        count = start - bound
    elif cond.op == ">=":
        count = start - bound + 1
    else:
        return True
    return count >= 2


# ---------------------------------------------------------------------------
# Affine types
# ---------------------------------------------------------------------------

_AFFINE_TYPES: frozenset[str] = frozenset({"Sig", "SigHashPreimage"})

_CONSUMING_FUNCTIONS: dict[str, list[int]] = {
    "checkSig":      [0],
    "checkMultiSig": [0],
    "checkPreimage": [0],
}


# ---------------------------------------------------------------------------
# Type checker
# ---------------------------------------------------------------------------

def _consumed_param_summary(
    contract: ContractNode,
) -> dict[str, tuple[list[int], list[str]]]:
    """N-109: run the affine checker over each method body with throwaway
    diagnostics and record which parameters (and, N-288, which ``prop:<name>``
    property origins) end up consumed. Reusing the
    checker inherits alias, if-arm and loop handling. Consumption only grows as
    summaries grow, so iterating until no entry changes terminates, also for
    recursive call graphs (refused separately by the validator). Mirrors
    ``consumedParamSummary`` in the TS reference 03-typecheck.ts."""
    summary: dict[str, tuple[list[int], list[str]]] = {
        m.name: ([], []) for m in contract.methods
    }
    changed = True
    while changed:
        changed = False
        for method in contract.methods:
            scratch = _TypeChecker(contract)
            scratch._consumed_params = summary
            consumed = scratch._consumed_param_indices(method)
            prev = summary[method.name]
            if len(consumed[0]) != len(prev[0]) or len(consumed[1]) != len(prev[1]):
                summary[method.name] = consumed
                changed = True
    return summary


class _TypeChecker:
    def __init__(self, contract: ContractNode) -> None:
        self.contract = contract
        self.errors: list[Diagnostic] = []
        self.prop_types: dict[str, str] = {}
        self.method_sigs: dict[str, FuncSig] = {}
        # Origin keys of affine values consumed in the current scope.
        # 2026-04-30 audit finding F6.
        self.consumed_values: dict[str, bool] = {}
        # Maps a local variable name to the canonical affine origin
        # it aliases. Populated when a VariableDeclStmt of affine
        # type is initialized from another affine origin.
        self.affine_aliases: dict[str, str] = {}
        # F-110: for every enclosing loop that may run two or more times, the
        # env scope index its init/body bindings live at (innermost last). A
        # bounded loop is unrolled ``count`` times, so consuming an affine
        # value bound below the innermost index happens once per iteration.
        self._repeating_loop_scopes: list[int] = []
        self._current_method_loc: SourceLocation | None = None
        self._current_stmt_loc: SourceLocation | None = None
        # Lazily computed side-effect summary (F-075).
        self._side_effects: dict[str, MethodEffects] | None = None
        # N-109: for every contract method, the indices of the parameters it
        # consumes (directly or through further helper calls). Private helpers
        # are inlined, so a call consumes the arguments at those positions.
        # N-288: each entry also carries the ``prop:<name>`` origins the
        # method consumes, which a call consumes in the caller.
        # Computed lazily by _consumed_param_summary.
        self._consumed_params: dict[str, tuple[list[int], list[str]]] | None = None

        for prop in contract.properties:
            self.prop_types[prop.name] = _type_node_to_string(prop.type)

        # For StatefulSmartContract, add the implicit txPreimage property
        if contract.parent_class == "StatefulSmartContract":
            self.prop_types["txPreimage"] = "SigHashPreimage"

        for method in contract.methods:
            params = [_type_node_to_string(p.type) for p in method.params]
            ret_type = "void"
            if method.visibility != "public":
                ret_type = _infer_method_return_type(method)
            self.method_sigs[method.name] = FuncSig(params=params, return_type=ret_type)

    def _refuse_continuation_amount_write(self, target) -> None:
        """F-024 (R14): ``continuationAmount()`` is a read-only view of the
        auto-injected ``_newAmount``. Without this check an assignment to it
        would lower as a plain read and silently drop the write."""
        if (isinstance(target, CallExpr) and isinstance(target.callee, Identifier)
                and target.callee.name == "continuationAmount"):
            self._add_error(CONTINUATION_AMOUNT_READ_ONLY)

    def _add_error(self, msg: str, at: Expression | None = None) -> None:
        # N-321: a message may echo user-written type text of any length; cap it.
        if len(msg) > MAX_DIAGNOSTIC_CHARS:
            msg = f"{msg[:MAX_DIAGNOSTIC_CHARS]}...({len(msg) - MAX_DIAGNOSTIC_CHARS} more bytes elided)"
        # N-463: an error about an expression is anchored at that expression,
        # as in TS, when its position is known (every surface parser records
        # it); otherwise at the statement, then the method, as before.
        loc = _expr_loc(at) if at is not None else None
        if loc is None:
            loc = self._current_stmt_loc if self._current_stmt_loc is not None else self._current_method_loc
        self.errors.append(Diagnostic(message=msg, severity=Severity.ERROR, loc=loc))

    def _add_operand_error(self, msg: str, operand: Expression) -> None:
        # N-472: an operand type error is anchored at the operand with no
        # fallback, as TS does with ``operand.sourceLocation``. A bigint or
        # boolean literal carries no location in any TS parser, so the
        # diagnostic prints none rather than the statement. Any other operand
        # without a recorded position (a surface that does not record it)
        # keeps ``_add_error``'s statement anchor.
        if _expr_loc(operand) is None and isinstance(operand, (BigIntLiteral, BoolLiteral)):
            if len(msg) > MAX_DIAGNOSTIC_CHARS:
                msg = f"{msg[:MAX_DIAGNOSTIC_CHARS]}...({len(msg) - MAX_DIAGNOSTIC_CHARS} more bytes elided)"
            self.errors.append(Diagnostic(message=msg, severity=Severity.ERROR, loc=None))
            return
        self._add_error(msg, operand)

    def check_property_initializers(self) -> None:
        """N-234: a scalar property initializer whose literal type does not
        match the declared property type compiled without complaint on
        every tier (``readonly x: bigint = toByteString('ab')`` emitted a
        locking script that pushes a byte string where the contract's own
        arithmetic expects a script NUMBER). The validator only checks that
        an initializer IS a literal of one of the three families, never
        that it is a literal OF THE DECLARED TYPE. FixedArray properties
        are skipped here: their element-type check already lives in
        expand_fixed_arrays.py (N-133), which runs on the expanded array
        elements, not the whole-array initializer this pass sees. Mirrors
        the TS reference's method of the same name in 03-typecheck.ts.
        """
        for prop in self.contract.properties:
            if prop.initializer is None:
                continue
            if isinstance(prop.type, FixedArrayType):
                continue
            init_type = _infer_expr_type_static(prop.initializer)
            if init_type == "<unknown>":
                continue
            declared_type = _type_node_to_string(prop.type)
            if not is_subtype(init_type, declared_type):
                self._current_method_loc = prop.source_location
                self._add_error(
                    f"type '{init_type}' is not assignable to type '{declared_type}'"
                )

    def check_constructor(self) -> None:
        ctor = self.contract.constructor
        env = _TypeEnv()

        # Set current method location for diagnostics
        self._current_method_loc = ctor.source_location

        # Reset affine tracking
        self.consumed_values = {}
        self.affine_aliases = {}

        for param in ctor.params:
            env.define(param.name, _type_node_to_string(param.type))
        for prop in self.contract.properties:
            env.define(prop.name, _type_node_to_string(prop.type))

        self._check_statements(ctor.body, env)

    def _method_effects(self, name: str) -> MethodEffects:
        """The named method's effects, following private helpers (F-075)."""
        if self._side_effects is None:
            self._side_effects = compute_side_effect_summary(self.contract)
        return self._side_effects.get(name) or MethodEffects()

    def check_method(self, method: MethodNode) -> None:
        env = _TypeEnv()

        # Set current method location for diagnostics
        self._current_method_loc = method.source_location

        # Reset affine tracking
        self.consumed_values = {}
        self.affine_aliases = {}

        for param in method.params:
            env.define(param.name, _type_node_to_string(param.type))

        self._check_statements(method.body, env)

        # Crit-3 — reject mixing requireOutputP2PKH with addDataOutput in the
        # same method body. The intrinsic's compile-time output-offset
        # computation assumes a fixed 34-byte stride per output, which is
        # silently wrong when an OP_RETURN output (variable length) precedes
        # the indexed P2PKH output. Caller would get a runtime
        # OP_EQUALVERIFY failure only if the specific output index is
        # exercised — attackers could route the bond P2PKH through an
        # unmatched index. v1 forbids the mix; v2 may relax with a
        # variable-stride decoder.
        #
        # F-075: all three guards here read the method's effects from
        # compute_side_effect_summary, which follows the private-helper call
        # graph — the same analysis ANF lowering injects the continuation from,
        # and ANF lowering inlines private helpers. A body-local walk let a
        # developer disable every guard by moving the triggering call into a
        # helper.
        effects = self._method_effects(method.name)
        has_require_p2pkh = effects.calls_require_output_p2pkh
        has_add_data_output = effects.has_data_output
        if has_require_p2pkh and has_add_data_output:
            self._add_error(
                f"method '{method.name}' mixes requireOutputP2PKH() with addDataOutput() — "
                "v1 of the intrinsic assumes a fixed 34-byte output stride and "
                "variable-length OP_RETURN outputs break the offset computation; "
                "split the addDataOutput call into a separate method"
            )

        # Reject requireOutputP2PKH(0) in a method whose implicit single-output
        # state continuation ALSO claims output 0. A StatefulSmartContract
        # method that mutates state but uses no this.addOutput()/addRawOutput()
        # re-creates the contract's own (large codePart) script at output 0;
        # requiring output 0 to also be a 34-byte P2PKH is impossible
        # (codePart >= 253 bytes forces a 3-byte CompactSize length prefix,
        # never the P2PKH template's 0x19), so the contract is PERMANENTLY
        # unspendable. The terminal case (no state mutation -> no continuation)
        # stays valid.
        #
        # R-300: "addOutput/addRawOutput layouts are left to the developer" used
        # to finish that sentence, and it was wrong -- no layout the developer
        # can pick makes the offsets work. this.addOutput(...) writes the
        # continuation (codePart plus serialised state, hundreds of bytes) at
        # output 0, so outputIndex*34 lands INSIDE that script for every index.
        # addRawOutput's length is a runtime value, so the stride cannot be
        # proven there either. See
        # conformance/negatives/N34-p2pkh-index-with-state-output.runar.ts.
        if self.contract.parent_class == "StatefulSmartContract":
            if has_require_p2pkh and effects.has_state_output:
                self._add_error(
                    f"method '{method.name}' mixes requireOutputP2PKH() with "
                    "this.addOutput()/addRawOutput() — the intrinsic reads output i at byte "
                    "offset i*34, which is only correct when every earlier output is exactly "
                    "34 bytes, and a state-continuation output never is (codePart plus "
                    "serialised state). The assertion would read bytes from the middle of the "
                    "contract's own locking script, so the contract would be permanently "
                    "unspendable. Assert the payment from a separate method that emits no "
                    "output of its own"
                )
            if (
                effects.requires_output_p2pkh_zero
                and effects.mutates_state
                and not effects.has_state_output
            ):
                self._add_error(
                    f"method '{method.name}' calls requireOutputP2PKH(0, ...) but also mutates state "
                    "without this.addOutput()/addRawOutput() — the auto-injected single-output state "
                    "continuation already claims output 0 (the contract's codePart), so output 0 cannot "
                    "simultaneously be the required 34-byte P2PKH. This contract would be permanently "
                    "unspendable. Assert the bond on a non-continuation output index, or make the method "
                    "terminal (no state mutation)"
                )

    def _check_statements(self, stmts: list[Statement], env: _TypeEnv) -> None:
        for stmt in stmts:
            self._check_statement(stmt, env)

    def _check_statement(self, stmt: Statement, env: _TypeEnv) -> None:
        # Set statement-level source location for diagnostics
        prev_stmt_loc = self._current_stmt_loc
        stmt_loc = _stmt_source_location(stmt)
        if stmt_loc is not None:
            self._current_stmt_loc = stmt_loc

        if isinstance(stmt, VariableDeclStmt):
            init_type = self._infer_expr_type(stmt.init, env)
            if stmt.type is not None:
                declared_type = _type_node_to_string(stmt.type)
                if not is_subtype(init_type, declared_type):
                    self._add_error(
                        f"type '{init_type}' is not assignable to type '{declared_type}'"
                    )
                env.define(stmt.name, declared_type)
                decl_type = declared_type
            else:
                env.define(stmt.name, init_type)
                decl_type = init_type
            # Record affine alias when the new local is affine-typed
            # and its initializer is itself an affine origin
            # (parameter or contract property). 2026-04-30 audit
            # finding F6.
            if decl_type in _AFFINE_TYPES and stmt.init is not None:
                origin = self._affine_origin_of_expr(stmt.init)
                if origin is not None:
                    self.affine_aliases[stmt.name] = origin

        elif isinstance(stmt, AssignmentStmt):
            self._refuse_continuation_amount_write(stmt.target)
            target_type = self._infer_expr_type(stmt.target, env)
            value_type = self._infer_expr_type(stmt.value, env)
            if not is_subtype(value_type, target_type):
                self._add_error(
                    f"type '{value_type}' is not assignable to type '{target_type}'"
                )

        elif isinstance(stmt, IfStmt):
            cond_type = self._infer_expr_type(stmt.condition, env)
            if cond_type != "boolean":
                self._add_error(f"if condition must be boolean, got '{cond_type}'")
            # F-222: the arms are mutually exclusive, so each is checked
            # against the consumed set as it stood before the if; afterwards a
            # value consumed in either arm counts as consumed.
            consumed_before = dict(self.consumed_values)
            env.push_scope()
            self._check_statements(stmt.then, env)
            env.pop_scope()
            consumed_after_then = self.consumed_values
            self.consumed_values = consumed_before
            if stmt.else_:
                env.push_scope()
                self._check_statements(stmt.else_, env)
                env.pop_scope()
            self.consumed_values.update(consumed_after_then)

        elif isinstance(stmt, ForStmt):
            loop_scope = env.depth
            repeats = _loop_may_run_twice(stmt)
            env.push_scope()
            self._check_statement(stmt.init, env)
            cond_type = self._infer_expr_type(stmt.condition, env)
            if cond_type != "boolean":
                self._add_error(
                    f"for loop condition must be boolean, got '{cond_type}'"
                )
            # R-065: the update clause used to be skipped entirely, so
            # ``for (let i = 0n; i < 3n; undefinedFn())`` compiled clean -- a
            # hole in the rule that only Rúnar builtins and contract methods
            # are callable (CLAUDE.md names ``console.log`` explicitly).
            # validator.py separately restricts the clause to a unit-step
            # advance; this is the type-level half of the same guard.
            self._check_statement(stmt.update, env)
            # F-110: the body runs once per iteration; see
            # ``_repeating_loop_scopes``.
            if repeats:
                self._repeating_loop_scopes.append(loop_scope)
            self._check_statements(stmt.body, env)
            if repeats:
                self._repeating_loop_scopes.pop()
            env.pop_scope()

        elif isinstance(stmt, ExpressionStmt):
            self._infer_expr_type(stmt.expr, env)

        elif isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                self._infer_expr_type(stmt.value, env)

        # Restore previous statement location
        self._current_stmt_loc = prev_stmt_loc

    # -------------------------------------------------------------------
    # Type inference
    # -------------------------------------------------------------------

    def _infer_expr_type(self, expr: Expression | None, env: _TypeEnv) -> str:
        if expr is None:
            return "<unknown>"

        if isinstance(expr, BigIntLiteral):
            return "bigint"
        if isinstance(expr, BoolLiteral):
            return "boolean"
        if isinstance(expr, ByteStringLiteral):
            return "ByteString"

        if isinstance(expr, Identifier):
            if expr.name == "this":
                return "<this>"
            if expr.name == "super":
                return "<super>"
            if expr.name in ("true", "false"):
                return "boolean"
            # The blank identifier. `_ = x` is the Go / Rust / Zig discard idiom and
            # the Go DSL frontend emits it as an assignment TARGET, so it reaches the
            # identifier arm as a name to be typed. It is a discard, not a reference:
            # nothing is being looked up, so `undefined` is the wrong word for it.
            # Measured at the parent commit, go/rust/python/zig/ruby/java all compiled
            # `_ = doubled` to the same 7652957c009c77 while TS alone refused it with
            # "Undefined variable '_'" — invariant 1 (all seven parse all nine
            # surfaces) already broken for this shape. Listing it here rather than
            # letting the new fall-through reject it keeps the six tiers' bytes and
            # brings the seventh into line.
            if expr.name == "_":
                return "<unknown>"
            t, found = env.lookup(expr.name)
            if found:
                return t
            if expr.name in BUILTIN_FUNCTIONS:
                return "<builtin>"
            # A contract property named without a receiver. Java lets a method say
            # `strikePrice` for `this.strikePrice`, and the Solidity frontend emits the
            # same shape; the TS reference tier has resolved it here since that frontend
            # landed. Without this the identifier types as `<unknown>` and any operator
            # that demands a type rejects valid source — a frontend parity break the
            # `--parse-only` matrix cannot see, because the identifier PARSES fine and
            # only fails to RESOLVE.
            if expr.name in self.prop_types:
                return self.prop_types[expr.name]
            if expr.name in KNOWN_GLOBALS:
                return KNOWN_GLOBALS[expr.name]
            # GK-BUG-009 -- a name that resolves to nothing is an error HERE, at
            # the only pass that can see the binding environment. It used to
            # return "<unknown>" silently, and "<unknown>" is compatible with
            # everything under is_subtype by design (R-092), so
            # `notAThing === 1n` raised nothing. `notAThing > 1n` did raise --
            # is_bigint_family does not admit "<unknown>" -- which is why
            # R-085's `>` pin read as closed while the `===` path was wide open.
            # Where the reference is reachable from codegen, stack lowering
            # later refuses to emit an OP_0 placeholder and the compile still
            # fails, but for the wrong reason and with a message that calls the
            # name a "method parameter"; where it is NOT reachable (an uncalled
            # private helper, a zero-iteration loop) nothing fired at all and
            # the contract compiled to a locking script.
            self._add_error(f"Undefined variable '{expr.name}'")
            return "<unknown>"

        if isinstance(expr, PropertyAccessExpr):
            if expr.property in self.prop_types:
                return self.prop_types[expr.property]
            return "<unknown>"

        if isinstance(expr, MemberExpr):
            obj_type = self._infer_expr_type(expr.object, env)
            if obj_type == "<this>":
                if expr.property in self.prop_types:
                    return self.prop_types[expr.property]
                if expr.property in self.method_sigs:
                    return "<method>"
                if expr.property == "getStateScript":
                    return "<method>"
                return "<unknown>"
            if isinstance(expr.object, Identifier) and expr.object.name == "SigHash":
                return "bigint"
            return "<unknown>"

        if isinstance(expr, BinaryExpr):
            return self._check_binary_expr(expr, env)

        if isinstance(expr, UnaryExpr):
            return self._check_unary_expr(expr, env)

        if isinstance(expr, CallExpr):
            return self._check_call_expr(expr, env)

        if isinstance(expr, TernaryExpr):
            cond_type = self._infer_expr_type(expr.condition, env)
            if cond_type != "boolean":
                self._add_error(
                    f"ternary condition must be boolean, got '{cond_type}'"
                )
            cons_type = self._infer_expr_type(expr.consequent, env)
            alt_type = self._infer_expr_type(expr.alternate, env)
            if cons_type != alt_type:
                if is_subtype(alt_type, cons_type):
                    return cons_type
                if is_subtype(cons_type, alt_type):
                    return alt_type
                # N-099: arms related in NEITHER direction used to fall through
                # to ``return cons_type``, silently retyping the alternate. A
                # ByteString and a bigint do not share a stack representation --
                # one is a byte string, the other a script number -- so the
                # retyped arm leaves the wrong kind of value on the stack and
                # everything downstream reads a type the author never wrote.
                # ts / rust / java already refused this; go / python / zig /
                # ruby accepted it.
                #
                # Ported from the TypeScript reference (Rust carries it
                # verbatim), wording included -- hence the capital T, which
                # differs from the lowercase house style of the condition
                # message above. That casing divergence is pre-existing and left
                # alone; the new message matches TS so the seven tiers agree.
                #
                # ``<unknown>`` never reaches here: is_subtype treats it as top
                # of the lattice, so a private helper's return type is related to
                # everything, exactly as in TS.
                self._add_error(
                    f"Ternary branches have incompatible types: "
                    f"'{cons_type}' and '{alt_type}'",
                    expr,
                )
            return cons_type

        if isinstance(expr, IndexAccessExpr):
            obj_type = self._infer_expr_type(expr.object, env)
            index_type = self._infer_expr_type(expr.index, env)
            if not is_bigint_family(index_type):
                self._add_error(f"array index must be bigint, got '{index_type}'")
            if obj_type.endswith("[]"):
                return obj_type[:-2]
            return "<unknown>"

        if isinstance(expr, IncrementExpr):
            self._refuse_continuation_amount_write(expr.operand)
            operand_type = self._infer_expr_type(expr.operand, env)
            if not is_bigint_family(operand_type):
                self._add_error(f"++ operator requires bigint, got '{operand_type}'")
            return "bigint"

        if isinstance(expr, DecrementExpr):
            self._refuse_continuation_amount_write(expr.operand)
            operand_type = self._infer_expr_type(expr.operand, env)
            if not is_bigint_family(operand_type):
                self._add_error(f"-- operator requires bigint, got '{operand_type}'")
            return "bigint"

        if isinstance(expr, ArrayLiteralExpr):
            # F-063: without this arm every array literal typed as "<unknown>"
            # -- which is_subtype accepts against anything, making
            # checkMultiSig's argument check vacuous -- and its elements were
            # never visited, so a call nested in one never reached the
            # unknown-function rule. Ported from the TS reference, wording
            # included.
            if not expr.elements:
                return "<unknown>[]"
            elem_type = self._infer_expr_type(expr.elements[0], env)
            for el in expr.elements[1:]:
                et = self._infer_expr_type(el, env)
                if not is_subtype(et, elem_type) and et != "<unknown>":
                    self._add_error(
                        f"Array element type mismatch: expected '{elem_type}', got '{et}'"
                    )
            return elem_type + "[]"

        return "<unknown>"

    # -------------------------------------------------------------------
    # Binary expression type checking
    # -------------------------------------------------------------------

    def _check_binary_expr(self, e: BinaryExpr, env: _TypeEnv) -> str:
        left_type = self._infer_expr_type(e.left, env)
        right_type = self._infer_expr_type(e.right, env)

        # ByteString concatenation: ByteString + ByteString -> ByteString (via OP_CAT)
        if e.op == "+" and is_byte_family(left_type) and is_byte_family(right_type):
            return "ByteString"

        # Arithmetic: bigint x bigint -> bigint
        if e.op in ("+", "-", "*", "/", "%"):
            if not is_bigint_family(left_type):
                self._add_operand_error(
                    f"left operand of '{e.op}' must be bigint, got '{left_type}'",
                    e.left,
                )
            if not is_bigint_family(right_type):
                self._add_operand_error(
                    f"right operand of '{e.op}' must be bigint, got '{right_type}'",
                    e.right,
                )
            return "bigint"

        if e.op in ("<", "<=", ">", ">="):
            if not is_bigint_family(left_type):
                self._add_operand_error(
                    f"left operand of '{e.op}' must be bigint, got '{left_type}'",
                    e.left,
                )
            if not is_bigint_family(right_type):
                self._add_operand_error(
                    f"right operand of '{e.op}' must be bigint, got '{right_type}'",
                    e.right,
                )
            return "boolean"

        if e.op in ("===", "!=="):
            # Exactly the reference tier's rule: each side is tried as a
            # subtype of the other, and nothing else. The both-in-family
            # clauses that used to sit here were this tier's local patch for an
            # is_subtype that lacked them (N-104); is_subtype carries them now,
            # so repeating them here would be a second copy of the lattice to
            # drift out of sync.
            compatible = is_subtype(left_type, right_type) or is_subtype(
                right_type, left_type
            )
            if not compatible:
                if left_type != "<unknown>" and right_type != "<unknown>":
                    self._add_error(
                        f"cannot compare '{left_type}' and '{right_type}' with '{e.op}'",
                        e,
                    )
            return "boolean"

        if e.op in ("&&", "||"):
            if left_type != "boolean" and left_type != "<unknown>":
                self._add_operand_error(
                    f"left operand of '{e.op}' must be boolean, got '{left_type}'",
                    e.left,
                )
            if right_type != "boolean" and right_type != "<unknown>":
                self._add_operand_error(
                    f"right operand of '{e.op}' must be boolean, got '{right_type}'",
                    e.right,
                )
            return "boolean"

        if e.op in ("<<", ">>"):
            if not is_bigint_family(left_type):
                self._add_operand_error(
                    f"left operand of '{e.op}' must be bigint, got '{left_type}'",
                    e.left,
                )
            if not is_bigint_family(right_type):
                self._add_operand_error(
                    f"right operand of '{e.op}' must be bigint, got '{right_type}'",
                    e.right,
                )
            return "bigint"

        # Bitwise operators: bigint x bigint -> bigint, or ByteString x ByteString -> ByteString
        if e.op in ("&", "|", "^"):
            if is_byte_family(left_type) and is_byte_family(right_type):
                return "ByteString"
            if not is_bigint_family(left_type):
                self._add_operand_error(
                    f"left operand of '{e.op}' must be bigint or ByteString, got '{left_type}'",
                    e.left,
                )
            if not is_bigint_family(right_type):
                self._add_operand_error(
                    f"right operand of '{e.op}' must be bigint or ByteString, got '{right_type}'",
                    e.right,
                )
            return "bigint"

        return "<unknown>"

    # -------------------------------------------------------------------
    # Unary expression type checking
    # -------------------------------------------------------------------

    def _check_unary_expr(self, e: UnaryExpr, env: _TypeEnv) -> str:
        operand_type = self._infer_expr_type(e.operand, env)

        if e.op == "!":
            if operand_type != "boolean" and operand_type != "<unknown>":
                self._add_error(
                    f"operand of '!' must be boolean, got '{operand_type}'",
                    e,
                )
            return "boolean"

        if e.op == "-":
            if not is_bigint_family(operand_type):
                self._add_error(
                    f"operand of unary '-' must be bigint, got '{operand_type}'",
                    e,
                )
            return "bigint"

        if e.op == "~":
            if is_byte_family(operand_type):
                return "ByteString"
            if not is_bigint_family(operand_type):
                self._add_error(
                    f"operand of '~' must be bigint or ByteString, got '{operand_type}'",
                    e,
                )
            return "bigint"

        return "<unknown>"

    # -------------------------------------------------------------------
    # Call expression type checking
    # -------------------------------------------------------------------

    def _check_call_expr(self, e: CallExpr, env: _TypeEnv) -> str:
        # super() call
        if isinstance(e.callee, Identifier) and e.callee.name == "super":
            for arg in e.args:
                self._infer_expr_type(arg, env)
            return "void"

        # Direct builtin call
        if isinstance(e.callee, Identifier):
            name = e.callee.name
            # asm is a compile-time intrinsic -- the parser has already
            # rewritten the { body, in_arity?, out_arity? } object-literal
            # argument into three positional args (body, in_arity, out_arity).
            # The statement form returns void; the expression form
            # asm<T>({...}) carries the captured return type on
            # asm_return_type and produces a value of that type.
            if name == "asm":
                for arg in e.args:
                    self._infer_expr_type(arg, env)
                if e.asm_return_type:
                    return e.asm_return_type
                return "void"
            if name in BUILTIN_FUNCTIONS:
                return self._check_call_args(name, BUILTIN_FUNCTIONS[name], e.args, env)
            # Check if it's a known contract method
            if name in self.method_sigs:
                return self._check_call_args(name, self.method_sigs[name], e.args, env)
            # Check if it's a local variable -- F-208: Rúnar has no
            # first-class functions, so a bound local can never be called.
            # This used to return "<unknown>" with no diagnostic, silently
            # accepting `const f: bigint = a; const r = f(a, a, a);`.
            _, found = env.lookup(name)
            if found:
                self._add_error(
                    f"local variable '{name}' is not callable -- Runar has "
                    f"no first-class functions; only built-in functions and "
                    f"contract methods can be called"
                )
                for arg in e.args:
                    self._infer_expr_type(arg, env)
                return "<unknown>"
            if name in GO_ONLY_BUILTINS:
                family = GO_ONLY_BUILTINS[name]
                self._add_error(
                    f"builtin '{name}' belongs to the {family} family, which is "
                    f"scoped to the Go tier by project policy -- see CLAUDE.md "
                    f"(\"EVM/STARK proof-system primitives\") and "
                    f"conformance/README.md (\"Per-fixture compiler allowlist\"). "
                    f"Compile this contract with the Go compiler, or opt the "
                    f"fixture out of the Python tier via source.json's "
                    f"\"compilers\" allowlist."
                )
            else:
                self._add_error(
                    f"unknown function '{name}' -- only Runar built-in functions "
                    f"and contract methods are allowed"
                )
            for arg in e.args:
                self._infer_expr_type(arg, env)
            return "<unknown>"

        # this.method() via PropertyAccessExpr
        if isinstance(e.callee, PropertyAccessExpr):
            prop = e.callee.property
            if prop == "getStateScript":
            # R-173: the builtin takes none -- it returns the contract's own
            # state script, a property of the contract rather than of
            # anything a caller could pass. Five tiers used to accept
            # arguments and DISCARD them, emitting hex byte-identical to the
            # zero-argument spelling. Message is the reference tier's.
                if e.args:
                    self._add_error("getStateScript() takes no arguments")
                return "ByteString"
            if prop in ("addOutput", "addRawOutput", "addDataOutput"):
                return self._check_output_intrinsic_args(prop, e.args, env)
            if prop in self.method_sigs:
                return self._check_call_args(prop, self.method_sigs[prop], e.args, env)
            self._add_error(
                f"unknown method 'this.{prop}' -- only Runar built-in methods "
                f"and contract methods are allowed"
            )
            for arg in e.args:
                self._infer_expr_type(arg, env)
            return "<unknown>"

        # this.method() via MemberExpr
        if isinstance(e.callee, MemberExpr):
            obj_type = self._infer_expr_type(e.callee.object, env)
            is_this = obj_type == "<this>" or (
                isinstance(e.callee.object, Identifier) and e.callee.object.name == "this"
            )
            if is_this:
                if e.callee.property == "getStateScript":
                    # R-173: see the property_access branch above.
                    if e.args:
                        self._add_error("getStateScript() takes no arguments")
                    return "ByteString"
                if e.callee.property in ("addOutput", "addRawOutput", "addDataOutput"):
                    return self._check_output_intrinsic_args(
                        e.callee.property, e.args, env
                    )
                if e.callee.property in self.method_sigs:
                    return self._check_call_args(
                        e.callee.property,
                        self.method_sigs[e.callee.property],
                        e.args,
                        env,
                    )
            # Not this.method -- reject (e.g. Math.floor)
            obj_name = "<expr>"
            if isinstance(e.callee.object, Identifier):
                obj_name = e.callee.object.name
            self._add_error(
                f"unknown function '{obj_name}.{e.callee.property}' -- only Runar "
                f"built-in functions and contract methods are allowed"
            )
            for arg in e.args:
                self._infer_expr_type(arg, env)
            return "<unknown>"

        # Fallback -- unknown callee shape
        self._add_error(
            "unsupported function call expression -- only Runar built-in "
            "functions and contract methods are allowed"
        )
        self._infer_expr_type(e.callee, env)
        for arg in e.args:
            self._infer_expr_type(arg, env)
        return "<unknown>"

    # -------------------------------------------------------------------
    # Argument checking
    # -------------------------------------------------------------------

    def _check_output_intrinsic_args(
        self,
        name: str,
        args: list[Expression],
        env: _TypeEnv,
    ) -> str:
        """Type-check the arguments of the three output intrinsics --
        ``this.addOutput`` / ``this.addRawOutput`` / ``this.addDataOutput`` --
        and return their result type.

        N-098: the first argument is the output's SATOSHI AMOUNT, and this tier
        used to accept any type there. That is not a missing lint.
        ``_lower_add_output`` prepends the operand as ``OP_8 OP_NUM2BIN``, so a
        ByteString in that slot is reinterpreted as a script number with no
        conversion and becomes the amount the covenant commits to:
        ``blob: ByteString`` and ``blob: bigint`` compiled to the SAME script,
        byte for byte. On the real ``@bsv/sdk`` Spend engine with
        ``blob = 0x2a`` only a 42-satoshi continuation validates, and blobs
        wider than 8 bytes abort at ``OP_NUM2BIN``, making the UTXO unspendable.

        N-105: the SECOND argument of addRawOutput / addDataOutput is the
        created output's LOCKING SCRIPT, and this tier used to accept any type
        there too. ``_lower_add_raw_output`` takes OP_SIZE of the operand,
        varint-prefixes it and concatenates it after the amount -- no
        conversion -- so ``n: bigint`` and ``n: ByteString`` compiled to the
        SAME script, byte for byte. A script number on the stack is its minimal
        little-endian encoding, so the covenant commits to an output whose
        locking script IS those bytes. Executed on the real ``@bsv/sdk`` Spend
        engine against the exact opcode window this tier emits: n=0 gives an
        EMPTY locking script, n=81 gives OP_1 and n=118 gives OP_DUP -- all
        three anyone-can-spend -- while n=1000 gives 0xe8 0x03, an invalid
        opcode, and the output is unspendable.

        N-105 (2/2): the remaining three checks TS performs and this tier did
        not -- the StatefulSmartContract gate, the arity of all three
        intrinsics, and the types of addOutput's state values. Each had an
        executed consequence: ``addOutput(1000n)`` dropped the state value from
        the continuation entirely, a surplus value was appended to a state
        serialization the next spend deserializes by fixed offsets, a ByteString
        state value was serialized where an 8-byte LE number belongs, and
        addRawOutput in a stateless SmartContract emitted a "continuation" for a
        contract with no state.

        Ported from the TypeScript reference, wording included.

        ``<unknown>`` is escaped exactly as TS escapes it -- a private helper's
        declared return type is discarded at parse time in every tier, so
        ``this.sats()`` infers as ``<unknown>`` and must keep compiling.
        """
        # N-105: all three intrinsics build an OUTPUT, and an output only
        # exists in a stateful contract. TS refuses the call outright and checks
        # nothing else, so the early return is part of the ported behaviour.
        if (
            self.contract is None
            or self.contract.parent_class != "StatefulSmartContract"
        ):
            self._add_error(f"{name}() is only available in StatefulSmartContract")
            return "void"

        if name == "addOutput":
            # The surface form ``this.addOutput(satoshis, .{ v1, v2, ... })``
            # that Zig and Move tuple syntax produce carries the state values in
            # a trailing array literal. anf_lower unwraps it with this same
            # helper, so the arity checked here is the arity codegen will see.
            from runar_compiler.frontend.anf_lower import _flatten_add_output_args

            normalized = _flatten_add_output_args(args)
            # N-107: count the state slots the continuation will actually
            # carry, not the DECLARED mutable properties. expand_fixed_arrays
            # runs right after this pass and splits ``board: FixedArray<bigint,
            # 3>`` into ``board__0 .. board__2``, so a contract declaring
            # ``board`` and ``n`` emits FOUR state values. addOutput is
            # positional against the emitted values, which is why the declared
            # count answers the wrong question.
            #
            # This used to be a ``shape_checkable`` flag that scoped the rule
            # OUT of every contract with FixedArray state, because porting it
            # verbatim would have rejected Boardy (in
            # tests/test_r025_expand_fixed_arrays_field_preservation.py) the way
            # the reference tier did. The cost of that opt-out was silent: a
            # wrong-arity addOutput on a FixedArray contract was ACCEPTED here
            # and emitted a state continuation one slot short of the contract's
            # own state. Gate:
            # conformance/negatives/N26-addoutput-arity-fixedarray.
            mutable_props = _expanded_state_slots(self.contract.properties)
            expected = 1 + len(mutable_props)
            if len(normalized) != expected:
                self._add_error(
                    f"addOutput() expects {expected} argument(s): satoshis + "
                    f"{len(mutable_props)} state value(s), got {len(normalized)}"
                )
            if len(normalized) >= 1:
                sat_type = self._infer_expr_type(normalized[0], env)
                if not is_bigint_family(sat_type) and sat_type != "<unknown>":
                    self._add_error(
                        "addOutput() first argument (satoshis) must be bigint, "
                        f"got '{sat_type}'",
                        args[0],
                    )
            i = 0
            while i < len(mutable_props) and i + 1 < len(normalized):
                arg_type = self._infer_expr_type(normalized[i + 1], env)
                prop_type = _type_node_to_string(mutable_props[i][1])
                if not is_subtype(arg_type, prop_type) and arg_type != "<unknown>":
                    self._add_error(
                        f"addOutput() argument {i + 2} ({mutable_props[i][0]}) "
                        f"must be '{prop_type}', got '{arg_type}'",
                        normalized[i + 1],
                    )
                i += 1
            # Surplus arguments are still inferred, so a type error inside one
            # is not swallowed by the arity diagnostic. Mirrors TS.
            for extra in normalized[expected:]:
                self._infer_expr_type(extra, env)
            return "void"

        # addRawOutput / addDataOutput -- (satoshis, scriptBytes).
        if len(args) != 2:
            self._add_error(
                f"{name}() expects 2 arguments (satoshis, scriptBytes), "
                f"got {len(args)}"
            )
        if len(args) >= 1:
            sat_type = self._infer_expr_type(args[0], env)
            if not is_bigint_family(sat_type) and sat_type != "<unknown>":
                self._add_error(
                    f"{name}() first argument (satoshis) must be bigint, "
                    f"got '{sat_type}'",
                    args[0],
                )
        if len(args) >= 2:
            # TS uses is_subtype against ByteString, not equality, so every
            # ByteString subtype (PubKey, Ripemd160, Sig, ...) stays accepted.
            script_type = self._infer_expr_type(args[1], env)
            if not is_subtype(script_type, "ByteString") and script_type != "<unknown>":
                self._add_error(
                    f"{name}() second argument (scriptBytes) must be ByteString, "
                    f"got '{script_type}'",
                    args[1],
                )
        return "void"

    def _check_call_args(
        self,
        func_name: str,
        sig: FuncSig,
        args: list[Expression],
        env: _TypeEnv,
    ) -> str:
        # assert special case
        if func_name == "assert":
            if len(args) < 1 or len(args) > 2:
                self._add_error(
                    f"assert() expects 1 or 2 arguments, got {len(args)}"
                )
            if len(args) >= 1:
                cond_type = self._infer_expr_type(args[0], env)
                if cond_type != "boolean" and cond_type != "<unknown>":
                    self._add_error(
                        f"assert() condition must be boolean, got '{cond_type}'"
                    )
            if len(args) >= 2:
                self._infer_expr_type(args[1], env)
            return sig.return_type

        # checkMultiSig special case (Sig[] / PubKey[] arrays). Only
        # arity is special; arg-type validation falls through to the
        # standard subtype loop below so callers cannot pass
        # bigint[] or other element types. 2026-04-30 audit finding
        # F5.
        if func_name == "checkMultiSig":
            if len(args) != 2:
                self._add_error(
                    f"checkMultiSig() expects 2 arguments, got {len(args)}"
                )
                for arg in args:
                    self._infer_expr_type(arg, env)
                self._check_affine_consumption(func_name, args, env)
                return sig.return_type
            # Fall through to the standard subtype check below.

        # extractPrevOutputScript / requireOutputP2PKH — the index arg MUST
        # be a compile-time integer literal so the ANF lowering can derive a
        # stable auto-injected witness-param name (extractPrevOutputScript) or
        # a constant byte offset (requireOutputP2PKH).
        if func_name in ("extractPrevOutputScript", "requireOutputP2PKH"):
            if len(args) >= 1:
                idx_lit: BigIntLiteral | None = None
                if isinstance(args[0], BigIntLiteral):
                    idx_lit = args[0]
                # Accept `-N` (UnaryExpr "-" over BigIntLiteral) so the bounds
                # check below produces a clear "must be >= 0" rather than the
                # misleading "must be an integer literal" message.
                elif (
                    isinstance(args[0], UnaryExpr)
                    and args[0].op == "-"
                    and isinstance(args[0].operand, BigIntLiteral)
                    # N-060: this arm exists ONLY to reach the "must be >= 0"
                    # message below, so it must surrender anything that is not
                    # actually negative. ``-0`` negates to 0 and would sail
                    # past that bound check, but ANF lowering matches on a bare
                    # BigIntLiteral: on a UnaryExpr it falls through to
                    # ``load_const ""`` and the covenant the intrinsic was
                    # supposed to install is silently absent. Let it fall to
                    # the non-literal-index diagnostic instead.
                    and -args[0].operand.value < 0
                ):
                    idx_lit = BigIntLiteral(value=-args[0].operand.value)
                if idx_lit is None:
                    self._add_error(
                        f"{func_name}() argument 1 (index) must be an integer literal"
                    )
                else:
                    # R-2: bound the index literal. For requireOutputP2PKH, the
                    # emitted Stack-IR computes byte-offset = idx * 34; require
                    # 0 <= idx <= 1000 to keep the offset well under script-int
                    # max and to reject obvious nonsense (e.g. negative or
                    # astronomically large).
                    idx = idx_lit.value
                    if idx < 0:
                        self._add_error(
                            f"{func_name}() argument 1 (index) must be >= 0; got {idx}"
                        )
                    if func_name == "requireOutputP2PKH" and idx > 0:
                        self._add_error(
                            f"requireOutputP2PKH() argument 1 (outputIndex) must be 0 in v1; got {idx}. The emitted Stack-IR reads output i at byte offset i*34, but Bitcoin outputs are variable length, so for i > 0 that offset is not an output boundary: an attacker sizes output 0 freely and places the expected 34 P2PKH bytes inside its OP_RETURN payload, leaving the transaction's real output i to pay whoever they like. Offset 0 IS a boundary, so index 0 is sound; other indexes need a CompactSize walk the v1 codegen does not emit"
                        )

        # extractPrevOutputScript variable-arity special case (2-arg full-hash
        # or 3-arg prefix-hash form). Validates types + literal-only on the
        # optional prefixLen, then returns the signature's return type to
        # bypass the standard arg-count check below (which would reject the
        # 3-arg form against the 2-arg sig table entry).
        if func_name == "extractPrevOutputScript":
            if len(args) != 2 and len(args) != 3:
                self._add_error(
                    f"extractPrevOutputScript() expects 2 or 3 arguments, got {len(args)}"
                )
            if len(args) >= 1:
                self._infer_expr_type(args[0], env)  # already validated as literal above
            if len(args) >= 2:
                arg_type = self._infer_expr_type(args[1], env)
                if not is_subtype(arg_type, "ByteString") and arg_type != "<unknown>":
                    self._add_error(
                        f"argument 2 of extractPrevOutputScript(): expected 'ByteString', got '{arg_type}'"
                    )
            if len(args) == 3:
                if not isinstance(args[2], BigIntLiteral):
                    self._add_error(
                        "extractPrevOutputScript() argument 3 (prefixLen) must be an integer literal when supplied"
                    )
                else:
                    # R-4: bound the prefixLen literal. The intrinsic hashes
                    # substr(witness, 0, prefixLen) and compares against a
                    # 32-byte SHA-256 hash. prefixLen < 32 is suspicious (the
                    # prefix bytes don't even cover a hash-sized chunk).
                    # prefixLen > 4 MiB exceeds MAX_SCRIPT_BYTES — wouldn't
                    # fit in a legal Bitcoin Script anyway.
                    n = args[2].value
                    if n < 32:
                        self._add_error(
                            f"extractPrevOutputScript() argument 3 (prefixLen) must be >= 32 (the hash assertion compares a 32-byte SHA-256); got {n}"
                        )
                    if n > 4 * 1024 * 1024:
                        self._add_error(
                            f"extractPrevOutputScript() argument 3 (prefixLen) must be <= MAX_SCRIPT_BYTES (4 MiB); got {n}"
                        )
                self._infer_expr_type(args[2], env)
            return sig.return_type

        # requireOutputP2PKH, currentBlockHeight and continuationAmount need
        # the auto-injected txPreimage / _newAmount -- only available in
        # StatefulSmartContract methods.
        if func_name in ("requireOutputP2PKH", "currentBlockHeight", "continuationAmount"):
            if self.contract is not None and self.contract.parent_class != "StatefulSmartContract":
                self._add_error(
                    f"{func_name}() is only available in StatefulSmartContract methods"
                )

        # F-265: substr(witness, start, len) lowers to a raw OP_SPLIT
        # argument. A literal negative start used to type-check as plain
        # 'bigint' (the standard subtype loop below never inspects a
        # literal's VALUE) and compile to a script that aborts at runtime
        # -- `-5n` minimal-encodes to `<85>`, which OP_SPLIT rejects. Catch
        # the literal case (bare or unary-negated BigIntLiteral) at compile
        # time, mirroring the extractPrevOutputScript/requireOutputP2PKH
        # "must be >= 0" pattern above. A non-literal start (a variable or
        # computed expression) has no static value to check and is
        # unaffected.
        if func_name == "substr" and len(args) >= 2:
            start_lit: BigIntLiteral | None = None
            if isinstance(args[1], BigIntLiteral):
                start_lit = args[1]
            elif (
                isinstance(args[1], UnaryExpr)
                and args[1].op == "-"
                and isinstance(args[1].operand, BigIntLiteral)
            ):
                start_lit = BigIntLiteral(value=-args[1].operand.value)
            if start_lit is not None and start_lit.value < 0:
                self._add_error(
                    f"substr() argument 2 (start) must be >= 0; got {start_lit.value}"
                )

        # Standard arg count check
        if len(args) != len(sig.params):
            self._add_error(
                f"{func_name}() expects {len(sig.params)} argument(s), got {len(args)}"
            )

        count = min(len(args), len(sig.params))

        for i in range(count):
            arg_type = self._infer_expr_type(args[i], env)
            expected_type = sig.params[i]
            if not is_subtype(arg_type, expected_type) and arg_type != "<unknown>":
                self._add_error(
                    f"argument {i + 1} of {func_name}(): expected '{expected_type}', "
                    f"got '{arg_type}'"
                )

        for i in range(count, len(args)):
            self._infer_expr_type(args[i], env)

        # Affine type enforcement
        self._check_affine_consumption(func_name, args, env)

        return sig.return_type

    # -------------------------------------------------------------------
    # Affine consumption
    # -------------------------------------------------------------------

    def _check_affine_consumption(
        self,
        func_name: str,
        args: list[Expression],
        env: _TypeEnv,
    ) -> None:
        """Track consumption by *origin*, not variable name, so aliases
        (`const again = sig`) and property accesses (`this.sig`) cannot
        launder a double-consumption past the affine check.
        2026-04-30 audit finding F6."""
        consumed_indices = _CONSUMING_FUNCTIONS.get(func_name)
        consumed_props: list[str] = []
        if consumed_indices is None:
            # N-109: a call to a contract method consumes the arguments at the
            # parameter positions that method consumes.
            if func_name in BUILTIN_FUNCTIONS or func_name not in self.method_sigs:
                return
            if self._consumed_params is None:
                self._consumed_params = _consumed_param_summary(self.contract)
            consumed_indices, consumed_props = self._consumed_params.get(func_name, ([], []))

        for param_index in consumed_indices:
            if param_index >= len(args):
                continue

            arg = args[param_index]
            arg_type = self._affine_expr_type(arg, env)
            if arg_type is None or arg_type not in _AFFINE_TYPES:
                continue

            origin = self._affine_origin_of_expr(arg)
            if origin is None:
                continue

            # Render a short label (source-form) for the diagnostic.
            if isinstance(arg, Identifier):
                label = arg.name
            elif isinstance(arg, PropertyAccessExpr):
                label = f"this.{arg.property}"
            else:
                label = origin

            if self.consumed_values.get(origin, False) or self._consumed_per_loop_iteration(origin, env):
                self._add_error(
                    f"affine value '{label}' has already been consumed",
                    arg,
                )
            else:
                self.consumed_values[origin] = True

        # N-288: the call also consumes every property the method consumes.
        for origin in consumed_props:
            if self.consumed_values.get(origin, False) or self._consumed_per_loop_iteration(origin, env):
                self._add_error(
                    f"affine value 'this.{origin[len('prop:'):]}' has already been consumed",
                    args[0] if args else None,
                )
            else:
                self.consumed_values[origin] = True

    def _consumed_param_indices(self, method: MethodNode) -> tuple[list[int], list[str]]:
        """N-109: the indices of ``method``'s parameters its body consumes,
        and (N-288) the ``prop:<name>`` property origins it consumes."""
        env = _TypeEnv()
        self._current_method_loc = method.source_location
        self.consumed_values = {}
        self.affine_aliases = {}
        for param in method.params:
            env.define(param.name, _type_node_to_string(param.type))
        self._check_statements(method.body, env)
        indices = [i for i, p in enumerate(method.params) if self.consumed_values.get(p.name, False)]
        props = sorted(o for o, used in self.consumed_values.items() if used and o.startswith("prop:"))
        return indices, props

    def _consumed_per_loop_iteration(self, origin: str, env: _TypeEnv) -> bool:
        """F-110: true when ``origin`` is bound outside the innermost enclosing
        loop that may run two or more times, so this one syntactic consumption
        is executed once per iteration -- a double use. A property, or a name
        the env does not bind (a bare-identifier property), is always outside."""
        if not self._repeating_loop_scopes:
            return False
        if origin.startswith("prop:"):
            return True
        return env.scope_index_of(origin) < self._repeating_loop_scopes[-1]

    def _affine_origin_of_expr(self, expr: Expression) -> str | None:
        """Resolve the canonical affine origin for an expression.
        Identifiers consult the alias map; property accesses use a
        ``prop:<name>`` namespace."""
        if isinstance(expr, Identifier):
            return self.affine_aliases.get(expr.name, expr.name)
        if isinstance(expr, PropertyAccessExpr):
            return f"prop:{expr.property}"
        return None

    def _affine_expr_type(self, expr: Expression, env: _TypeEnv) -> str | None:
        """Look up the type of an expression for affine purposes."""
        if isinstance(expr, Identifier):
            arg_type, found = env.lookup(expr.name)
            return arg_type if found else None
        if isinstance(expr, PropertyAccessExpr):
            return self.prop_types.get(expr.property)
        return None


# ---------------------------------------------------------------------------
# Private method return type inference
# ---------------------------------------------------------------------------

def _infer_method_return_type(method: MethodNode) -> str:
    """Walk a private method body, collect return types, and unify them."""
    return_types = _collect_return_types(method.body)
    if not return_types:
        return "void"

    first = return_types[0]
    if all(t == first for t in return_types):
        return first

    # Check if all are in the bigint family
    if all(t in _BIGINT_SUBTYPES for t in return_types):
        return "bigint"

    # Check if all are in the ByteString family
    if all(t in _BYTESTRING_SUBTYPES for t in return_types):
        return "ByteString"

    # Check if all are boolean
    if all(t == "boolean" for t in return_types):
        return "boolean"

    return first


def _collect_return_types(stmts: list[Statement]) -> list[str]:
    """Recursively collect inferred types from return statements."""
    types: list[str] = []
    for stmt in stmts:
        if isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                types.append(_infer_expr_type_static(stmt.value))
        elif isinstance(stmt, IfStmt):
            types.extend(_collect_return_types(stmt.then))
            if stmt.else_:
                types.extend(_collect_return_types(stmt.else_))
        elif isinstance(stmt, ForStmt):
            types.extend(_collect_return_types(stmt.body))
    return types


def _infer_expr_type_static(expr: Expression | None) -> str:
    """Lightweight expression type inference without a type environment.

    Used for inferring return types of private methods before the full
    type-check pass runs.
    """
    if expr is None:
        return "<unknown>"

    if isinstance(expr, BigIntLiteral):
        return "bigint"
    if isinstance(expr, BoolLiteral):
        return "boolean"
    if isinstance(expr, ByteStringLiteral):
        return "ByteString"

    if isinstance(expr, Identifier):
        if expr.name in ("true", "false"):
            return "boolean"
        return "<unknown>"

    if isinstance(expr, BinaryExpr):
        if expr.op in ("+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"):
            return "bigint"
        # Comparison, equality, logical operators -> boolean
        return "boolean"

    if isinstance(expr, UnaryExpr):
        if expr.op == "!":
            return "boolean"
        return "bigint"  # '-' and '~'

    if isinstance(expr, CallExpr):
        if isinstance(expr.callee, Identifier):
            # Expression-form asm<T>({...}) statically yields type T.
            if expr.callee.name == "asm" and expr.asm_return_type:
                return expr.asm_return_type
            sig = BUILTIN_FUNCTIONS.get(expr.callee.name)
            if sig is not None:
                return sig.return_type
        if isinstance(expr.callee, PropertyAccessExpr):
            sig = BUILTIN_FUNCTIONS.get(expr.callee.property)
            if sig is not None:
                return sig.return_type
        return "<unknown>"

    if isinstance(expr, TernaryExpr):
        cons_type = _infer_expr_type_static(expr.consequent)
        if cons_type != "<unknown>":
            return cons_type
        return _infer_expr_type_static(expr.alternate)

    if isinstance(expr, (IncrementExpr, DecrementExpr)):
        return "bigint"

    if isinstance(expr, ArrayLiteralExpr):
        return "<unknown>[]"

    return "<unknown>"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _type_node_to_string(node: TypeNode | None) -> str:
    """Convert a type node to its string representation."""
    if node is None:
        return "<unknown>"
    if isinstance(node, PrimitiveType):
        return node.name
    if isinstance(node, FixedArrayType):
        return _type_node_to_string(node.element) + "[]"
    if isinstance(node, CustomType):
        return node.name
    return "<unknown>"


def _expr_loc(expr: Expression) -> SourceLocation | None:
    """N-463: the position of ``expr``'s first token, or None when unknown.

    Only identifiers (``this`` included), ``this.x`` and ByteString literals
    record a position, and only on .runar.ts. A composite expression starts
    where its leftmost child starts, which is the position TS reports for it
    (a parenthesised leftmost child is the exception: TS points at the ``(``).
    """
    while True:
        if isinstance(expr, (Identifier, PropertyAccessExpr, ByteStringLiteral)):
            return expr.source_location
        if isinstance(expr, BinaryExpr):
            # N-472: the parser records where the whole expression
            # starts, which a leading ``(`` moves left of the leftmost leaf.
            if expr.source_location is not None:
                return expr.source_location
            expr = expr.left
        elif isinstance(expr, UnaryExpr):
            # N-472: the operator token; the other surfaces record none.
            return expr.source_location
        elif isinstance(expr, CallExpr):
            expr = expr.callee
        elif isinstance(expr, (MemberExpr, IndexAccessExpr)):
            expr = expr.object
        elif isinstance(expr, TernaryExpr):
            expr = expr.condition
        else:
            return None


def _stmt_source_location(stmt: Statement) -> SourceLocation | None:
    """Extract the SourceLocation from a statement node, if it has a meaningful value."""
    loc = getattr(stmt, "source_location", None)
    if loc is not None and (loc.file or loc.line > 0):
        return loc
    return None
