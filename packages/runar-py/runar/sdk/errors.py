"""Typed SDK errors raised by deploy / call / provider entry points."""

from __future__ import annotations

from .input_limits import MAX_SCRIPT_BYTES


class ScriptSizeExceededError(Exception):
    """Raised when a script exceeds :data:`MAX_SCRIPT_BYTES` at a public SDK
    entry point.

    Distinct typed exception so callers can distinguish DoS-bound rejection
    from generic decode / network errors.
    """

    def __init__(self, limit: int, actual: int, context: str) -> None:
        self.limit = limit
        self.actual = actual
        self.context = context
        super().__init__(
            f"script exceeds MAX_SCRIPT_BYTES (limit={limit}, actual={actual}, context={context})"
        )


def assert_script_hex_under_limit(
    script_hex: str,
    limit: int,
    context: str,
) -> None:
    """Raise :class:`ScriptSizeExceededError` if ``script_hex`` is over ``limit`` bytes.

    A hex-encoded script is 2 chars per byte; odd-length inputs are
    handled defensively by rounding up.
    """
    actual_bytes = (len(script_hex) + 1) // 2
    if actual_bytes > limit:
        raise ScriptSizeExceededError(limit=limit, actual=actual_bytes, context=context)


class BroadcastRejected(Exception):
    """Raised when :class:`~runar.sdk.provider.MockProvider` refuses to
    acknowledge a broadcast (testing-gap remediation Phase A5).

    Distinct typed exception so a test can assert the fund-safety gate fired,
    rather than matching on a generic ``RuntimeError``.
    """


class BroadcastValidationUnavailable(Exception):
    """Raised when :class:`~runar.sdk.provider.MockProvider` is asked to
    validate a broadcast but the optional ``bsv-sdk`` dependency that provides
    the script interpreter is not installed.

    This is deliberately an ERROR, not a silent skip. Quietly degrading to
    "validated nothing, returned a fake txid" is exactly the fail-open bug
    class Phase A5 exists to close: it would let a test suite report green
    while every transaction it built was unspendable.

    ``runar`` itself stays zero-dependency at RUNTIME; ``bsv-sdk`` is a TEST
    dependency (``pip install 'runar[dev]'`` or ``pip install bsv-sdk``) and CI
    installs it for the ``packages/runar-py`` job.
    """


class MalformedScriptError(Exception):
    """Raised when a provider-supplied script cannot be parsed as a sequence
    of Bitcoin Script push elements (F-238).

    ``_read_script_element`` (``runar/sdk/script_utils.py``) used to raise a
    bare ``ValueError`` on an empty/odd-length tail (no opcode byte to read)
    and silently return a SHORT ``data_hex`` when a push's declared length
    ran past the remaining bytes -- which corrupts every later constructor
    slot's offset in the same walk. A caller fed an untrusted script by a
    ``Provider`` (``from_txid`` / ``from_utxo``) needs a typed, specific
    rejection, not a crash or a quietly wrong value.
    """


class InvalidConstructorArgError(ValueError):
    """Raised by ``RunarContract`` when a ByteString-family constructor arg
    (ByteString, PubKey, Sig, Addr, Ripemd160, Sha256, Point, P256Point,
    P384Point, SigHashPreimage) is a string that is not an even-length hex
    string (N-329). The SDK treats such a string as hex when it splices it into
    the locking script, so raw bytes would otherwise build a corrupt script.
    """


class WitnessValueMissingError(Exception):
    """Raised when a method call requires a caller-supplied intent-intrinsic
    witness value (auto-injected ``_prevOutScript_<i>`` or
    ``_serialisedOutputs``) that has not been set on the
    :class:`RunarContract`.

    Auto-injected witness params come from the compiler when a contract
    method uses ``extractPrevOutputScript(i)`` or ``requireOutputP2PKH(...)``.
    The caller must supply concrete bytes for each before invoking
    ``call()`` / ``prepare_call()`` via
    :meth:`RunarContract.set_prev_out_script` and
    :meth:`RunarContract.set_serialised_outputs`.
    """

    def __init__(self, param_name: str, method_name: str, contract_name: str) -> None:
        self.param_name = param_name
        self.method_name = method_name
        self.contract_name = contract_name
        super().__init__(
            f"witness value missing for auto-injected param '{param_name}' on "
            f"{contract_name}.{method_name} — call set_prev_out_script(i, bytes) "
            f"or set_serialised_outputs(bytes) before invoking the method"
        )
