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
