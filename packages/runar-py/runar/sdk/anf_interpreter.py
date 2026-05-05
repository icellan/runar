"""Lightweight ANF interpreter for auto-computing state transitions.

Given a compiled artifact's ANF IR, the current contract state, and
method arguments, this interpreter walks the ANF bindings and computes
the new state. It handles ``update_prop`` nodes to track state mutations,
while skipping on-chain-only operations like ``check_preimage``,
``deserialize_state``, and ``get_state_script``. ``add_data_output`` and
``add_raw_output`` are surfaced through the result envelope rather than
skipped — see below.

This enables the SDK to auto-compute ``newState`` for stateful contract
calls, so callers don't need to duplicate contract logic.

Three execution modes are exposed:

* **Lenient** (:func:`compute_new_state`, :func:`compute_new_state_and_data_outputs`)
  — skips ``assert`` predicates, deferring enforcement to the on-chain script.
* **Strict** (:func:`execute_strict`) — evaluates every ``assert`` predicate and
  raises :class:`AssertionFailureError` (carrying the contract method + ANF
  binding name) on the first falsy one. Crypto built-ins (``checkSig``,
  ``checkMultiSig``, ``checkPreimage``) still mock-return ``True`` in strict
  mode; only explicit ``assert(...)`` predicates are enforced.
* **On-chain authoritative** (:func:`execute_on_chain_authoritative`) — strict
  assert enforcement PLUS real ECDSA / SHA-256 preimage verification against a
  caller-supplied 32-byte ``sighash`` (BIP-143). ``checkSig(sig, pk)`` only
  passes if the supplied DER signature verifies against the supplied SEC1
  public key over the supplied sighash; ``checkPreimage(preimage)`` only
  passes if ``SHA256(SHA256(preimage)) == sighash``. The signature shape
  requires the caller to provide the sighash up front via
  :class:`OnChainCryptoContext`, so this mode cannot be invoked accidentally
  without the cryptographic inputs.

All three modes return a 3-tuple ``(state, data_outputs, raw_outputs)``.
``raw_outputs`` collects entries from ``this.addRawOutput(satoshis,
scriptBytes)`` in the method body; the script bytes are caller-supplied raw
locking-script hex and the simulator does NOT introspect them — it forwards
them verbatim so an off-chain transaction builder can splice them in at the
correct position.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class AssertionFailureError(Exception):
    """Raised by :func:`execute_strict` on the first failing ``assert`` predicate.

    Carries enough context to point a developer at the exact ANF binding that
    aborted: the method being executed (``method_name``) and the binding name
    (``binding_name``, e.g. ``t17`` or ``assertPositive``). The string form
    matches the TS / Go / Java / Zig SDKs byte-for-byte so cross-tier diffing
    on the wire is stable.
    """

    def __init__(self, method_name: str, binding_name: str) -> None:
        super().__init__(
            f"assert failed in {method_name}: binding '{binding_name}' "
            f"evaluated to false"
        )
        self.method_name = method_name
        self.binding_name = binding_name

    def __str__(self) -> str:
        return (
            f"assert failed in {self.method_name}: binding "
            f"'{self.binding_name}' evaluated to false"
        )


class OnChainCryptoContext:
    """Cryptographic context for :func:`execute_on_chain_authoritative`.

    Carries the 32-byte BIP-143 sighash digest the on-chain VM would verify
    signatures against (and that the caller would have signed before
    broadcasting). The interpreter:

    * verifies ``checkSig(sig, pk)`` by parsing ``pk`` as SEC1 secp256k1
      (33-byte compressed or 65-byte uncompressed), parsing ``sig`` as DER
      (with the optional trailing sighash byte stripped — Bitcoin convention),
      and ECDSA-verifying against this sighash. Any mismatch returns ``False``,
      tripping the enclosing ``assert(...)`` and raising
      :class:`AssertionFailureError`.
    * verifies ``checkMultiSig(sigs, pks)`` by iterating signatures
      left-to-right and consuming pubkeys greedily, mirroring Bitcoin's
      ``OP_CHECKMULTISIG``.
    * verifies ``checkPreimage(preimage)`` by computing
      ``hash256(preimage) == SHA256(SHA256(preimage))`` and byte-comparing it
      to this sighash — the on-chain ``OP_PUSH_TX`` semantic.

    Construct with either a 64-character hex string (with or without ``0x``
    prefix) or a 32-byte ``bytes`` / ``bytearray`` value.
    """

    __slots__ = ("sighash",)

    def __init__(self, sighash: Union[str, bytes, bytearray]) -> None:
        if isinstance(sighash, str):
            s = sighash[2:] if sighash.startswith("0x") or sighash.startswith("0X") else sighash
            try:
                b = bytes.fromhex(s)
            except ValueError as exc:
                raise ValueError(
                    f"OnChainCryptoContext: invalid sighash hex: {exc}"
                ) from exc
        elif isinstance(sighash, (bytes, bytearray)):
            b = bytes(sighash)
        else:
            raise TypeError(
                "OnChainCryptoContext: sighash must be hex str or bytes, "
                f"got {type(sighash).__name__}"
            )
        if len(b) != 32:
            raise ValueError(
                "OnChainCryptoContext: sighash must be exactly 32 bytes, "
                f"got {len(b)}"
            )
        self.sighash: bytes = b


class _StrictCtx:
    """Per-evaluation strict-mode handle. ``None`` (in callers) = lenient.

    When ``real_crypto`` is set, crypto built-ins (``checkSig``,
    ``checkMultiSig``, ``checkPreimage``) verify against
    ``real_crypto.sighash`` instead of mock-returning ``True``. A non-``None``
    ``real_crypto`` implies strict assert enforcement (the on-chain
    authoritative mode used by :func:`execute_on_chain_authoritative`).
    """

    __slots__ = ("method_name", "real_crypto")

    def __init__(
        self,
        method_name: str,
        real_crypto: Optional[OnChainCryptoContext] = None,
    ) -> None:
        self.method_name = method_name
        self.real_crypto = real_crypto


def compute_new_state(
    anf: dict,
    method_name: str,
    current_state: dict,
    args: dict,
    constructor_args: list = None,
) -> dict:
    """Compute the new state after executing a contract method.

    Args:
        anf: The ANF IR from the compiled artifact (plain dict from JSON).
        method_name: The method to execute (must be a public method).
        current_state: Current contract state (property name -> value).
        args: Method arguments (param name -> value).
        constructor_args: Constructor arg values (declaration order) for readonly fields.

    Returns:
        The updated state (merged with current_state).
    """
    state, _, _ = compute_new_state_and_data_outputs(
        anf, method_name, current_state, args, constructor_args,
    )
    return state


def compute_new_state_and_data_outputs(
    anf: dict,
    method_name: str,
    current_state: dict,
    args: dict,
    constructor_args: list = None,
) -> Tuple[dict, list, list]:
    """Like :func:`compute_new_state` but also returns data + raw outputs.

    Data outputs come from ``this.addDataOutput(...)`` calls in the method
    body, in declaration order. Each entry is a
    ``{"script": hex, "satoshis": int}`` dict that becomes the payload of an
    ``OP_RETURN`` data output. The SDK uses these to populate the tx between
    state outputs and the change output so the on-chain continuation-hash
    check matches.

    Raw outputs come from ``this.addRawOutput(satoshis, scriptBytes)`` calls
    in the method body, in declaration order. Each entry is a
    ``{"script": hex, "satoshis": int}`` dict where ``script`` is the
    **caller-supplied** raw locking-script bytes. The simulator does NOT
    introspect those bytes; it forwards them so an off-chain transaction
    builder can splice them in at the correct index (after the state output
    and after data outputs).

    Returns:
        ``(state, data_outputs, raw_outputs)`` — the new state dict, a list
        of data output dicts, and a list of raw output dicts.
    """
    return _run_method(
        anf, method_name, current_state, args, constructor_args, strict=None,
    )


def execute_strict(
    anf: dict,
    method_name: str,
    current_state: dict,
    args: dict,
    constructor_args: list = None,
) -> Tuple[dict, list, list]:
    """Strict-mode counterpart to :func:`compute_new_state_and_data_outputs`.

    Walks the same ANF body but raises :class:`AssertionFailureError` on the
    first ``assert(predicate)`` whose predicate evaluates to a falsy value.
    Use this before broadcasting a transaction to surface guard failures
    off-chain instead of relying on a node rejection. Crypto built-ins
    (``checkSig``, ``checkMultiSig``, ``checkPreimage``) still mock-return
    ``True`` — strict mode only enforces explicit ``assert(...)`` predicates.

    Returns:
        ``(state, data_outputs, raw_outputs)`` — same envelope as
        :func:`compute_new_state_and_data_outputs`.

    Raises:
        AssertionFailureError: on the first falsy assert predicate.
    """
    return _run_method(
        anf, method_name, current_state, args, constructor_args,
        strict=_StrictCtx(method_name),
    )


def execute_on_chain_authoritative(
    anf: dict,
    method_name: str,
    current_state: dict,
    args: dict,
    constructor_args: list,
    ctx: OnChainCryptoContext,
) -> Tuple[dict, list, list]:
    """Like :func:`execute_strict` but also performs real cryptographic
    verification of ``checkSig``, ``checkMultiSig``, and ``checkPreimage``
    against the supplied ``ctx.sighash``.

    Raises :class:`AssertionFailureError` when any ``assert(...)`` (including
    the implicit one wrapping a failed crypto built-in) fires.

    The ``ctx`` parameter is mandatory and carries the sighash, so it is
    impossible to call this entry point accidentally without supplying the
    cryptographic inputs the verification needs.

    Args:
        anf: The ANF IR from the compiled artifact (plain dict from JSON).
        method_name: The method to execute (must be a public method).
        current_state: Current contract state (property name -> value).
        args: Method arguments (param name -> value).
        constructor_args: Constructor arg values (declaration order).
        ctx: The :class:`OnChainCryptoContext` carrying the 32-byte sighash.

    Returns:
        ``(state, data_outputs, raw_outputs)`` — same envelope as
        :func:`compute_new_state_and_data_outputs`.

    Raises:
        AssertionFailureError: on the first falsy assert predicate (including
            failed crypto verifications).
        TypeError: if ``ctx`` is not an :class:`OnChainCryptoContext`.
    """
    if not isinstance(ctx, OnChainCryptoContext):
        raise TypeError(
            "execute_on_chain_authoritative: ctx must be an "
            "OnChainCryptoContext instance"
        )
    return _run_method(
        anf, method_name, current_state, args, constructor_args,
        strict=_StrictCtx(method_name, real_crypto=ctx),
    )


def _run_method(
    anf: dict,
    method_name: str,
    current_state: dict,
    args: dict,
    constructor_args: Optional[list],
    strict: Optional[_StrictCtx],
) -> Tuple[dict, list, list]:
    """Shared entry-point for both lenient and strict modes.

    ``strict is None`` -> lenient (asserts skipped).
    ``strict is not None`` -> strict (first falsy assert raises
    :class:`AssertionFailureError`).
    """
    if constructor_args is None:
        constructor_args = []
    method = None
    for m in anf.get('methods', []):
        if m['name'] == method_name and m.get('isPublic', False):
            method = m
            break

    if method is None:
        raise ValueError(
            f"computeNewState: method '{method_name}' not found in ANF IR"
        )

    # Initialize the environment with property values and method params
    env: Dict[str, Any] = {}

    # Load properties: mutable fields from current_state, non-initialized fields
    # from constructor_args (matched by constructor param index, which excludes
    # initialized properties).
    ctor_idx = {}
    ci = 0
    for p in anf.get('properties', []):
        if p.get('initialValue') is None:
            ctor_idx[p['name']] = ci
            ci += 1
    for prop in anf.get('properties', []):
        name = prop['name']
        if name in current_state:
            env[name] = current_state[name]
        elif prop.get('initialValue') is not None:
            env[name] = prop['initialValue']
        elif name in ctor_idx and ctor_idx[name] < len(constructor_args):
            env[name] = constructor_args[ctor_idx[name]]

    # Load method params (skip implicit ones injected by the compiler)
    implicit_params = {'_changePKH', '_changeAmount', '_newAmount', 'txPreimage'}
    for param in method.get('params', []):
        pname = param['name']
        if pname in implicit_params:
            continue
        if pname in args:
            env[pname] = args[pname]

    # Track state mutations, data outputs, and raw outputs.
    # ``raw_outputs`` collects ``add_raw_output`` entries; the simulator does
    # not introspect the script bytes (they're caller-supplied) and forwards
    # them so an off-chain tx builder can splice them in at the correct index.
    state_delta: Dict[str, Any] = {}
    data_outputs: List[dict] = []
    raw_outputs: List[dict] = []

    # Walk bindings. In strict mode an AssertionFailureError raised from any
    # nested if/loop/private-method call propagates up out of this function
    # to the caller — there is no special unwind logic needed in Python.
    _eval_bindings(
        method.get('body', []), env, state_delta, data_outputs, raw_outputs,
        anf, strict,
    )

    return {**current_state, **state_delta}, data_outputs, raw_outputs


# ---------------------------------------------------------------------------
# Binding evaluation
# ---------------------------------------------------------------------------

def _eval_bindings(
    bindings: List[dict],
    env: Dict[str, Any],
    state_delta: Dict[str, Any],
    data_outputs: List[dict],
    raw_outputs: List[dict],
    anf: Optional[dict] = None,
    strict: Optional[_StrictCtx] = None,
) -> None:
    for binding in bindings:
        val = _eval_value(
            binding['value'], env, state_delta, data_outputs, raw_outputs, anf,
            strict=strict, binding_name=binding['name'],
        )
        env[binding['name']] = val


def _eval_value(
    value: dict,
    env: Dict[str, Any],
    state_delta: Dict[str, Any],
    data_outputs: List[dict],
    raw_outputs: List[dict],
    anf: Optional[dict] = None,
    strict: Optional[_StrictCtx] = None,
    binding_name: str = '<anonymous>',
) -> Any:
    kind = value.get('kind', '')

    if kind == 'load_param':
        return env.get(value['name'])

    if kind == 'load_prop':
        return env.get(value['name'])

    if kind == 'load_const':
        v = value.get('value')
        # Handle @ref: aliases
        if isinstance(v, str) and v.startswith('@ref:'):
            return env.get(v[5:])
        return v

    if kind == 'bin_op':
        return _eval_bin_op(
            value['op'],
            env.get(value['left']),
            env.get(value['right']),
            value.get('result_type'),
        )

    if kind == 'unary_op':
        return _eval_unary_op(
            value['op'],
            env.get(value['operand']),
            value.get('result_type'),
        )

    if kind == 'call':
        call_args = [env.get(a) for a in value.get('args', [])]
        # Strict mode: a `call(assert, x)` lowering path must enforce the
        # predicate the same way the dedicated `assert` ANF node does.
        if strict is not None and value.get('func') == 'assert':
            pred = call_args[0] if call_args else None
            if not _is_truthy(pred):
                raise AssertionFailureError(strict.method_name, binding_name)
            return None
        real_crypto = strict.real_crypto if strict is not None else None
        return _eval_call(value['func'], call_args, real_crypto=real_crypto)

    if kind == 'method_call':
        call_args = [env.get(a) for a in value.get('args', [])]
        return _eval_method_call(
            env.get(value.get('object')), value.get('method'), call_args,
            env, state_delta, data_outputs, raw_outputs, anf, strict=strict,
        )

    if kind == 'if':
        cond = env.get(value['cond'])
        branch = value['then'] if _is_truthy(cond) else value['else']
        child_env = dict(env)
        _eval_bindings(
            branch, child_env, state_delta, data_outputs, raw_outputs, anf, strict,
        )
        env.update(child_env)
        if branch:
            return child_env.get(branch[-1]['name'])
        return None

    if kind == 'loop':
        count = value.get('count', 0)
        body = value.get('body', [])
        iter_var = value.get('iterVar', '')
        last_val = None
        for i in range(count):
            env[iter_var] = i
            loop_env = dict(env)
            _eval_bindings(
                body, loop_env, state_delta, data_outputs, raw_outputs, anf, strict,
            )
            env.update(loop_env)
            if body:
                last_val = loop_env.get(body[-1]['name'])
        return last_val

    if kind == 'assert':
        # Lenient mode: skip; the on-chain script enforces.
        # Strict mode: enforce — raise AssertionFailureError on first falsy
        # predicate, which propagates up out of any nested if/loop/private
        # call to the original execute_strict caller.
        if strict is not None:
            pred_ref = value.get('value', '')
            pred = env.get(pred_ref)
            if not _is_truthy(pred):
                raise AssertionFailureError(strict.method_name, binding_name)
        return None

    if kind == 'update_prop':
        new_val = env.get(value['value'])
        env[value['name']] = new_val
        state_delta[value['name']] = new_val
        return None

    # add_output -- process stateValues to update mutable properties
    if kind == 'add_output':
        state_values = value.get('stateValues', [])
        if state_values and anf:
            mutable_props = [
                p['name'] for p in anf.get('properties', [])
                if not p.get('readonly', False)
            ]
            for i, sv in enumerate(state_values):
                if i < len(mutable_props):
                    resolved = env.get(sv)
                    prop_name = mutable_props[i]
                    env[prop_name] = resolved
                    state_delta[prop_name] = resolved
        return None

    if kind == 'add_data_output':
        # Resolve the two arg refs from env and record the data output.
        sat_ref = value.get('satoshis', '')
        script_ref = value.get('scriptBytes', '')
        sats = _to_int(env.get(sat_ref))
        script_val = env.get(script_ref)
        script_hex = script_val if isinstance(script_val, str) else ''
        data_outputs.append({'satoshis': sats, 'script': script_hex})
        return None

    if kind == 'add_raw_output':
        # ``addRawOutput(satoshis, scriptBytes)``. The simulator does not
        # introspect the script bytes (they're caller-supplied raw locking
        # script); it forwards them in the result envelope so an off-chain
        # transaction builder can emit the output at the correct index.
        sat_ref = value.get('satoshis', '')
        script_ref = value.get('scriptBytes', '')
        sats = _to_int(env.get(sat_ref))
        script_val = env.get(script_ref)
        script_hex = script_val if isinstance(script_val, str) else ''
        raw_outputs.append({'satoshis': sats, 'script': script_hex})
        return None

    # On-chain-only operations -- skip in simulation
    if kind in ('check_preimage', 'deserialize_state', 'get_state_script'):
        return None

    return None


# ---------------------------------------------------------------------------
# Binary operations
# ---------------------------------------------------------------------------

def _eval_bin_op(op: str, left: Any, right: Any, result_type: Optional[str] = None) -> Any:
    if result_type == 'bytes' or (isinstance(left, str) and isinstance(right, str)):
        return _eval_bytes_bin_op(op, str(left or ''), str(right or ''))

    l = _to_int(left)
    r = _to_int(right)

    if op == '+':
        return l + r
    if op == '-':
        return l - r
    if op == '*':
        return l * r
    if op == '/':
        return 0 if r == 0 else _truncate_div(l, r)
    if op == '%':
        return 0 if r == 0 else _truncate_mod(l, r)
    if op in ('==', '==='):
        return l == r
    if op in ('!=', '!=='):
        return l != r
    if op == '<':
        return l < r
    if op == '<=':
        return l <= r
    if op == '>':
        return l > r
    if op == '>=':
        return l >= r
    if op in ('&&', 'and'):
        return _is_truthy(left) and _is_truthy(right)
    if op in ('||', 'or'):
        return _is_truthy(left) or _is_truthy(right)
    if op == '&':
        return l & r
    if op == '|':
        return l | r
    if op == '^':
        return l ^ r
    if op == '<<':
        return l << r
    if op == '>>':
        return l >> r
    return 0


def _truncate_div(a: int, b: int) -> int:
    """Integer division truncating toward zero (matching JS/Bitcoin semantics)."""
    return int(a / b) if (a < 0) != (b < 0) and a % b != 0 else a // b


def _truncate_mod(a: int, b: int) -> int:
    """Modulo matching truncation toward zero."""
    return a - _truncate_div(a, b) * b


def _eval_bytes_bin_op(op: str, left: str, right: str) -> Any:
    if op == '+':  # cat
        return left + right
    if op in ('==', '==='):
        return left == right
    if op in ('!=', '!=='):
        return left != right
    return ''


# ---------------------------------------------------------------------------
# Unary operations
# ---------------------------------------------------------------------------

def _eval_unary_op(op: str, operand: Any, result_type: Optional[str] = None) -> Any:
    if result_type == 'bytes':
        if op == '~':
            hex_str = str(operand or '')
            b = bytes.fromhex(hex_str)
            return bytes(~x & 0xff for x in b).hex()
        return operand

    val = _to_int(operand)
    if op == '-':
        return -val
    if op in ('!', 'not'):
        return not _is_truthy(operand)
    if op == '~':
        return ~val
    return val


# ---------------------------------------------------------------------------
# Built-in function calls
# ---------------------------------------------------------------------------

def _eval_call(
    func: str,
    args: List[Any],
    real_crypto: Optional[OnChainCryptoContext] = None,
) -> Any:
    # Crypto -- mocked unless real-crypto context is present.
    if func == 'checkSig':
        if real_crypto is None:
            return True
        sig = args[0] if len(args) > 0 else None
        pk = args[1] if len(args) > 1 else None
        return _verify_ecdsa(sig, pk, real_crypto.sighash)
    if func == 'checkMultiSig':
        if real_crypto is None:
            return True
        sigs = args[0] if len(args) > 0 else None
        pks = args[1] if len(args) > 1 else None
        return _verify_multi_sig(sigs, pks, real_crypto.sighash)
    if func == 'checkPreimage':
        if real_crypto is None:
            return True
        pre = args[0] if len(args) > 0 else None
        return _verify_preimage(pre, real_crypto.sighash)

    # Crypto -- real hashes
    if func == 'sha256':
        return _hash_fn('sha256', args[0])
    if func == 'hash256':
        return _hash_fn('hash256', args[0])
    if func == 'hash160':
        return _hash_fn('hash160', args[0])
    if func == 'ripemd160':
        return _hash_fn('ripemd160', args[0])

    # Assert -- skip
    if func == 'assert':
        return None

    # Byte operations
    if func == 'num2bin':
        n = _to_int(args[0])
        length = int(_to_int(args[1]))
        return _num2bin_hex(n, length)
    if func == 'bin2num':
        return _bin2num_int(str(args[0] or ''))
    if func == 'cat':
        return str(args[0] or '') + str(args[1] or '')
    if func == 'substr':
        hex_str = str(args[0] or '')
        start = int(_to_int(args[1]))
        length = int(_to_int(args[2]))
        return hex_str[start * 2:(start + length) * 2]
    if func == 'reverseBytes':
        hex_str = str(args[0] or '')
        pairs = [hex_str[i:i + 2] for i in range(0, len(hex_str), 2)]
        return ''.join(reversed(pairs))
    if func == 'len':
        hex_str = str(args[0] or '')
        return len(hex_str) // 2

    # Math builtins
    if func == 'abs':
        return abs(_to_int(args[0]))
    if func == 'min':
        return min(_to_int(args[0]), _to_int(args[1]))
    if func == 'max':
        return max(_to_int(args[0]), _to_int(args[1]))
    if func == 'within':
        x = _to_int(args[0])
        return x >= _to_int(args[1]) and x < _to_int(args[2])
    if func == 'safediv':
        d = _to_int(args[1])
        return 0 if d == 0 else _truncate_div(_to_int(args[0]), d)
    if func == 'safemod':
        d = _to_int(args[1])
        return 0 if d == 0 else _truncate_mod(_to_int(args[0]), d)
    if func == 'clamp':
        v, lo, hi = _to_int(args[0]), _to_int(args[1]), _to_int(args[2])
        return lo if v < lo else hi if v > hi else v
    if func == 'sign':
        v = _to_int(args[0])
        return 1 if v > 0 else -1 if v < 0 else 0
    if func == 'pow':
        base = _to_int(args[0])
        exp = _to_int(args[1])
        if exp < 0:
            return 0
        return base ** exp
    if func == 'sqrt':
        v = _to_int(args[0])
        if v <= 0:
            return 0
        x = v
        y = (x + 1) // 2
        while y < x:
            x = y
            y = (x + v // x) // 2
        return x
    if func == 'gcd':
        a, b = abs(_to_int(args[0])), abs(_to_int(args[1]))
        while b:
            a, b = b, a % b
        return a
    if func == 'divmod':
        a = _to_int(args[0])
        b = _to_int(args[1])
        if b == 0:
            return 0
        return _truncate_div(a, b)
    if func == 'log2':
        v = _to_int(args[0])
        if v <= 0:
            return 0
        bits = 0
        x = v
        while x > 1:
            x >>= 1
            bits += 1
        return bits
    if func == 'bool':
        return 1 if _is_truthy(args[0]) else 0
    if func == 'mulDiv':
        return _truncate_div(_to_int(args[0]) * _to_int(args[1]), _to_int(args[2]))
    if func == 'percentOf':
        return _truncate_div(_to_int(args[0]) * _to_int(args[1]), 10000)

    # Preimage intrinsics -- return dummy values in simulation
    if func in ('extractOutputHash', 'extractAmount'):
        return '00' * 32

    return None


def _eval_method_call(
    obj: Any,
    method: Optional[str],
    args: List[Any],
    caller_env: Optional[Dict[str, Any]] = None,
    state_delta: Optional[Dict[str, Any]] = None,
    data_outputs: Optional[List[dict]] = None,
    raw_outputs: Optional[List[dict]] = None,
    anf: Optional[dict] = None,
    strict: Optional[_StrictCtx] = None,
) -> Any:
    if data_outputs is None:
        data_outputs = []
    if raw_outputs is None:
        raw_outputs = []
    # Look up private method in ANF IR
    if anf and method:
        for m in anf.get('methods', []):
            if m['name'] == method and not m.get('isPublic', False):
                # Create new env with property values from caller
                new_env: Dict[str, Any] = {}
                if caller_env:
                    for prop in anf.get('properties', []):
                        name = prop['name']
                        if name in caller_env:
                            new_env[name] = caller_env[name]
                # Map method params to passed args
                params = m.get('params', [])
                for i, param in enumerate(params):
                    if i < len(args):
                        new_env[param['name']] = args[i]
                # Evaluate method body (strict mode propagates into the callee)
                body = m.get('body', [])
                child_delta: Dict[str, Any] = {}
                _eval_bindings(
                    body, new_env, child_delta, data_outputs, raw_outputs,
                    anf, strict,
                )
                # Propagate state delta back
                if state_delta is not None:
                    state_delta.update(child_delta)
                if caller_env is not None:
                    for k, v in child_delta.items():
                        caller_env[k] = v
                # Return last binding's value
                if body:
                    return new_env.get(body[-1]['name'])
                return None
    return None


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def _hash_fn(name: str, input_val: Any) -> str:
    hex_str = str(input_val or '')
    data = bytes.fromhex(hex_str)

    if name == 'sha256':
        return hashlib.sha256(data).hexdigest()
    if name == 'hash256':
        return hashlib.sha256(hashlib.sha256(data).digest()).hexdigest()
    if name == 'ripemd160':
        return hashlib.new('ripemd160', data).hexdigest()
    if name == 'hash160':
        return hashlib.new('ripemd160', hashlib.sha256(data).digest()).hexdigest()
    return ''


# ---------------------------------------------------------------------------
# Numeric helpers
# ---------------------------------------------------------------------------

_BIGINT_RE = re.compile(r'^-?\d+n$')
_INT_RE = re.compile(r'^-?\d+$')


def _to_int(v: Any) -> int:
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str):
        # Handle "42n" format from JSON
        if _BIGINT_RE.match(v):
            return int(v[:-1])
        if _INT_RE.match(v):
            return int(v)
        return 0
    return 0


def _is_truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v != 0
    if isinstance(v, float):
        return v != 0.0
    if isinstance(v, str):
        return v != '' and v != '0' and v != 'false'
    return False


# ---------------------------------------------------------------------------
# Byte encoding helpers
# ---------------------------------------------------------------------------

def _num2bin_hex(n: int, byte_len: int) -> str:
    if n == 0:
        return '00' * byte_len

    negative = n < 0
    abs_n = -n if negative else n

    result_bytes = []
    while abs_n > 0:
        result_bytes.append(abs_n & 0xff)
        abs_n >>= 8

    # Sign bit handling
    if result_bytes:
        if negative:
            if (result_bytes[-1] & 0x80) == 0:
                result_bytes[-1] |= 0x80
            else:
                result_bytes.append(0x80)
        else:
            if (result_bytes[-1] & 0x80) != 0:
                result_bytes.append(0x00)

    # Pad or truncate to requested length
    while len(result_bytes) < byte_len:
        result_bytes.append(0x00)
    result_bytes = result_bytes[:byte_len]

    return ''.join(f'{b:02x}' for b in result_bytes)


def _bin2num_int(hex_str: str) -> int:
    if not hex_str:
        return 0
    result_bytes = []
    for i in range(0, len(hex_str), 2):
        result_bytes.append(int(hex_str[i:i + 2], 16))
    if not result_bytes:
        return 0

    negative = (result_bytes[-1] & 0x80) != 0
    if negative:
        result_bytes[-1] &= 0x7f

    result = 0
    for i in range(len(result_bytes) - 1, -1, -1):
        result = (result << 8) | result_bytes[i]

    return -result if negative else result


# ---------------------------------------------------------------------------
# Real ECDSA / preimage verification (used by execute_on_chain_authoritative)
# ---------------------------------------------------------------------------

def _to_byte_array(v: Any) -> Optional[bytes]:
    """Convert an interpreter value to a raw byte slice.

    Accepts hex strings (even-length, lowercase or uppercase), ``bytes``,
    ``bytearray``, and lists of byte-sized integers. Returns ``None`` on any
    malformed input — the caller treats ``None`` as a verification failure
    rather than a Python-level error.
    """
    if isinstance(v, str):
        if len(v) % 2 != 0:
            return None
        try:
            return bytes.fromhex(v)
        except ValueError:
            return None
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, list):
        out = bytearray(len(v))
        for i, item in enumerate(v):
            if isinstance(item, bool) or not isinstance(item, int):
                return None
            if item < 0 or item > 255:
                return None
            out[i] = item
        return bytes(out)
    return None


def _normalize_pubkey_to_compressed(pk_bytes: bytes) -> Optional[bytes]:
    """Accept SEC1 33-byte compressed or 65-byte uncompressed pubkey.

    Returns a 33-byte compressed encoding (the form expected by
    :func:`runar.ecdsa.ecdsa_verify`'s ``_decompress_pubkey``). Returns
    ``None`` on any malformed input.
    """
    if len(pk_bytes) == 33 and pk_bytes[0] in (0x02, 0x03):
        return pk_bytes
    if len(pk_bytes) == 65 and pk_bytes[0] == 0x04:
        x = pk_bytes[1:33]
        y = pk_bytes[33:65]
        # y % 2 == 0 -> 0x02, else 0x03
        prefix = 0x02 if (y[-1] & 0x01) == 0 else 0x03
        return bytes([prefix]) + x
    return None


def _verify_ecdsa(sig_val: Any, pk_val: Any, sighash: bytes) -> bool:
    """Real ECDSA verify against a 32-byte sighash.

    Parses ``sig_val`` as DER (with optional trailing sighash byte stripped —
    Bitcoin convention) and ``pk_val`` as SEC1 secp256k1 (33-byte compressed
    or 65-byte uncompressed). The signature is verified directly against the
    raw 32-byte sighash (the on-chain ``OP_CHECKSIG`` semantic — the VM does
    NOT re-hash before verifying). Returns ``False`` on any parse error or
    signature mismatch.
    """
    sig_bytes = _to_byte_array(sig_val)
    pk_bytes = _to_byte_array(pk_val)
    if sig_bytes is None or pk_bytes is None:
        return False
    pk_compressed = _normalize_pubkey_to_compressed(pk_bytes)
    if pk_compressed is None:
        return False
    try:
        # Lazy import: keeps the SDK's zero-required-deps stance for callers
        # who never invoke real-crypto mode.
        from runar.ecdsa import ecdsa_verify
        return ecdsa_verify(sig_bytes, pk_compressed, sighash)
    except Exception:
        return False


def _verify_multi_sig(sigs_val: Any, pks_val: Any, sighash: bytes) -> bool:
    """OP_CHECKMULTISIG semantic: iterate sigs left-to-right, consume pks
    greedily. Returns ``True`` iff every signature finds a matching pubkey.
    """
    if not isinstance(sigs_val, list) or not isinstance(pks_val, list):
        return False
    if len(sigs_val) > len(pks_val):
        return False
    pk_idx = 0
    for sig in sigs_val:
        matched = False
        while pk_idx < len(pks_val):
            ok = _verify_ecdsa(sig, pks_val[pk_idx], sighash)
            pk_idx += 1
            if ok:
                matched = True
                break
        if not matched:
            return False
    return True


def _verify_preimage(preimage_val: Any, sighash: bytes) -> bool:
    """BIP-143 / OP_PUSH_TX semantic: ``hash256(preimage) == sighash``."""
    pre_bytes = _to_byte_array(preimage_val)
    if pre_bytes is None:
        return False
    digest = hashlib.sha256(hashlib.sha256(pre_bytes).digest()).digest()
    return digest == sighash
