"""Lightweight ANF interpreter for auto-computing state transitions.

Given a compiled artifact's ANF IR, the current contract state, and
method arguments, this interpreter walks the ANF bindings and computes
the new state. It handles ``update_prop`` nodes to track state mutations,
while skipping on-chain-only operations like ``check_preimage``,
``deserialize_state``, ``get_state_script``, ``add_output``, and ``add_raw_output``.

This enables the SDK to auto-compute ``newState`` for stateful contract
calls, so callers don't need to duplicate contract logic.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_new_state(
    anf: dict,
    method_name: str,
    current_state: dict,
    args: dict,
) -> dict:
    """Compute the new state after executing a contract method.

    Args:
        anf: The ANF IR from the compiled artifact (plain dict from JSON).
        method_name: The method to execute (must be a public method).
        current_state: Current contract state (property name -> value).
        args: Method arguments (param name -> value).

    Returns:
        The updated state (merged with current_state).
    """
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

    # Load properties
    for prop in anf.get('properties', []):
        name = prop['name']
        env[name] = current_state.get(name, prop.get('initialValue'))

    # Load method params (skip implicit ones injected by the compiler)
    implicit_params = {'_changePKH', '_changeAmount', '_newAmount', 'txPreimage'}
    for param in method.get('params', []):
        pname = param['name']
        if pname in implicit_params:
            continue
        if pname in args:
            env[pname] = args[pname]

    # Track state mutations
    state_delta: Dict[str, Any] = {}

    # Walk bindings
    _eval_bindings(method.get('body', []), env, state_delta, anf)

    return {**current_state, **state_delta}


# ---------------------------------------------------------------------------
# Binding evaluation
# ---------------------------------------------------------------------------

def _eval_bindings(
    bindings: List[dict],
    env: Dict[str, Any],
    state_delta: Dict[str, Any],
    anf: Optional[dict] = None,
) -> None:
    for binding in bindings:
        val = _eval_value(binding['value'], env, state_delta, anf)
        env[binding['name']] = val


def _eval_value(
    value: dict,
    env: Dict[str, Any],
    state_delta: Dict[str, Any],
    anf: Optional[dict] = None,
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
        return _eval_call(value['func'], call_args)

    if kind == 'method_call':
        call_args = [env.get(a) for a in value.get('args', [])]
        return _eval_method_call(env.get(value.get('object')), value.get('method'), call_args, env, state_delta, anf)

    if kind == 'if':
        cond = env.get(value['cond'])
        branch = value['then'] if _is_truthy(cond) else value['else']
        child_env = dict(env)
        _eval_bindings(branch, child_env, state_delta, anf)
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
            _eval_bindings(body, loop_env, state_delta, anf)
            env.update(loop_env)
            if body:
                last_val = loop_env.get(body[-1]['name'])
        return last_val

    if kind == 'assert':
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

    # On-chain-only operations -- skip in simulation
    if kind in ('check_preimage', 'deserialize_state', 'get_state_script',
                'add_raw_output'):
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

def _eval_call(func: str, args: List[Any]) -> Any:
    # Crypto -- mock
    if func in ('checkSig', 'checkMultiSig', 'checkPreimage'):
        return True

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
    anf: Optional[dict] = None,
) -> Any:
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
                # Evaluate method body
                body = m.get('body', [])
                child_delta: Dict[str, Any] = {}
                _eval_bindings(body, new_env, child_delta, anf)
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
