"""Constant folding pass for ANF IR.

Evaluates compile-time-known expressions and replaces them with ``load_const``
bindings.  Constants are propagated through the binding chain so downstream
operations can be folded too.

Direct port of ``compilers/rust/src/frontend/constant_fold.rs``.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

from runar_compiler.ir.types import (
    ANFBinding,
    ANFMethod,
    ANFProgram,
    ANFValue,
)


# ---------------------------------------------------------------------------
# Constant environment
# ---------------------------------------------------------------------------

# Constants are represented as (type_tag, value) tuples:
#   ("int", int_value)
#   ("bool", bool_value)
#   ("str", str_value)

ConstValue = tuple[str, Any]

ConstEnv = dict[str, ConstValue]


# ---------------------------------------------------------------------------
# Binary operation evaluation
# ---------------------------------------------------------------------------

def _eval_bin_op(op: str, left: ConstValue, right: ConstValue) -> ConstValue | None:
    # Arithmetic/bitwise/comparison on ints
    if left[0] == "int" and right[0] == "int":
        a: int = left[1]
        b: int = right[1]
        if op == "+":
            return ("int", a + b)
        if op == "-":
            return ("int", a - b)
        if op == "*":
            return ("int", a * b)
        if op == "/":
            if b == 0:
                return None
            # Truncated division (toward zero), matching JS BigInt semantics
            return ("int", int(a / b))
        if op == "%":
            if b == 0:
                return None
            # Remainder matching JS BigInt (sign follows dividend)
            return ("int", a - int(a / b) * b)
        if op == "===":
            return ("bool", a == b)
        if op == "!==":
            return ("bool", a != b)
        if op == "<":
            return ("bool", a < b)
        if op == ">":
            return ("bool", a > b)
        if op == "<=":
            return ("bool", a <= b)
        if op == ">=":
            return ("bool", a >= b)
        if op == "&":
            return ("int", a & b)
        if op == "|":
            return ("int", a | b)
        if op == "^":
            return ("int", a ^ b)
        if op == "<<":
            if a < 0:
                return None  # skip for negative left operand (BSV shifts are logical)
            if b < 0 or b > 128:
                return None
            return ("int", a << b)
        if op == ">>":
            if a < 0:
                return None  # skip for negative left operand (BSV shifts are logical)
            if b < 0 or b > 128:
                return None
            return ("int", a >> b)
        return None

    # Boolean operations
    if left[0] == "bool" and right[0] == "bool":
        a_b: bool = left[1]
        b_b: bool = right[1]
        if op == "&&":
            return ("bool", a_b and b_b)
        if op == "||":
            return ("bool", a_b or b_b)
        if op == "===":
            return ("bool", a_b == b_b)
        if op == "!==":
            return ("bool", a_b != b_b)
        return None

    # String (ByteString) operations
    if left[0] == "str" and right[0] == "str":
        a_s: str = left[1]
        b_s: str = right[1]
        if op == "+":
            if not _is_valid_hex(a_s) or not _is_valid_hex(b_s):
                return None
            return ("str", a_s + b_s)
        if op == "===":
            return ("bool", a_s == b_s)
        if op == "!==":
            return ("bool", a_s != b_s)
        return None

    # Cross-type equality
    if op == "===":
        return ("bool", False)
    if op == "!==":
        return ("bool", True)

    return None


def _is_valid_hex(s: str) -> bool:
    return all(c in "0123456789abcdefABCDEF" for c in s)


# ---------------------------------------------------------------------------
# Unary operation evaluation
# ---------------------------------------------------------------------------

def _eval_unary_op(op: str, operand: ConstValue) -> ConstValue | None:
    if operand[0] == "bool":
        if op == "!":
            return ("bool", not operand[1])
        return None
    if operand[0] == "int":
        n: int = operand[1]
        if op == "-":
            return ("int", -n)
        if op == "~":
            return ("int", ~n)
        if op == "!":
            return ("bool", n == 0)
        return None
    return None


# ---------------------------------------------------------------------------
# Builtin call evaluation (pure math functions only)
# ---------------------------------------------------------------------------

def _eval_builtin_call(func_name: str, args: list[ConstValue]) -> ConstValue | None:
    # Only fold pure math builtins with int arguments
    int_args: list[int] = []
    for a in args:
        if a[0] != "int":
            return None
        int_args.append(a[1])

    if func_name == "abs":
        if len(int_args) != 1:
            return None
        return ("int", abs(int_args[0]))

    if func_name == "min":
        if len(int_args) != 2:
            return None
        return ("int", min(int_args[0], int_args[1]))

    if func_name == "max":
        if len(int_args) != 2:
            return None
        return ("int", max(int_args[0], int_args[1]))

    if func_name == "safediv":
        if len(int_args) != 2 or int_args[1] == 0:
            return None
        return ("int", int(int_args[0] / int_args[1]))

    if func_name == "safemod":
        if len(int_args) != 2 or int_args[1] == 0:
            return None
        a, b = int_args[0], int_args[1]
        return ("int", a - int(a / b) * b)

    if func_name == "clamp":
        if len(int_args) != 3:
            return None
        val, lo, hi = int_args[0], int_args[1], int_args[2]
        return ("int", max(lo, min(val, hi)))

    if func_name == "sign":
        if len(int_args) != 1:
            return None
        n = int_args[0]
        if n > 0:
            return ("int", 1)
        elif n < 0:
            return ("int", -1)
        else:
            return ("int", 0)

    if func_name == "pow":
        if len(int_args) != 2:
            return None
        base, exp = int_args[0], int_args[1]
        if exp < 0 or exp > 256:
            return None
        result = 1
        for _ in range(exp):
            result *= base
        return ("int", result)

    if func_name == "mulDiv":
        if len(int_args) != 3 or int_args[2] == 0:
            return None
        tmp = int_args[0] * int_args[1]
        return ("int", int(tmp / int_args[2]))

    if func_name == "percentOf":
        if len(int_args) != 2:
            return None
        tmp = int_args[0] * int_args[1]
        return ("int", int(tmp / 10000))

    if func_name == "sqrt":
        if len(int_args) != 1:
            return None
        n = int_args[0]
        if n < 0:
            return None
        if n == 0:
            return ("int", 0)
        # Integer square root via Newton's method
        x = n
        y = (x + 1) // 2
        while y < x:
            x = y
            y = (x + n // x) // 2
        return ("int", x)

    if func_name == "gcd":
        if len(int_args) != 2:
            return None
        a, b = abs(int_args[0]), abs(int_args[1])
        while b != 0:
            a, b = b, a % b
        return ("int", a)

    if func_name == "divmod":
        if len(int_args) != 2 or int_args[1] == 0:
            return None
        return ("int", int(int_args[0] / int_args[1]))

    if func_name == "log2":
        if len(int_args) != 1:
            return None
        n = int_args[0]
        if n <= 0:
            return ("int", 0)
        return ("int", n.bit_length() - 1)

    if func_name == "bool":
        if len(int_args) != 1:
            return None
        return ("bool", int_args[0] != 0)

    return None


# ---------------------------------------------------------------------------
# ANF Value <-> ConstValue conversion
# ---------------------------------------------------------------------------

def _anf_value_to_const(value: ANFValue) -> ConstValue | None:
    """Extract a constant value from a load_const ANFValue."""
    if value.kind != "load_const":
        return None

    # Skip @ref: aliases -- they are binding references, not real constants
    if value.const_string is not None and value.const_string.startswith("@ref:"):
        return None

    # Check bool BEFORE int (bool is subclass of int in Python)
    if value.const_bool is not None:
        return ("bool", value.const_bool)
    if value.const_big_int is not None:
        return ("int", value.const_big_int)
    if value.const_int is not None:
        return ("int", value.const_int)
    if value.const_string is not None:
        return ("str", value.const_string)

    # Try to decode from raw_value
    raw = value.raw_value
    if raw is None:
        return None
    if isinstance(raw, bool):
        return ("bool", raw)
    if isinstance(raw, int):
        return ("int", raw)
    if isinstance(raw, float):
        return ("int", int(raw))
    if isinstance(raw, str):
        if raw.startswith("@ref:"):
            return None
        return ("str", raw)

    return None


def _const_to_anf_value(cv: ConstValue) -> ANFValue:
    """Convert a ConstValue to a load_const ANFValue."""
    tag, val = cv
    if tag == "int":
        return ANFValue(
            kind="load_const",
            raw_value=json.dumps(val),
            const_big_int=val,
            const_int=val,
        )
    if tag == "bool":
        return ANFValue(
            kind="load_const",
            raw_value=json.dumps(val),
            const_bool=val,
        )
    if tag == "str":
        return ANFValue(
            kind="load_const",
            raw_value=json.dumps(val),
            const_string=val,
        )
    # Fallback (shouldn't happen)
    return ANFValue(kind="load_const", raw_value=json.dumps(val))


# ---------------------------------------------------------------------------
# Fold bindings
# ---------------------------------------------------------------------------

def _fold_bindings(bindings: list[ANFBinding], env: ConstEnv) -> list[ANFBinding]:
    return [_fold_binding(b, env) for b in bindings]


def _fold_binding(binding: ANFBinding, env: ConstEnv) -> ANFBinding:
    folded_value = _fold_value(binding.value, env)

    # If the folded value is a load_const, register in the environment
    cv = _anf_value_to_const(folded_value)
    if cv is not None:
        env[binding.name] = cv

    return ANFBinding(name=binding.name, value=folded_value)


# ---------------------------------------------------------------------------
# Fold a single value
# ---------------------------------------------------------------------------

def _fold_value(value: ANFValue, env: ConstEnv) -> ANFValue:
    kind = value.kind

    if kind in ("load_const", "load_param", "load_prop"):
        return value

    if kind == "bin_op":
        left_const = env.get(value.left)
        right_const = env.get(value.right)
        if left_const is not None and right_const is not None:
            result = _eval_bin_op(value.op, left_const, right_const)
            if result is not None:
                return _const_to_anf_value(result)
        return value

    if kind == "unary_op":
        operand_const = env.get(value.operand)
        if operand_const is not None:
            result = _eval_unary_op(value.op, operand_const)
            if result is not None:
                return _const_to_anf_value(result)
        return value

    if kind == "call":
        if value.args is not None and all(a in env for a in value.args):
            const_args = [env[a] for a in value.args]
            folded = _eval_builtin_call(value.func, const_args)
            if folded is not None:
                return _const_to_anf_value(folded)
        return value

    if kind == "method_call":
        return value

    if kind == "if":
        cond_const = env.get(value.cond)
        if cond_const is not None and cond_const[0] == "bool":
            cond_val: bool = cond_const[1]
            if cond_val:
                then_env = dict(env)
                folded_then = _fold_bindings(value.then or [], then_env)
                # Merge constants from taken branch back into env
                for b in folded_then:
                    cv = _anf_value_to_const(b.value)
                    if cv is not None:
                        env[b.name] = cv
                return ANFValue(
                    kind="if",
                    cond=value.cond,
                    then=folded_then,
                    else_=[],
                )
            else:
                else_env = dict(env)
                folded_else = _fold_bindings(value.else_ or [], else_env)
                for b in folded_else:
                    cv = _anf_value_to_const(b.value)
                    if cv is not None:
                        env[b.name] = cv
                return ANFValue(
                    kind="if",
                    cond=value.cond,
                    then=[],
                    else_=folded_else,
                )
        else:
            # Condition not known -- fold both branches independently
            then_env = dict(env)
            else_env = dict(env)
            folded_then = _fold_bindings(value.then or [], then_env)
            folded_else = _fold_bindings(value.else_ or [], else_env)
            return ANFValue(
                kind="if",
                cond=value.cond,
                then=folded_then,
                else_=folded_else,
            )

    if kind == "loop":
        body_env = dict(env)
        folded_body = _fold_bindings(value.body or [], body_env)
        return ANFValue(
            kind="loop",
            count=value.count,
            body=folded_body,
            iter_var=value.iter_var,
        )

    # Terminal / side-effecting kinds pass through
    return value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _fold_method(method: ANFMethod) -> ANFMethod:
    env: ConstEnv = {}
    folded_body = _fold_bindings(method.body, env)
    return ANFMethod(
        name=method.name,
        params=list(method.params),
        body=folded_body,
        is_public=method.is_public,
    )


def fold_constants(program: ANFProgram) -> ANFProgram:
    """Apply constant folding to an ANF program.

    Evaluates compile-time-known expressions and replaces them with
    ``load_const`` bindings.  Does NOT run dead binding elimination --
    that is handled separately by the EC optimizer's DCE pass.
    """
    return ANFProgram(
        contract_name=program.contract_name,
        properties=list(program.properties),
        methods=[_fold_method(m) for m in program.methods],
    )
