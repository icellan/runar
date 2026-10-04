"""F-134: the two Python runtimes of the math builtins agree with the SCRIPT.

``runar/builtins.py`` is what a ``.runar.py`` contract calls when its pytest
suite runs it as native Python; ``runar/sdk/anf_interpreter.py`` is what the
SDK uses to derive a call's post-state. Both must compute what the compiled
locking script computes -- otherwise a contract's tests pass while its
deployed script does something else, or the SDK builds a continuation the
covenant rejects.

The expected column is NOT taken from a peer implementation. Every row was
established by EXECUTING the TS compiler's script for that builtin in
@bsv/sdk's Spend (``ScriptExecutionContract``, fold ON and OFF, identical):
OP_DIV/OP_MOD truncate toward zero; a zero divisor aborts; ``pow`` aborts
outside ``0 <= exp <= 32`` (``OP_WITHIN`` guard); ``sqrt`` aborts on ``n < 0``
and on ``n >= 2^495`` (``OP_SIZE <63> OP_LESSTHAN`` guard). ``ABORT`` means
the script fails, so the off-chain runtime must refuse rather than return a
number.

What this proves: for each listed input, both Python runtimes return the
script's value or refuse where the script aborts, and the interpreter's
truncating division stays exact on operands too large for a float.
What it does not prove: agreement on inputs outside the table, and nothing
about the script itself (the script is the oracle here, not the subject).
"""

from __future__ import annotations

import pytest

from runar.builtins import (
    divmod_, mul_div, percent_of, pow_, safediv, safemod, sqrt,
)
from runar.sdk.anf_interpreter import compute_new_state

ABORT = object()

# (anf builtin, native function, args, script result)
VECTORS = [
    ('divmod', divmod_, (-7, 2), -3),
    ('divmod', divmod_, (7, -2), -3),
    ('divmod', divmod_, (-7, -2), 3),
    ('divmod', divmod_, (1, 0), ABORT),
    ('mulDiv', mul_div, (-7, 1, 2), -3),
    ('mulDiv', mul_div, (7, 1, -2), -3),
    ('mulDiv', mul_div, (1, 1, 0), ABORT),
    ('percentOf', percent_of, (-1, 5000), 0),
    ('percentOf', percent_of, (-15000, 1), -1),
    ('percentOf', percent_of, (1, -5000), 0),
    ('pow', pow_, (2, -1), ABORT),
    ('pow', pow_, (2, 0), 1),
    ('pow', pow_, (0, 0), 1),
    ('pow', pow_, (-2, 3), -8),
    ('pow', pow_, (2, 32), 4294967296),
    ('pow', pow_, (2, 33), ABORT),
    ('sqrt', sqrt, (-1,), ABORT),
    ('sqrt', sqrt, (0,), 0),
    ('sqrt', sqrt, (8,), 2),
    ('sqrt', sqrt, (1 << 495,), ABORT),
    ('safediv', safediv, (-7, 2), -3),
    ('safediv', safediv, (1, 0), ABORT),
    ('safemod', safemod, (-7, 2), -1),
    ('safemod', safemod, (7, -2), 1),
    ('safemod', safemod, (1, 0), ABORT),
]

_IDS = [f'{name}{args}'.replace(str(1 << 495), '2**495') for name, _, args, _ in VECTORS]


def _call_anf(func: str, nargs: int) -> dict:
    params = ['a', 'b', 'c'][:nargs]
    body = [
        {'name': f't{i}', 'value': {'kind': 'load_param', 'name': p}}
        for i, p in enumerate(params)
    ]
    body.append({'name': 'r', 'value': {
        'kind': 'call', 'func': func, 'args': [f't{i}' for i in range(nargs)],
    }})
    body.append({'name': 'u', 'value': {
        'kind': 'update_prop', 'name': 'result', 'value': 'r',
    }})
    return {
        'contractName': 'MathProbe',
        'properties': [{'name': 'result', 'type': 'bigint', 'readonly': False}],
        'methods': [
            {'name': 'constructor', 'params': [], 'body': [], 'isPublic': False},
            {
                'name': 'probe',
                'params': [{'name': p, 'type': 'bigint'} for p in params],
                'body': body,
                'isPublic': True,
            },
        ],
    }


def _run_anf(func: str, args: tuple) -> int:
    anf = _call_anf(func, len(args))
    named = dict(zip(['a', 'b', 'c'], args))
    return compute_new_state(anf, 'probe', {'result': 0}, named)['result']


@pytest.mark.parametrize('func,native,args,expected', VECTORS, ids=_IDS)
def test_native_builtin_matches_script(func, native, args, expected):
    if expected is ABORT:
        with pytest.raises((ValueError, ZeroDivisionError)):
            native(*args)
    else:
        got = native(*args)
        assert type(got) is int and got == expected


@pytest.mark.parametrize('func,native,args,expected', VECTORS, ids=_IDS)
def test_anf_interpreter_matches_script(func, native, args, expected):
    if expected is ABORT:
        with pytest.raises(ValueError):
            _run_anf(func, args)
    else:
        got = _run_anf(func, args)
        assert type(got) is int and got == expected


def test_truncating_division_is_exact_beyond_float_precision():
    # (-(10**30) - 7) / 3 truncated toward zero. A float-based quotient
    # (int(a / b)) loses the low digits at this magnitude.
    a, b = -(10 ** 30) - 7, 3
    want = -((10 ** 30 + 7) // 3)
    assert _run_anf('divmod', (a, b)) == want
    assert _run_anf('mulDiv', (a, 1, b)) == want
    assert _run_anf('safediv', (a, b)) == want
    assert divmod_(a, b) == want
    assert mul_div(a, 1, b) == want
