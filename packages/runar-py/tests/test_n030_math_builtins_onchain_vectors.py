"""N-030 (CL-BUG-104): both Python runtimes of the math builtins return what
the COMPILED SCRIPT returns, for every vector in the shared on-chain file
``packages/runar-zig/src/fixtures/f033-math-builtins-onchain.json``.

That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
``packages/runar-testing/src/__tests__/f033-zig-native-math-onchain.test.ts``
(accept at ``expect``, reject at ``expect + 1``; an ``abort`` row rejects both
``== 0`` and ``!= 0``). Every other tier replays the same file.

What this proves: for every ``cases`` and ``wideCases`` row, the native
``runar`` builtins (what a ``.runar.py`` contract calls under pytest) and the
SDK ANF interpreter return the on-chain value, or raise where the script aborts
(never a value) -- including clamp with lo > hi, log2 saturating at 64 and
gcd's partial remainder after 256 Euclid steps.
What it does not prove: inputs outside the file, or the script itself (the
oracle). ``bool``/``within`` interpreter results are compared as script
numbers (True == 1, False == 0).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import runar
from runar.sdk.anf_interpreter import compute_new_state


def _vectors_path() -> Path:
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = (ancestor / 'packages' / 'runar-zig' / 'src' / 'fixtures'
                     / 'f033-math-builtins-onchain.json')
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f'could not locate f033-math-builtins-onchain.json walking up from {here}')


def _load_rows():
    data = json.loads(_vectors_path().read_text())
    rows = [(c['fn'], tuple(c['args']), c['expect']) for c in data['cases']]
    for c in data['wideCases']:
        e = c['expect']
        if isinstance(e, str) and e != 'abort':
            e = int(e)
        rows.append((c['fn'], tuple(int(a) for a in c['args']), e))
    return rows


ROWS = _load_rows()
_IDS = [f'{fn}{args}'[:120] for fn, args, _ in ROWS]

NATIVE = {
    'percentOf': runar.percent_of, 'mulDiv': runar.mul_div,
    'safediv': runar.safediv, 'safemod': runar.safemod, 'divmod': runar.divmod_,
    'sqrt': runar.sqrt, 'log2': runar.log2, 'pow': runar.pow_,
    'clamp': runar.clamp, 'within': runar.within, 'sign': runar.sign,
    'gcd': runar.gcd, 'abs': runar.abs, 'min': runar.min, 'max': runar.max,
    'bool': runar.bool_cast,
}


def test_vectors_cover_every_math_builtin():
    assert {fn for fn, _, _ in ROWS} == set(NATIVE)


def _run_anf(func: str, args: tuple):
    params = ['a', 'b', 'c'][:len(args)]
    body = [{'name': f't{i}', 'value': {'kind': 'load_param', 'name': p}}
            for i, p in enumerate(params)]
    body.append({'name': 'r', 'value': {
        'kind': 'call', 'func': func, 'args': [f't{i}' for i in range(len(args))]}})
    body.append({'name': 'u', 'value': {
        'kind': 'update_prop', 'name': 'result', 'value': 'r'}})
    anf = {
        'contractName': 'MathProbe',
        'properties': [{'name': 'result', 'type': 'bigint', 'readonly': False}],
        'methods': [
            {'name': 'constructor', 'params': [], 'body': [], 'isPublic': False},
            {'name': 'probe', 'params': [{'name': p, 'type': 'bigint'} for p in params],
             'body': body, 'isPublic': True},
        ],
    }
    return compute_new_state(anf, 'probe', {'result': 0}, dict(zip(params, args)))['result']


@pytest.mark.parametrize('fn,args,expected', ROWS, ids=_IDS)
def test_native_builtin_returns_onchain_value(fn, args, expected):
    native = NATIVE[fn]
    if expected == 'abort':
        with pytest.raises((ValueError, ZeroDivisionError)):
            native(*args)
        return
    got = native(*args)
    assert type(got) is type(expected) and got == expected


@pytest.mark.parametrize('fn,args,expected', ROWS, ids=_IDS)
def test_anf_interpreter_returns_onchain_value(fn, args, expected):
    if expected == 'abort':
        with pytest.raises(ValueError):
            _run_anf(fn, args)
        return
    assert int(_run_anf(fn, args)) == int(expected)
