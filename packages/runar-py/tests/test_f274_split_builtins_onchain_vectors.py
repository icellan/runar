"""F-274 (CL-BUG-163): the Python SDK ANF interpreter (what derives a call's
post-state before the SDK builds the spend) must return what the COMPILED
SCRIPT returns for `left`/`right`, for every vector in the shared on-chain
file ``packages/runar-zig/src/fixtures/f274-split-builtins-onchain.json``.

That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
``packages/runar-testing/src/__tests__/f274-split-builtins-onchain.test.ts``.

Unlike the math builtins (N-030), the ``runar`` package exposes no native
``left``/``right`` -- there is no top-level convenience wrapper for them at
all (`runar/builtins.py` has no such function), so there is nothing to probe
at that layer. Only the SDK ANF interpreter is exercised here.

What this proves: for every row, the interpreter returns the on-chain value,
or raises where the script aborts (never a value) -- covering n=0,
n=len(data), n>len(data), n<0, and an empty ``data`` input.
What it does not prove: inputs outside the file, or the script itself (the
oracle).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar.sdk.anf_interpreter import compute_new_state


def _vectors_path() -> Path:
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = (ancestor / 'packages' / 'runar-zig' / 'src' / 'fixtures'
                     / 'f274-split-builtins-onchain.json')
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f'could not locate f274-split-builtins-onchain.json walking up from {here}')


def _load_rows():
    data = json.loads(_vectors_path().read_text())
    return [(c['fn'], c['data'], c['n'], c['expect']) for c in data['cases']]


ROWS = _load_rows()
_IDS = [f'{fn}({data!r}, {n})' for fn, data, n, _ in ROWS]


def _run_anf(func: str, data: str, n: int):
    anf = {
        'contractName': 'SplitProbe',
        'properties': [{'name': 'result', 'type': 'ByteString', 'readonly': False}],
        'methods': [
            {'name': 'constructor', 'params': [], 'body': [], 'isPublic': False},
            {
                'name': 'probe',
                'params': [{'name': 'data', 'type': 'ByteString'}, {'name': 'n', 'type': 'bigint'}],
                'body': [
                    {'name': 't0', 'value': {'kind': 'load_param', 'name': 'data'}},
                    {'name': 't1', 'value': {'kind': 'load_param', 'name': 'n'}},
                    {'name': 'r', 'value': {'kind': 'call', 'func': func, 'args': ['t0', 't1']}},
                    {'name': 'u', 'value': {'kind': 'update_prop', 'name': 'result', 'value': 'r'}},
                ],
                'isPublic': True,
            },
        ],
    }
    return compute_new_state(anf, 'probe', {'result': ''}, {'data': data, 'n': n})['result']


@pytest.mark.parametrize('fn,data,n,expected', ROWS, ids=_IDS)
def test_anf_interpreter_returns_onchain_value(fn, data, n, expected):
    if expected == 'abort':
        with pytest.raises(ValueError):
            _run_anf(fn, data, n)
        return
    assert _run_anf(fn, data, n) == expected
