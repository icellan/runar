"""N-171 (sibling of F-274): the Python SDK ANF interpreter (what derives a
call's post-state before the SDK builds the spend) must return what the
COMPILED SCRIPT returns for `split` and `substr`, for every vector in the
shared on-chain file
``packages/runar-zig/src/fixtures/n171-split-substr-builtins-onchain.json``.

R67: `substr` used to be left modelled-but-not-abort-faithful here, because
its one caller via `extractScriptCode` (`FungibleToken.merge`) got an empty
dummy scriptCode, turning a realistic `substr(sc, ...)` call into a POSITIVE
overflow the old clamp had to swallow to avoid breaking state derivation.
`extractScriptCode` now returns the contract's own REAL codePart
(``contract.py``'s ``prepare_call``, via ``_IntentCtx.mock_preimage_bytes``),
so `substr` can be fully abort-faithful without starving `merge` of a
realistic scriptCode.

That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
``packages/runar-testing/src/__tests__/n171-split-substr-builtins-onchain.test.ts``.

What this proves: for every row, the interpreter returns the on-chain value,
or raises where the script aborts (never a value) -- covering n=0, interior,
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
                     / 'n171-split-substr-builtins-onchain.json')
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f'could not locate n171-split-substr-builtins-onchain.json walking up from {here}')


def _load_rows():
    data = json.loads(_vectors_path().read_text())
    return [(c['fn'], c['data'], c['a'], c['b'], c['expect']) for c in data['cases']]


ROWS = _load_rows()
_IDS = [f'{fn}({data!r}, {a}' + (f', {b})' if fn == 'substr' else ')') for fn, data, a, b, _ in ROWS]


def _run_anf(fn: str, data: str, a: int, b: int):
    params = [{'name': 'data', 'type': 'ByteString'}, {'name': 'a', 'type': 'bigint'}]
    call_args = ['t0', 't1']
    body = [
        {'name': 't0', 'value': {'kind': 'load_param', 'name': 'data'}},
        {'name': 't1', 'value': {'kind': 'load_param', 'name': 'a'}},
    ]
    if fn == 'substr':
        params.append({'name': 'b', 'type': 'bigint'})
        call_args.append('t2')
        body.append({'name': 't2', 'value': {'kind': 'load_param', 'name': 'b'}})
    body.append({'name': 'r', 'value': {'kind': 'call', 'func': fn, 'args': call_args}})
    body.append({'name': 'u', 'value': {'kind': 'update_prop', 'name': 'result', 'value': 'r'}})
    anf = {
        'contractName': 'SplitSubstrProbe',
        'properties': [{'name': 'result', 'type': 'ByteString', 'readonly': False}],
        'methods': [
            {'name': 'constructor', 'params': [], 'body': [], 'isPublic': False},
            {'name': 'probe', 'params': params, 'body': body, 'isPublic': True},
        ],
    }
    return compute_new_state(anf, 'probe', {'result': ''}, {'data': data, 'a': a, 'b': b})['result']


@pytest.mark.parametrize('fn,data,a,b,expected', ROWS, ids=_IDS)
def test_anf_interpreter_returns_onchain_value(fn, data, a, b, expected):
    if expected == 'abort':
        with pytest.raises(ValueError):
            _run_anf(fn, data, a, b)
        return
    assert _run_anf(fn, data, a, b) == expected
