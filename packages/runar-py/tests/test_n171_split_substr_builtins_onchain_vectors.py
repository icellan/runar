"""N-171 (sibling of F-274): `substr` compiles to `<data> <start> OP_SPLIT
OP_NIP <length> OP_SPLIT OP_DROP` -- TWO chained OP_SPLITs, the second against
the REMAINDER `size(data) - start`. It ABORTS whenever `start` is outside
[0, size(data)] or `length` is outside [0, size(data) - start], which
collapses to: start < 0, length < 0, or start + length > size(data). Python
slicing clamps instead of raising, so `runar.builtins.substr` checks the
bound explicitly.

This file replays the shared on-chain vectors in
``packages/runar-zig/src/fixtures/n171-split-substr-builtins-onchain.json``
(oracle: ``packages/runar-testing/src/__tests__/n171-split-substr-builtins-onchain.test.ts``)
against the native ``runar.builtins.substr`` wrapper.

Unlike `left`/`right` (F-274), the ``runar`` package exposes no native
``split`` -- there is no top-level convenience wrapper for it at all
(`runar/builtins.py` has no such function), so only `substr` rows are
replayed here; `split` rows are skipped, matching F-274's "Python's native
package has no left/right at all, which is out of scope" precedent.

What this proves: for every `substr` row, the native wrapper returns the
on-chain value, or raises where the script aborts (never a value) --
covering start/length = 0, interior, at the boundary, past the end,
negative, and an empty `data` input.
What it does not prove: inputs outside the file, the script itself (the
oracle), or `split` (no native wrapper exists). See
``test_n171_split_builtins_onchain_vectors.py`` for the SDK ANF
interpreter's `split`/`substr` coverage (R67 made `substr` abort-faithful
there too, by giving `extractScriptCode` a real codePart instead of an
empty mock).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar.builtins import substr


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
    return [(c['fn'], c['data'], c['a'], c['b'], c['expect']) for c in data['cases']
            if c['fn'] == 'substr']


ROWS = _load_rows()
_IDS = [f'substr({data!r}, {a}, {b})' for _, data, a, b, _ in ROWS]


@pytest.mark.parametrize('fn,data,start,length,expected', ROWS, ids=_IDS)
def test_native_substr_returns_onchain_value(fn, data, start, length, expected):
    raw = bytes.fromhex(data)
    if expected == 'abort':
        with pytest.raises(ValueError):
            substr(raw, start, length)
        return
    assert substr(raw, start, length).hex() == expected
