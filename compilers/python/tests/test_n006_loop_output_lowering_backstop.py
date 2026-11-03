"""N-006 / CL-BUG-186 -- the pass-4 backstop behind R-127.

R-127 is a syntactic search in the validator. ``lower_to_anf`` is public, so a
caller can go ``parse_source`` -> ``lower_to_anf`` having run no validator at
all, and ``_lower_for_statement`` used to drop the body sub-context's output
refs without a word: the loop's outputs were built but left out of the
continuation hash, so a spender could drop them (proven on @bsv/sdk Spend for
the TS and Go tiers in
packages/runar-testing/src/__tests__/f005-go-loop-output-continuation.test.ts).

What this proves: this tier's pass 4 refuses a loop whose body registered an
output ref, with R-127's shared diagnostic, whatever let the contract past
passes 1-3; a loop with no output in it still lowers.
What it does not prove: anything about emitted bytes.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.parser_dispatch import parse_source

HEAD = """import { StatefulSmartContract, ByteString, assert, num2bin } from 'runar-lang';

class Fan extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }
"""


def _contract(method: str):
    result = parse_source(HEAD + method + "\n}\n", "Fan.runar.ts")
    assert not result.errors, result.errors
    return result.contract


def _refusal(method: str) -> str:
    with pytest.raises(Exception) as exc:
        lower_to_anf(_contract(method))
    return str(exc.value)


def test_array_literal_raw_output_in_loop_is_refused_at_lowering():
    msg = _refusal("""  public fan(n: bigint) {
    this.addOutput(1000n, this.count + 1n);
    for (let i = 0n; i < 2n; i++) {
      const xs = [this.addRawOutput(n, num2bin(i, 4n))];
    }
  }""")
    assert "Output intrinsic 'addRawOutput' cannot be called inside a loop body." in msg


def test_add_output_and_data_output_in_loop_are_refused_at_lowering():
    out = _refusal("""  public fan(n: bigint) {
    this.addOutput(1000n, this.count);
    for (let i = 0n; i < 2n; i++) {
      this.addOutput(1000n, this.count + i);
    }
    assert(n > 0n);
  }""")
    assert "Output intrinsic 'addOutput' cannot be called inside a loop body." in out
    data = _refusal("""  public fan(n: bigint) {
    for (let i = 0n; i < 2n; i++) {
      if (i < n) {
        this.addDataOutput(0n, num2bin(i, 4n));
      }
    }
    this.count = this.count + 1n;
  }""")
    assert "Output intrinsic 'addDataOutput' cannot be called inside a loop body." in data


def test_control_loop_without_outputs_still_lowers():
    lower_to_anf(_contract("""  public fan(n: bigint) {
    let acc: bigint = 0n;
    for (let i = 0n; i < 2n; i++) {
      acc = acc + n;
    }
    this.addOutput(1000n, this.count + acc);
  }"""))
