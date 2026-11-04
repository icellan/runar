"""N-051 (TaffyTail) — the ``SIZE(_codePart)`` pin is always OP_NUMEQUAL.

A stateful contract with a variable-length state section pins the spender's
``_codePart`` with ``76 04 LL LL LL LL 81 <cmp> 69``. When a readonly
constructor arg of variable width (ByteString / bigint) is baked into the code,
the deployed length is unknown at compile time. The compiler used to emit
OP_GREATERTHANOREQUAL (``a2``) there — a lower bound that accepts a truncated
``_codePart`` ending at a 0x6a byte inside the baked value. Now the comparison
is always ``9c`` and the length field is recorded as an artifact
``codePartLenSlots`` entry that the SDK patches at deploy time.

The expected bytes are the TypeScript reference compile (fold OFF): template
script sha256 ``738869ba...``, the pin's length field at byte 947.
"""

from __future__ import annotations

import hashlib
import json

from runar_compiler.compiler import (
    artifact_to_json,
    compile_from_source_str_with_result,
)

TAFFY_TAIL_SRC = """
import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';
import type { ByteString, PubKey, Sig } from 'runar-lang';

class TaffyTailVault extends StatefulSmartContract {
  message: ByteString;
  readonly tag: ByteString;
  readonly owner: PubKey;

  constructor(message: ByteString, tag: ByteString, owner: PubKey) {
    super(message, tag, owner);
    this.message = message;
    this.tag = tag;
    this.owner = owner;
  }

  public burn(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }

  public post(next: ByteString, claimedTag: ByteString) {
    assert(claimedTag === this.tag);
    this.addOutput(extractAmount(this.txPreimage), next);
  }
}
"""

# Same shape, but every readonly arg baked into the code is fixed-width, so the
# pin is exact at compile time and needs no deploy-time slot.
FIXED_WIDTH_SRC = """
import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';
import type { ByteString, PubKey, Sig } from 'runar-lang';

class FixedWidthVault extends StatefulSmartContract {
  message: ByteString;
  readonly owner: PubKey;

  constructor(message: ByteString, owner: PubKey) {
    super(message, owner);
    this.message = message;
    this.owner = owner;
  }

  public burn(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }

  public post(next: ByteString) {
    this.addOutput(extractAmount(this.txPreimage), next);
  }
}
"""

TS_SCRIPT_SHA256 = "738869ba6eed4d229d0d30f0b91b6fe98addff349a4f0fe0dee3ca3ffb656e45"
TS_PIN_VALUE_OFFSET = 947


def _compile(src: str, name: str):
    r = compile_from_source_str_with_result(src, name, disable_constant_folding=True)
    assert r.success, [d.message for d in r.diagnostics]
    return r.artifact


def _pin_offsets(script: str, cmp: str) -> list[int]:
    """Byte offsets of the 4-byte length field of every pin with ``cmp``."""
    out = []
    for i in range(0, len(script) - 17, 2):
        seq = script[i:i + 18]
        if seq.startswith("7604") and seq[12:14] == "81" and seq[14:16] == cmp and seq[16:18] == "69":
            out.append(i // 2 + 2)
    return out


def test_variable_width_readonly_arg_gets_equality_pin_and_slot():
    artifact = _compile(TAFFY_TAIL_SRC, "TaffyTailVault.runar.ts")
    script = artifact.script

    assert _pin_offsets(script, "a2") == [], "lower-bound pin must never be emitted"
    assert "81a269" not in script
    assert _pin_offsets(script, "9c") == [TS_PIN_VALUE_OFFSET]

    # Byte-identical to the TypeScript reference.
    assert hashlib.sha256(script.encode()).hexdigest() == TS_SCRIPT_SHA256

    d = json.loads(artifact_to_json(artifact))
    assert d["codePartLenSlots"] == [{"byteOffset": TS_PIN_VALUE_OFFSET}]
    keys = list(d.keys())
    assert keys.index("codePartLenSlots") == keys.index("codeSepIndexSlots") + 1


def test_fixed_width_contract_keeps_exact_pin_without_slot():
    artifact = _compile(FIXED_WIDTH_SRC, "FixedWidthVault.runar.ts")
    script = artifact.script

    assert _pin_offsets(script, "a2") == []
    assert len(_pin_offsets(script, "9c")) == 1
    d = json.loads(artifact_to_json(artifact))
    assert "codePartLenSlots" not in d
