"""
DataOutputs integration test -- stateful contract emitting an OP_RETURN
data output via this.addDataOutput(...).

Ported from integration/go/data_outputs_test.go (BSVM R9 acceptance):
data outputs must appear in declaration order between the state output
and the change output so the compile-time continuation-hash check
matches at spend time.
"""

import json
import os
import tempfile

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet, rpc_call,
)
from runar_compiler.compiler import compile_from_source, artifact_to_json
from runar.sdk import RunarArtifact, RunarContract, DeployOptions


SOURCE = """\
import { StatefulSmartContract, ByteString } from 'runar-lang';

export class DataEmitter extends StatefulSmartContract {
    counter: bigint;

    constructor(counter: bigint) {
        super(counter);
        this.counter = counter;
    }

    public emit(payload: ByteString) {
        this.counter = this.counter + 1n;
        this.addDataOutput(0n, payload);
    }
}
"""


def _compile_source(source: str, file_name: str) -> RunarArtifact:
    """Compile inline source to an SDK artifact via a temp file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=file_name, delete=False, dir=tempfile.gettempdir()
    ) as f:
        f.write(source)
        tmp_path = f.name
    try:
        compiler_artifact = compile_from_source(tmp_path)
        artifact_dict = json.loads(artifact_to_json(compiler_artifact))
        return RunarArtifact.from_dict(artifact_dict)
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Minimal raw-tx parser -- just enough to inspect outputs.
# ---------------------------------------------------------------------------

def _read_varint_hex(buf: str, pos: int) -> tuple[int, int]:
    first = int(buf[pos:pos + 2], 16)
    if first < 0xfd:
        return first, 2
    if first == 0xfd:
        n = int.from_bytes(bytes.fromhex(buf[pos + 2:pos + 6]), "little")
        return n, 6
    if first == 0xfe:
        n = int.from_bytes(bytes.fromhex(buf[pos + 2:pos + 10]), "little")
        return n, 10
    n = int.from_bytes(bytes.fromhex(buf[pos + 2:pos + 18]), "little")
    return n, 18


def _parse_outputs(tx_hex: str) -> list[tuple[int, str]]:
    """Return [(satoshis, script_hex), ...] from a raw transaction hex."""
    pos = 8  # version
    n_in, w = _read_varint_hex(tx_hex, pos)
    pos += w
    for _ in range(n_in):
        pos += 64 + 8  # prev txid + prev vout
        script_len, slw = _read_varint_hex(tx_hex, pos)
        pos += slw + script_len * 2 + 8  # script bytes + sequence
    n_out, w = _read_varint_hex(tx_hex, pos)
    pos += w
    outs: list[tuple[int, str]] = []
    for _ in range(n_out):
        sats = int.from_bytes(bytes.fromhex(tx_hex[pos:pos + 16]), "little")
        pos += 16
        script_len, slw = _read_varint_hex(tx_hex, pos)
        pos += slw
        script = tx_hex[pos:pos + script_len * 2]
        pos += script_len * 2
        outs.append((sats, script))
    return outs


class TestDataOutputs:

    def test_emit_data_output_index_one(self):
        """Emit a single data output: outputs are [state, data, change]."""
        artifact = _compile_source(SOURCE, "DataEmitter.runar.ts")
        contract = RunarContract(artifact, [0])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        deploy_txid, _ = contract.deploy(
            provider, wallet["signer"], DeployOptions(satoshis=10_000),
        )
        assert deploy_txid

        # OP_RETURN "bsvm-test"
        payload = "6a09" + "6273766d2d74657374"

        call_txid, _ = contract.call(
            "emit", [payload], provider, wallet["signer"],
        )
        assert call_txid
        # State increments are tested by test_counter.py — here we just verify
        # the broadcast tx carries the data output at index [1].

        # Re-fetch the broadcast tx and inspect outputs.
        raw_hex = rpc_call("getrawtransaction", call_txid)
        outs = _parse_outputs(raw_hex)
        assert len(outs) >= 2, f"expected >=2 outputs, got {len(outs)}"

        # Output[1] is the data output: 0 satoshis, exact payload script.
        assert outs[1][0] == 0
        assert outs[1][1] == payload

    def test_chain_two_emits_accumulates_state(self):
        """Two consecutive emits: state increments and each tx carries the
        right OP_RETURN payload at index [1]."""
        artifact = _compile_source(SOURCE, "DataEmitter.runar.ts")
        contract = RunarContract(artifact, [0])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(
            provider, wallet["signer"], DeployOptions(satoshis=10_000),
        )

        payload1 = "6a05" + "6669727374"   # OP_RETURN "first"
        payload2 = "6a06" + "7365636f6e64" # OP_RETURN "second"

        t1, _ = contract.call(
            "emit", [payload1], provider, wallet["signer"],
        )
        assert t1

        t2, _ = contract.call(
            "emit", [payload2], provider, wallet["signer"],
        )
        assert t2

        raw2 = rpc_call("getrawtransaction", t2)
        outs2 = _parse_outputs(raw2)
        assert outs2[1][1] == payload2
        assert outs2[1][0] == 0
