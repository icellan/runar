"""R3-PY-NEGATIVES: a negative must prove the NODE refused the spend, and why.

Round 1 (GK-BUG-004) made a failed confirming mine after an ACCEPTED tx an
error: RPCProvider.broadcast raises after sendrawtransaction succeeded. The
suite's negatives asserted `pytest.raises(Exception)` plus a moved
`broadcast_attempts` counter, which that case satisfies, so every one of them
also passed when the node accepted the attack. `assert_node_rejected` reads
what each broadcast came to instead.

These tests drive the real SDK RPCProvider (through the suite's
`_instrument_broadcast`) against a stub JSON-RPC server on 127.0.0.1, so they
need no node. Locally run them with `--noconftest`; under the integration run
the conftest's autouse fixtures also apply and the stub still isolates them.
"""
from __future__ import annotations

import importlib
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
conftest = importlib.import_module("conftest")

TXID = "ab" * 32
SCRIPT_FAILURE = "mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"


def _err(code, msg):
    return 500, {"result": None, "error": {"code": code, "message": msg}, "id": "runar"}


def _ok(result):
    return 200, {"result": result, "error": None, "id": "runar"}


@pytest.fixture
def node():
    servers = []

    def start(answers: dict):
        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                status, body = answers.get(req["method"], _err(-32601, "Method not found"))
                out = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return conftest._instrument_broadcast(
            conftest.RPCProvider.regtest(f"http://127.0.0.1:{srv.server_port}", "u", "p"))

    yield start
    for s in servers:
        s.shutdown()


def _old_pattern_holds(provider, call) -> bool:
    """The pre-R3 assertion: the call raised after a broadcast attempt."""
    before = provider.broadcast_attempts
    try:
        call()
    except Exception:  # noqa: BLE001
        return provider.broadcast_attempts > before
    return False


def test_accepted_then_mine_failed_is_not_a_rejection(node):
    p = node({"sendrawtransaction": _ok(TXID), "generate": _err(-32601, "Method not found")})
    assert _old_pattern_holds(p, lambda: p.broadcast("00")), "setup: the old pattern must pass here"
    with pytest.raises(pytest.fail.Exception, match="ACCEPTED"):
        with conftest.assert_node_rejected(p):
            p.broadcast("00")


def test_accepted_spend_is_not_a_rejection(node):
    p = node({"sendrawtransaction": _ok(TXID), "generate": _ok(["00"])})
    with pytest.raises(pytest.fail.Exception, match="ACCEPTED"):
        with conftest.assert_node_rejected(p):
            p.broadcast("00")


def test_sdk_side_refusal_is_not_a_rejection(node):
    p = node({})
    with pytest.raises(pytest.fail.Exception, match="never handed a transaction"):
        with conftest.assert_node_rejected(p):
            raise RuntimeError("RunarContract.call: the ANF interpreter could not evaluate ...")


def test_transport_failure_is_not_a_rejection():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    p = conftest._instrument_broadcast(conftest.RPCProvider.regtest(f"http://127.0.0.1:{port}", "u", "p"))
    with pytest.raises(pytest.fail.Exception, match="never ruled"):
        with conftest.assert_node_rejected(p):
            p.broadcast("00")


def test_wrong_reason_is_not_the_rejection_under_test(node):
    p = node({"sendrawtransaction": _err(-26, "16: bad-txns-inputs-missingorspent")})
    with pytest.raises(pytest.fail.Exception, match="wrong reason"):
        with conftest.assert_node_rejected(p):
            p.broadcast("00")


def test_genuine_script_refusal_passes(node):
    """The control with teeth: an over-strict helper reddens here."""
    p = node({"sendrawtransaction": _err(-26, SCRIPT_FAILURE)})
    with conftest.assert_node_rejected(p):
        p.broadcast("00")
    assert p.broadcast_log == [(conftest.NODE_REJECTED, SCRIPT_FAILURE)]
