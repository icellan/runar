"""R3-PY-NEGATIVES: RPCProvider reports the node's JSON-RPC error as a typed
``RPCNodeError`` (method, code, message), so a caller can tell "the node said
no" from "the node never answered" without parsing message text.

Bitcoin RPC answers an error with HTTP 500 and the error object in the body
(that path's message never carried the method name), or with HTTP 200 and a
non-null ``error``. Both must surface the node's code and message; a transport
failure must not look like a node error. Node-free: a stub JSON-RPC server on
127.0.0.1.
"""
from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from runar.sdk.rpc_provider import RPCNodeError, RPCProvider


def _serve(status: int, body: dict):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
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
    return srv


REFUSAL = {"code": -26, "message": "mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)"}


@pytest.mark.parametrize("status", [500, 200])
def test_node_error_is_typed_with_method_code_and_message(status):
    srv = _serve(status, {"result": None, "error": REFUSAL, "id": "runar"})
    try:
        p = RPCProvider(f"http://127.0.0.1:{srv.server_port}", "u", "p")
        with pytest.raises(RPCNodeError) as ei:
            p.broadcast("00")
        e = ei.value
        assert e.method == "sendrawtransaction"
        assert e.code == -26
        assert e.message == REFUSAL["message"]
        assert isinstance(e, RuntimeError)  # existing `except RuntimeError` callers still catch it
    finally:
        srv.shutdown()


def test_transport_failure_is_not_a_node_error():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    p = RPCProvider(f"http://127.0.0.1:{port}", "u", "p")
    with pytest.raises(Exception) as ei:
        p.broadcast("00")
    assert not isinstance(ei.value, RPCNodeError), repr(ei.value)
