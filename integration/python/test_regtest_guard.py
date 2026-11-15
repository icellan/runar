"""GK-BUG-001: the funding helpers refuse to touch a node that is not regtest.

The session fixture `ensure_regtest` checked the chain, but `ensure_blocks`
(also session-scoped, autouse, and defined first) could mine before it ran,
and the two funding helpers (`fund_address`, `create_funded_wallet`) had no
check of their own: anything that reached them outside the fixture order sent
real coins from the node's wallet. They now call `require_regtest()` first.

These tests stub `rpc_call`, so they need no node. Locally (no node) run them
with `--noconftest`; under the integration run the conftest's autouse
fixtures also apply and the stub still isolates them.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
conftest = importlib.import_module("conftest")


class _StubNode:
    def __init__(self, chain: object) -> None:
        self.chain = chain
        self.calls: list[str] = []

    def __call__(self, method: str, *params: object) -> object:
        self.calls.append(method)
        if method == "getblockchaininfo":
            return {} if self.chain is None else {"chain": self.chain, "blocks": 200}
        if method == "sendtoaddress":
            return "00" * 32
        if method in ("generate", "generatetoaddress"):
            return ["11" * 32]
        if method == "getnewaddress":
            return "mxxx"
        return None


@pytest.fixture
def stub(monkeypatch):
    def install(chain):
        node = _StubNode(chain)
        monkeypatch.setattr(conftest, "rpc_call", node)
        monkeypatch.setattr(conftest, "_REGTEST_CONFIRMED", False, raising=False)
        return node
    return install


@pytest.mark.parametrize("chain", ["main", "test", "stn", None])
def test_fund_address_refuses_non_regtest(stub, chain):
    node = stub(chain)
    with pytest.raises(RuntimeError, match="SAFETY"):
        conftest.fund_address("mfoo", 1.0)
    assert "sendtoaddress" not in node.calls
    assert "generate" not in node.calls


@pytest.mark.parametrize("chain", ["main", "test", None])
def test_create_funded_wallet_refuses_non_regtest(stub, chain):
    node = stub(chain)
    with pytest.raises(RuntimeError, match="SAFETY"):
        conftest.create_funded_wallet(None, 1.0)
    assert "sendtoaddress" not in node.calls


def test_fund_address_proceeds_on_regtest(stub):
    node = stub("regtest")
    conftest.fund_address("mfoo", 1.0)
    assert node.calls.index("getblockchaininfo") < node.calls.index("sendtoaddress")
