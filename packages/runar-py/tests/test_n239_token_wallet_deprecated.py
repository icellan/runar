"""N-239: ``TokenWallet.merge`` / ``.transfer`` are deprecated and unsafe.

The ABI they drive cannot be made sound: ``merge(sig, otherSupply,
otherHolder)`` cannot authenticate its companion input (supply inflation) and
``transfer(sig, to: Addr)`` cannot re-key a PubKey holder. User decision R92:
deprecate (marker + runtime warning + docs), do not redesign or remove.

Proves: calling each method raises a ``DeprecationWarning`` naming its specific
unsoundness and pointing to token-ft (FungibleTokenExample); each docstring
carries a ``.. deprecated::`` marker; the method's own behaviour (here, its
error path) is unchanged.
Does NOT prove: that users see the warning — Python's default filters hide
``DeprecationWarning`` outside ``__main__`` unless run with ``-W default`` or
under pytest — nor anything on-chain (the happy paths stay covered by the
f045 / n042 suites). "Once" is Python's own per-call-site warning registry,
not a flag of ours, so it is not asserted here.
"""

from __future__ import annotations

import pytest

from runar.sdk.provider import MockProvider
from runar.sdk.signer import MockSigner
from runar.sdk.token_wallet import TokenWallet
from runar.sdk.types import RunarArtifact


def _wallet() -> TokenWallet:
    artifact = RunarArtifact(contract_name='WalletToken', script='76a988ac')
    return TokenWallet(artifact, MockProvider(), MockSigner())


def test_merge_warns_about_supply_inflation():
    with pytest.warns(DeprecationWarning) as record:
        with pytest.raises(RuntimeError, match='need at least 2 UTXOs'):
            _wallet().merge()
    msgs = [str(w.message) for w in record if 'TokenWallet.merge' in str(w.message)]
    assert len(msgs) == 1, msgs
    for needle in ('deprecated', 'supply inflation', 'token-ft', 'FungibleTokenExample'):
        assert needle in msgs[0], (needle, msgs[0])


def test_transfer_warns_about_holder_rekey():
    with pytest.warns(DeprecationWarning) as record:
        with pytest.raises(RuntimeError, match='no token UTXOs found'):
            _wallet().transfer('recipient', 1)
    msgs = [str(w.message) for w in record if 'TokenWallet.transfer' in str(w.message)]
    assert len(msgs) == 1, msgs
    for needle in ('deprecated', 're-key', 'token-ft', 'FungibleTokenExample'):
        assert needle in msgs[0], (needle, msgs[0])


@pytest.mark.parametrize('method', ['merge', 'transfer'])
def test_docstring_carries_deprecated_marker(method):
    doc = getattr(TokenWallet, method).__doc__ or ''
    assert '.. deprecated::' in doc, doc
