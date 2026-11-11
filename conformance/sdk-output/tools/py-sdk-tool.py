#!/usr/bin/env python3
import json
import sys
import os

# Add runar-py to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'packages', 'runar-py'))

from runar.sdk import RunarContract, RunarArtifact, Inscription
from runar.sdk import extract_constructor_args, matches_artifact
from runar.sdk.wallet import WalletClient, WalletProvider, WalletSigner


class StubWallet(WalletClient):
    """R-062: the smallest BRC-100 wallet that can fund a deploy."""

    def get_public_key(self, protocol_id, key_id):
        return '02' + '11' * 32

    def create_signature(self, hash_to_sign, protocol_id, key_id):
        return b'\x30\x06\x02\x01\x01\x02\x01\x01'

    def create_action(self, description, outputs):
        return {'txid': 'ab' * 32}

    def list_outputs(self, basket, tags, limit=100):
        return []


def convert_arg(arg: dict):
    t = arg['type']
    v = arg['value']
    if t in ('bigint', 'int'):
        return int(v)
    # `boolean` is the spelling the compiler's ABI carries; `bool` is the
    # alias some frontends use. Accept both (R-248).
    if t in ('bool', 'boolean'):
        return v == 'true'
    # ByteString, PubKey, Addr, Sig, Ripemd160, Sha256, Point — hex strings
    return v


def readback(artifact, script_hex: str) -> dict:
    """Readback mode (conformance/sdk-vertical): what matches_artifact and
    extract_constructor_args say about script_hex. ``args`` is positional by
    paramIndex as {type, value} (decimal / 'true'|'false' / lowercase hex),
    None for a param the extraction does not report; ``error`` is the message
    extract_constructor_args (or matches_artifact) raised, else None."""
    out = {'matches': None, 'args': None, 'error': None}
    try:
        out['matches'] = bool(matches_artifact(artifact, script_hex))
    except Exception as e:  # noqa: BLE001 — any raise is the result
        out['error'] = str(e) or type(e).__name__
    try:
        got = extract_constructor_args(artifact, script_hex)
    except Exception as e:  # noqa: BLE001
        if out['error'] is None:
            out['error'] = str(e) or type(e).__name__
        return out
    args = []
    for p in artifact.abi.constructor_params:
        if p.name not in got:
            args.append(None)
            continue
        v = got[p.name]
        if isinstance(v, bool):
            s = 'true' if v else 'false'
        elif isinstance(v, int):
            s = str(v)
        else:
            s = str(v).lower()
        args.append({'type': p.type, 'value': s})
    out['args'] = args
    return out


def main():
    if len(sys.argv) < 2:
        print('Usage: py-sdk-tool.py <input.json>', file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        data = json.load(f)

    artifact = RunarArtifact.from_dict(data['artifact'])
    if 'scriptHex' in data:
        sys.stdout.write(json.dumps(readback(artifact, data['scriptHex'])))
        return
    args = [convert_arg(a) for a in data['constructorArgs']]

    contract = RunarContract(artifact, args)
    if data.get('inscription'):
        insc = data['inscription']
        # N-043: a refused attach is a RESULT, not a crash — exit non-zero with
        # the reason on stderr so the runner can compare the refusal verdict
        # across all seven tiers.
        try:
            contract.with_inscription(Inscription(
                content_type=insc['contentType'],
                data=insc['data'],
            ))
        except ValueError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
    wallet_deploy = data.get('walletDeploy')
    if wallet_deploy is not None:
        # R-062: a refusal is a RESULT, not a crash — exit non-zero with the
        # reason on stderr so the runner can compare the verdict across all
        # seven tiers.
        wallet = StubWallet()
        signer = WalletSigner(wallet, protocol_id=(2, 'conformance'), key_id='1')
        contract.connect(WalletProvider(wallet, signer, basket='conformance'), signer)
        try:
            contract.deploy_with_wallet(
                satoshis=wallet_deploy.get('satoshis', 1),
                acknowledge_unsound=wallet_deploy.get('acknowledgeUnsound', []),
            )
        except Exception as e:
            print(e, file=sys.stderr)
            sys.exit(1)

    sys.stdout.write(contract.get_locking_script())


if __name__ == '__main__':
    main()
