#!/usr/bin/env python3
import json
import sys
import os

# Add runar-py to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'packages', 'runar-py'))

from runar.sdk import RunarContract, RunarArtifact, Inscription


def convert_arg(arg: dict):
    t = arg['type']
    v = arg['value']
    if t in ('bigint', 'int'):
        return int(v)
    if t == 'bool':
        return v == 'true'
    # ByteString, PubKey, Addr, Sig, Ripemd160, Sha256, Point — hex strings
    return v


def main():
    if len(sys.argv) < 2:
        print('Usage: py-sdk-tool.py <input.json>', file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        data = json.load(f)

    artifact = RunarArtifact.from_dict(data['artifact'])
    args = [convert_arg(a) for a in data['constructorArgs']]

    contract = RunarContract(artifact, args)
    if data.get('inscription'):
        insc = data['inscription']
        contract.with_inscription(Inscription(
            content_type=insc['contentType'],
            data=insc['data'],
        ))
    sys.stdout.write(contract.get_locking_script())


if __name__ == '__main__':
    main()
