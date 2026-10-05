"""F-135: RIPEMD-160 must work when OpenSSL 3 has no legacy provider.

OpenSSL 3 builds (Ubuntu 22.04+, Fedora) disable RIPEMD-160 in the default
provider, so ``hashlib.new('ripemd160')`` raises ``ValueError``. Before this
fix every RIPEMD-160 path in runar-py called ``hashlib.new`` bare, and
``runar.test_keys`` hashes the test keys at import time, so ``import runar``
itself died on those platforms.

What these tests prove:
  * the pure-Python RIPEMD-160 in ``runar._ripemd160`` matches the official
    RIPEMD-160 test vectors (Dobbertin/Bosselaers/Preneel) and hashlib;
  * in a fresh interpreter where ``hashlib.new('ripemd160')`` raises
    ``ValueError`` (simulated OpenSSL 3 without the legacy provider),
    ``import runar`` succeeds and hash160 / ripemd160 / test keys /
    LocalSigner / WalletSigner / build_p2pkh_script / the ANF interpreter all
    produce the known digests;
  * no module in the package calls ``hashlib.new('ripemd160', ...)`` outside
    the shared helper (covers call sites such as contract.py that are hard to
    reach in isolation).

What they do not prove: behaviour on a real OpenSSL 3 host. The legacy-provider
failure is simulated by patching ``hashlib.new``; a host that fails differently
(for example raising something other than ValueError) is not covered.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import textwrap

import pytest

from runar._ripemd160 import _ripemd160_pure, ripemd160_digest

_PKG_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Official RIPEMD-160 test vectors (https://homes.esat.kuleuven.be/~bosselae/ripemd160.html).
_OFFICIAL_VECTORS = [
    (b'', '9c1185a5c5e9fc54612808977ee8f548b2258d31'),
    (b'a', '0bdc9d2d256b3ee9daae347be6f4dc835a467ffe'),
    (b'abc', '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'),
    (b'message digest', '5d0689ef49d2fae572b881b123a85ffa21595f36'),
    (b'abcdefghijklmnopqrstuvwxyz', 'f71c27109c692c1b56bbdceb5b9d2865b3708dbc'),
    (b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
     '12a053384a9c0c88e405a06c27dcf49ada62eb2b'),
    (b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
     'b0e20b6e3116640286ed3a87a5713079b21f5189'),
    (b'1234567890' * 8, '9b752e45573d4b39f4dbd3323cab82bf63326bfb'),
]


def _hashlib_has_ripemd160() -> bool:
    try:
        hashlib.new('ripemd160')
        return True
    except ValueError:
        return False


@pytest.mark.parametrize('msg,expected', _OFFICIAL_VECTORS)
def test_pure_python_official_vectors(msg, expected):
    assert _ripemd160_pure(msg).hex() == expected


def test_pure_python_one_million_a():
    assert _ripemd160_pure(b'a' * 1_000_000).hex() == '52783243c1697bdbe16d37f97f68f08325dc1528'


@pytest.mark.skipif(not _hashlib_has_ripemd160(), reason='hashlib has no ripemd160 on this host')
def test_pure_python_matches_hashlib_across_padding_boundaries():
    # Lengths 0..200 cross every padding case (55/56/63/64/119/120/...).
    for n in range(201):
        msg = bytes((i * 7 + n) & 0xFF for i in range(n))
        assert _ripemd160_pure(msg) == hashlib.new('ripemd160', msg).digest(), n


def test_helper_returns_official_digest():
    for msg, expected in _OFFICIAL_VECTORS:
        assert ripemd160_digest(msg).hex() == expected


_PRELUDE = textwrap.dedent('''
    import hashlib
    _orig_new = hashlib.new
    def _no_legacy_new(name, *args, **kwargs):
        if str(name).lower().replace('-', '') in ('ripemd160', 'rmd160'):
            raise ValueError('unsupported hash type ' + str(name))
        return _orig_new(name, *args, **kwargs)
    hashlib.new = _no_legacy_new
''')

_PROBE = textwrap.dedent('''
    import json
    import runar
    from runar import hash160, ripemd160
    from runar.test_keys import ALICE
    from runar.sdk.local_signer import LocalSigner
    from runar.sdk.wallet import WalletSigner
    from runar.sdk.deployment import build_p2pkh_script
    from runar.sdk.anf_interpreter import _hash_fn

    class _Wallet:
        def get_public_key(self, protocol_id, key_id):
            return ALICE.pub_key.hex()

    print(json.dumps({
        'hash160_test': hash160(b'test').hex(),
        'ripemd160_abc': ripemd160(b'abc').hex(),
        'alice_pkh': ALICE.pub_key_hash.hex(),
        'local_signer_address': LocalSigner(ALICE.priv_key).get_address(),
        'wallet_address': WalletSigner(_Wallet(), (2, 'x'), '1').get_address(),
        'p2pkh': build_p2pkh_script(ALICE.pub_key.hex()),
        'anf_ripemd160': _hash_fn('ripemd160', b'abc'.hex()),
        'anf_hash160': _hash_fn('hash160', b'test'.hex()),
    }))
''')


def test_import_and_hash_paths_work_without_hashlib_ripemd160():
    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join(
        [str(_PKG_ROOT)] + ([env['PYTHONPATH']] if env.get('PYTHONPATH') else [])
    )
    proc = subprocess.run(
        [sys.executable, '-c', _PRELUDE + _PROBE],
        capture_output=True, text=True, env=env, cwd=str(_PKG_ROOT),
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout.strip().splitlines()[-1])

    # hash160(b'test') = RIPEMD160(SHA256('test')), cross-checked with
    # the official-vector-verified pure implementation.
    expected_h160_test = _ripemd160_pure(hashlib.sha256(b'test').digest()).hex()
    assert expected_h160_test == 'cebaa98c19807134434d107b0d3e5692a516ea66'
    assert out['hash160_test'] == expected_h160_test
    assert out['ripemd160_abc'] == '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'

    from runar.test_keys import ALICE
    alice_pkh = _ripemd160_pure(hashlib.sha256(ALICE.pub_key).digest()).hex()
    assert out['alice_pkh'] == alice_pkh
    assert out['wallet_address'] == alice_pkh
    assert out['p2pkh'] == '76a914' + alice_pkh + '88ac'
    assert out['anf_ripemd160'] == '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'
    assert out['anf_hash160'] == expected_h160_test

    from runar.sdk.local_signer import LocalSigner
    assert out['local_signer_address'] == LocalSigner(ALICE.priv_key).get_address()


def test_no_bare_hashlib_ripemd160_outside_helper():
    pattern = re.compile(r"hashlib\.new\(\s*['\"]ripemd160['\"]")
    offenders = []
    for path in (_PKG_ROOT / 'runar').rglob('*.py'):
        if path.name == '_ripemd160.py':
            continue
        if pattern.search(path.read_text(encoding='utf-8')):
            offenders.append(str(path.relative_to(_PKG_ROOT)))
    assert offenders == []
