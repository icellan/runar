"""SLH-DSA verification for the repo's SHA-256-only SLH-DSA variant.

This is the variant the compiled on-chain verifier and the TS / Go / Rust /
Zig / Ruby / Java SDKs implement: FIPS 205 Section 11.2.1 (category 1)
SHA-256 instantiation of F / H / T_l / PRF / H_msg / PRF_msg, applied to all
six SHA2 parameter sets at their FIPS 205 Table 2 dimensions. For the 192 and
256 sets this deliberately differs from real FIPS 205, which uses SHA-512 for
H / T_l / H_msg / PRF_msg there (SHA-512 is not available on-chain, #137).
Signatures use the internal interface (no context prefix).

Port reference: packages/runar-rb/lib/runar/slh_dsa.rb (verify path) and
packages/runar-go/slh_dsa.go. Pure stdlib; no optional dependency.
"""

import hashlib


def _wots_len(n: int) -> int:
    # w = 16: len1 = 2n, len2 = floor(log2(len1 * 15) / 4) + 1 = 3.
    len1 = 2 * n
    len2 = ((len1 * 15).bit_length() - 1) // 4 + 1
    return len1 + len2


def _params(name, n, h, d, hp, a, k):
    return {'name': name, 'n': n, 'h': h, 'd': d, 'hp': hp, 'a': a, 'k': k, 'w': 16, 'len': _wots_len(n)}


# Shared parameter table — identical to SLH_SHA2_* in every other tier.
PARAM_SETS = {
    'sha2_128s': _params('SLH-DSA-SHA2-128s', 16, 63, 7, 9, 12, 14),
    'sha2_128f': _params('SLH-DSA-SHA2-128f', 16, 66, 22, 3, 6, 33),
    'sha2_192s': _params('SLH-DSA-SHA2-192s', 24, 63, 7, 9, 14, 17),
    'sha2_192f': _params('SLH-DSA-SHA2-192f', 24, 66, 22, 3, 8, 33),
    'sha2_256s': _params('SLH-DSA-SHA2-256s', 32, 64, 8, 8, 14, 22),
    'sha2_256f': _params('SLH-DSA-SHA2-256f', 32, 68, 17, 4, 9, 35),
}

# ADRS types (FIPS 205 Section 4.2)
_WOTS_HASH = 0
_WOTS_PK = 1
_TREE = 2
_FORS_TREE = 3
_FORS_ROOTS = 4


def _new_adrs(layer: int, tree: int) -> bytearray:
    adrs = bytearray(32)
    adrs[0:4] = layer.to_bytes(4, 'big')
    adrs[4:16] = (tree & ((1 << 96) - 1)).to_bytes(12, 'big')
    return adrs


def _set_type(adrs: bytearray, typ: int) -> None:
    adrs[16:20] = typ.to_bytes(4, 'big')
    adrs[20:32] = bytes(12)


def _set_u32(adrs: bytearray, off: int, v: int) -> None:
    adrs[off:off + 4] = v.to_bytes(4, 'big')


def _t_hash(pk_seed: bytes, adrs: bytearray, msg: bytes, n: int) -> bytes:
    # T_l(PK.seed, ADRS, M) = trunc_n(SHA-256(PK.seed || 0^(64-n) || ADRSc || M))
    adrs_c = bytes(adrs[3:4]) + bytes(adrs[8:16]) + bytes(adrs[19:20]) + bytes(adrs[20:32])
    return hashlib.sha256(pk_seed + bytes(64 - n) + adrs_c + msg).digest()[:n]


def _hmsg(r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes, out_len: int) -> bytes:
    # MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)
    seed = r + pk_seed + hashlib.sha256(r + pk_seed + pk_root + msg).digest()
    out = b''
    counter = 0
    while len(out) < out_len:
        out += hashlib.sha256(seed + counter.to_bytes(4, 'big')).digest()
        counter += 1
    return out[:out_len]


def _base_16(data: bytes, out_len: int) -> list:
    digits = []
    for b in data:
        digits.append(b >> 4)
        digits.append(b & 0x0F)
    return digits[:out_len]


def _wots_pk_from_sig(sig: bytes, msg: bytes, pk_seed: bytes, adrs: bytearray, kp: int, p) -> bytes:
    n, ln = p['n'], p['len']
    len1 = 2 * n
    len2 = ln - len1
    digits = _base_16(msg, len1)
    csum = sum(15 - x for x in digits)
    csum <<= (8 - ((len2 * 4) % 8)) % 8
    digits += _base_16(csum.to_bytes((len2 * 4 + 7) // 8, 'big'), len2)

    chain_adrs = bytearray(adrs)
    _set_type(chain_adrs, _WOTS_HASH)
    _set_u32(chain_adrs, 20, kp)
    parts = b''
    for i in range(ln):
        _set_u32(chain_adrs, 24, i)
        tmp = sig[i * n:(i + 1) * n]
        for j in range(digits[i], 15):
            _set_u32(chain_adrs, 28, j)
            tmp = _t_hash(pk_seed, chain_adrs, tmp, n)
        parts += tmp

    pk_adrs = bytearray(adrs)
    _set_type(pk_adrs, _WOTS_PK)
    _set_u32(pk_adrs, 20, kp)
    return _t_hash(pk_seed, pk_adrs, parts, n)


def _xmss_pk_from_sig(idx: int, sig_xmss: bytes, msg: bytes, pk_seed: bytes, adrs: bytearray, p) -> bytes:
    n, hp = p['n'], p['hp']
    wots_len = p['len'] * n
    node = _wots_pk_from_sig(sig_xmss[:wots_len], msg, pk_seed, adrs, idx, p)
    auth = sig_xmss[wots_len:]

    tree_adrs = bytearray(adrs)
    _set_type(tree_adrs, _TREE)
    for j in range(hp):
        auth_j = auth[j * n:(j + 1) * n]
        _set_u32(tree_adrs, 24, j + 1)
        _set_u32(tree_adrs, 28, idx >> (j + 1))
        combined = node + auth_j if ((idx >> j) & 1) == 0 else auth_j + node
        node = _t_hash(pk_seed, tree_adrs, combined, n)
    return node


def _fors_idx(md: bytes, i: int, a: int) -> int:
    # i-th a-bit big-endian chunk of md (FIPS 205 Algorithm 4, MSB-first).
    bits = int.from_bytes(md, 'big')
    total = len(md) * 8
    return (bits >> (total - (i + 1) * a)) & ((1 << a) - 1)


def _fors_pk_from_sig(fors_sig: bytes, md: bytes, pk_seed: bytes, adrs: bytearray, kp: int, p) -> bytes:
    n, a, k = p['n'], p['a'], p['k']
    roots = b''
    off = 0
    node_adrs = bytearray(adrs)
    _set_type(node_adrs, _FORS_TREE)
    _set_u32(node_adrs, 20, kp)
    for i in range(k):
        idx = _fors_idx(md, i, a)
        sk = fors_sig[off:off + n]
        off += n
        _set_u32(node_adrs, 24, 0)
        _set_u32(node_adrs, 28, (i << a) + idx)
        node = _t_hash(pk_seed, node_adrs, sk, n)
        for j in range(a):
            auth_j = fors_sig[off:off + n]
            off += n
            _set_u32(node_adrs, 24, j + 1)
            _set_u32(node_adrs, 28, (i << (a - j - 1)) + (idx >> (j + 1)))
            combined = node + auth_j if ((idx >> j) & 1) == 0 else auth_j + node
            node = _t_hash(pk_seed, node_adrs, combined, n)
        roots += node

    roots_adrs = bytearray(adrs)
    _set_type(roots_adrs, _FORS_ROOTS)
    _set_u32(roots_adrs, 20, kp)
    return _t_hash(pk_seed, roots_adrs, roots, n)


def slh_verify(param_set: str, msg: bytes, sig: bytes, pk: bytes) -> bool:
    """Verify an SLH-DSA signature under the repo's SHA-256-only variant.

    Returns False (never raises) for a wrong-length public key or signature.
    Raises ValueError for an unknown parameter-set name.
    """
    p = PARAM_SETS.get(param_set)
    if p is None:
        raise ValueError(f"Unknown parameter set: {param_set}")
    n, d, hp, k, a, h = p['n'], p['d'], p['hp'], p['k'], p['a'], p['h']
    msg, sig, pk = bytes(msg), bytes(sig), bytes(pk)

    fors_len = k * (1 + a) * n
    xmss_len = (p['len'] + hp) * n
    if len(pk) != 2 * n or len(sig) != n + fors_len + d * xmss_len:
        return False

    pk_seed, pk_root = pk[:n], pk[n:]
    r = sig[:n]
    fors_sig = sig[n:n + fors_len]
    off = n + fors_len

    md_len = (k * a + 7) // 8
    tree_len = (h - hp + 7) // 8
    leaf_len = (hp + 7) // 8
    digest = _hmsg(r, pk_seed, pk_root, msg, md_len + tree_len + leaf_len)
    md = digest[:md_len]
    tree_idx = int.from_bytes(digest[md_len:md_len + tree_len], 'big') & ((1 << (h - hp)) - 1)
    leaf_idx = int.from_bytes(digest[md_len + tree_len:], 'big') & ((1 << hp) - 1)

    node = _fors_pk_from_sig(fors_sig, md, pk_seed, _new_adrs(0, tree_idx), leaf_idx, p)
    for layer in range(d):
        xmss_sig = sig[off:off + xmss_len]
        off += xmss_len
        node = _xmss_pk_from_sig(leaf_idx, xmss_sig, node, pk_seed, _new_adrs(layer, tree_idx), p)
        leaf_idx = tree_idx & ((1 << hp) - 1)
        tree_idx >>= hp
    return node == pk_root
