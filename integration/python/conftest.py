"""
Shared fixtures and helpers for Python integration tests.

Run with:
    PYTHONPATH=../../compilers/python:../../packages/runar-py pytest -v

Requires:
    - A BSV regtest node at localhost:18332 (user=bitcoin, pass=bitcoin)
    - bsv-sdk pip package for real ECDSA signing
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from base64 import b64encode
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

import pytest

from runar_compiler.compiler import compile_from_source, artifact_to_json
from runar.sdk import RunarArtifact, RPCProvider, ExternalSigner
from runar.sdk.local_signer import LocalSigner


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_THIS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = _THIS_DIR.parent.parent


# ---------------------------------------------------------------------------
# RPC config
# ---------------------------------------------------------------------------

RPC_URL = os.environ.get("RPC_URL", "http://localhost:18332")
RPC_USER = os.environ.get("RPC_USER", "bitcoin")
RPC_PASS = os.environ.get("RPC_PASS", "bitcoin")


# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

def rpc_call(method: str, *params: object) -> object:
    """Make a JSON-RPC call to the regtest node."""
    body = json.dumps({
        "jsonrpc": "1.0",
        "id": "runar-py",
        "method": method,
        "params": list(params),
    }).encode()

    auth = b64encode(f"{RPC_USER}:{RPC_PASS}".encode()).decode()
    req = Request(
        RPC_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth}",
        },
    )

    resp = urlopen(req, timeout=600)
    data = json.loads(resp.read())

    if data.get("error"):
        msg = data["error"].get("message", str(data["error"]))
        raise RuntimeError(f"RPC {method}: {msg}")

    return data["result"]


def is_node_available() -> bool:
    """Check whether the regtest node is reachable."""
    try:
        rpc_call("getblockcount")
        return True
    except Exception:
        return False


def mine(blocks: int) -> None:
    """Mine blocks on regtest."""
    rpc_call("generate", blocks)


def fund_address(address: str, btc_amount: float = 1.0) -> None:
    """Import an address and send coins to it, then mine a block."""
    rpc_call("importaddress", address, "", False)
    rpc_call("sendtoaddress", address, btc_amount)
    mine(1)


# ---------------------------------------------------------------------------
# Base58Check encoding
# ---------------------------------------------------------------------------

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    result = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        result = _BASE58_ALPHABET[remainder] + result
    # Leading zero bytes become '1' characters
    for byte in data:
        if byte == 0:
            result = "1" + result
        else:
            break
    return result


def _regtest_address(pub_key_hash: str) -> str:
    """Derive a regtest P2PKH address from a hex pubKeyHash (version byte 0x6f)."""
    version_byte = bytes([0x6F])
    payload = version_byte + bytes.fromhex(pub_key_hash)
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _base58_encode(payload + checksum)


def _hash160(data: bytes) -> str:
    """RIPEMD160(SHA256(data)), returned as hex."""
    sha = hashlib.sha256(data).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    return ripe.hex()


# ---------------------------------------------------------------------------
# Wallet / Signer creation
# ---------------------------------------------------------------------------

_wallet_index = os.getpid() * 1000


def create_wallet() -> dict:
    """Create a deterministic wallet using a sequential counter.

    Seeded from PID to avoid collisions between parallel test processes.
    """
    global _wallet_index
    _wallet_index += 1
    priv_hex = format(_wallet_index, '064x')
    local = LocalSigner(priv_hex)
    pub_hex = local.get_public_key()
    pub_key_hash = _hash160(bytes.fromhex(pub_hex))

    return {
        "privKeyHex": priv_hex,
        "pubKeyHex": pub_hex,
        "pubKeyHash": pub_key_hash,
    }


def create_funded_wallet(provider: RPCProvider, btc_amount: float = 1.0) -> dict:
    """Create a funded wallet with an ExternalSigner suitable for the SDK.

    Returns dict with keys: privKeyHex, pubKeyHex, pubKeyHash, address, signer.
    """
    wallet = create_wallet()
    address = _regtest_address(wallet["pubKeyHash"])

    # Import and fund
    rpc_call("importaddress", address, "", False)
    rpc_call("sendtoaddress", address, btc_amount)
    mine(1)

    # Build ExternalSigner wrapping LocalSigner
    local = LocalSigner(wallet["privKeyHex"])

    def _sign_fn(tx_hex: str, input_index: int, subscript: str, satoshis: int, sighash_type: int | None) -> str:
        return local.sign(tx_hex, input_index, subscript, satoshis, sighash_type or 0x41)

    signer = ExternalSigner(
        wallet["pubKeyHex"],
        address,
        _sign_fn,
    )

    return {
        "privKeyHex": wallet["privKeyHex"],
        "pubKeyHex": wallet["pubKeyHex"],
        "pubKeyHash": wallet["pubKeyHash"],
        "address": address,
        "signer": signer,
    }


# ---------------------------------------------------------------------------
# Compilation helper
# ---------------------------------------------------------------------------

def compile_contract(rel_path: str) -> RunarArtifact:
    """Compile a contract from a path relative to the project root.

    Returns an SDK RunarArtifact ready for RunarContract.
    """
    abs_path = str(PROJECT_ROOT / rel_path)
    compiler_artifact = compile_from_source(abs_path)
    artifact_dict = json.loads(artifact_to_json(compiler_artifact))
    return RunarArtifact.from_dict(artifact_dict)


def compile_contract_ts(rel_path: str) -> RunarArtifact:
    """Compile a contract using the TypeScript compiler (via Node subprocess).

    Falls back to this when the Python/Go compilers have known code generation
    differences (e.g., deeply nested if/else if chains in private methods).
    The TS compiler is the reference implementation.
    """
    import subprocess
    abs_path = str(PROJECT_ROOT / rel_path)
    file_name = Path(abs_path).name
    node_script = f"""
    const fs = require('fs');
    async function main() {{
        const {{ compile }} = await import('./packages/runar-compiler/dist/index.js');
        const src = fs.readFileSync({json.dumps(abs_path)}, 'utf-8');
        const result = compile(src, {{ fileName: {json.dumps(file_name)} }});
        if (!result.artifact) {{
            console.error('Compile failed:', JSON.stringify(result.errors));
            process.exit(1);
        }}
        const out = JSON.stringify(result.artifact, (k,v) => typeof v === 'bigint' ? v.toString() + 'n' : v, 2);
        console.log(out);
    }}
    main().catch(e => {{ console.error(e); process.exit(1); }});
    """
    result = subprocess.run(
        ['node', '-e', node_script],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT),
    )
    if result.returncode != 0:
        raise RuntimeError(f"TS compile failed for {rel_path}: {result.stderr}")
    artifact_dict = json.loads(result.stdout)
    return RunarArtifact.from_dict(artifact_dict)


# ---------------------------------------------------------------------------
# Provider helper
# ---------------------------------------------------------------------------

def create_provider() -> RPCProvider:
    """Create an RPCProvider configured for regtest with auto-mine."""
    return RPCProvider.regtest(RPC_URL, RPC_USER, RPC_PASS)


# ---------------------------------------------------------------------------
# EC scalar helpers (secp256k1) -- for EC tests
# ---------------------------------------------------------------------------

EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
EC_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
EC_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _mod_pow(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)


def _mod_inverse(a: int, m: int) -> int:
    return _mod_pow(((a % m) + m) % m, m - 2, m)


def ec_double(px: int, py: int) -> tuple[int, int]:
    s = (3 * px * px * _mod_inverse(2 * py, EC_P)) % EC_P
    rx = ((s * s - 2 * px) % EC_P + EC_P) % EC_P
    ry = ((s * (px - rx) - py) % EC_P + EC_P) % EC_P
    return rx, ry


def ec_add(p1x: int, p1y: int, p2x: int, p2y: int) -> tuple[int, int]:
    if p1x == p2x and p1y == p2y:
        return ec_double(p1x, p1y)
    s = ((p2y - p1y) * _mod_inverse(p2x - p1x, EC_P) % EC_P + EC_P) % EC_P
    rx = ((s * s - p1x - p2x) % EC_P + EC_P) % EC_P
    ry = ((s * (p1x - rx) - p1y) % EC_P + EC_P) % EC_P
    return rx, ry


def ec_mul(px: int, py: int, k: int) -> tuple[int, int]:
    k = ((k % EC_N) + EC_N) % EC_N
    rx, ry = 0, 0
    qx, qy = px, py
    first = True
    while k > 0:
        if k & 1:
            if first:
                rx, ry = qx, qy
                first = False
            else:
                rx, ry = ec_add(rx, ry, qx, qy)
        qx, qy = ec_double(qx, qy)
        k >>= 1
    return rx, ry


def ec_mul_gen(k: int) -> tuple[int, int]:
    return ec_mul(EC_GX, EC_GY, k)


def encode_point(x: int, y: int) -> str:
    return f"{x:064x}{y:064x}"


# ---------------------------------------------------------------------------
# WOTS+ helpers
# ---------------------------------------------------------------------------

WOTS_W = 16
WOTS_N = 32
WOTS_LEN1 = 64
WOTS_LEN2 = 3
WOTS_LEN = WOTS_LEN1 + WOTS_LEN2


def _wots_sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _wots_chain(x: bytes, start: int, steps: int, pub_seed: bytes, chain_idx: int) -> bytes:
    """WOTS+ chain: F(pubSeed || chainIdx_byte || stepIdx_byte || msg).
    Must match the on-chain script which uses 1-byte indices in a single 66-byte hash.
    """
    tmp = bytes(x)
    for i in range(start, start + steps):
        tmp = _wots_sha256(pub_seed + bytes([chain_idx, i]) + tmp)
    return tmp


def wots_keygen(seed: bytes, pub_seed: bytes) -> dict:
    """Generate a WOTS+ keypair. Returns dict with sk, pk (hex), pubSeed."""
    sk = []
    for i in range(WOTS_LEN):
        buf = seed + i.to_bytes(4, "big")
        sk.append(_wots_sha256(buf))

    pk_parts = []
    for i in range(WOTS_LEN):
        pk_parts.append(_wots_chain(sk[i], 0, WOTS_W - 1, pub_seed, i))

    all_pk = b"".join(pk_parts)
    pk_root = _wots_sha256(all_pk)
    pk = pub_seed + pk_root

    return {
        "sk": sk,
        "pk": pk.hex(),
        "pubSeed": pub_seed,
    }


# ---------------------------------------------------------------------------
# Rabin helpers
# ---------------------------------------------------------------------------

def wots_sign(msg: bytes, sk: list[bytes], pub_seed: bytes) -> bytes:
    """Sign a message with WOTS+. Returns the 2,144-byte signature (67 × 32 bytes)."""
    msg_hash = _wots_sha256(msg)
    msg_digits = _wots_extract_digits(msg_hash)
    csum_digits = _wots_checksum_digits(msg_digits)
    all_digits = msg_digits + csum_digits

    sig_parts = []
    for i in range(WOTS_LEN):
        sig_parts.append(_wots_chain(sk[i], 0, all_digits[i], pub_seed, i))
    return b"".join(sig_parts)


def _wots_extract_digits(msg_hash: bytes) -> list[int]:
    digits = []
    for i in range(WOTS_N):
        digits.append(msg_hash[i] >> 4)
        digits.append(msg_hash[i] & 0x0F)
    return digits


def _wots_checksum_digits(msg_digits: list[int]) -> list[int]:
    csum = 0
    for d in msg_digits:
        csum += WOTS_W - 1 - d
    digits = [0] * WOTS_LEN2
    c = csum
    for i in range(WOTS_LEN2 - 1, -1, -1):
        digits[i] = c % WOTS_W
        c //= WOTS_W
    return digits


# ---------------------------------------------------------------------------
# Rabin helpers
# ---------------------------------------------------------------------------

def generate_rabin_key_pair() -> dict:
    """Generate a deterministic Rabin keypair for testing.

    Uses 130-bit primes matching the TS helper.
    n must be > 2^256 so (sig²+padding) % n has the same byte width
    as SHA-256 output — otherwise OP_EQUALVERIFY fails.
    """
    p = 1361129467683753853853498429727072846227
    q = 1361129467683753853853498429727082846007
    return {"p": p, "q": q, "n": p * q}


def rabin_sign(msg: bytes, kp: dict) -> dict:
    """Rabin-sign a message. Returns dict with sig (int) and padding (int).

    On-chain verification: (sig² + padding) mod n === hash mod n
    So we need: sig² ≡ hash - padding (mod n).
    """
    p, q, n = kp["p"], kp["q"], kp["n"]
    h = hashlib.sha256(msg).digest()
    # Interpret hash as unsigned little-endian (matches Bitcoin Script)
    hash_bn = _buffer_to_unsigned_le(h)

    for padding in range(1000):
        target = (hash_bn - padding) % n
        if target < 0:
            target += n
        if not _is_qr(target, p) or not _is_qr(target, q):
            continue
        sp = pow(target, (p + 1) // 4, p)
        sq = pow(target, (q + 1) // 4, q)
        sig = _crt(sp, p, sq, q)
        # Verify: (sig² + padding) mod n === hash mod n
        if (sig * sig + padding) % n == hash_bn % n:
            return {"sig": sig, "padding": padding}
        # Try negative root
        sig_alt = n - sig
        if (sig_alt * sig_alt + padding) % n == hash_bn % n:
            return {"sig": sig_alt, "padding": padding}

    raise RuntimeError("Rabin sign: no valid padding found")


def _buffer_to_unsigned_le(buf: bytes) -> int:
    """Interpret bytes as unsigned little-endian integer (matches Bitcoin Script)."""
    result = 0
    for i, b in enumerate(buf):
        result += b << (i * 8)
    return result


def _is_qr(a: int, p: int) -> bool:
    """Check if a is a quadratic residue mod p (Euler criterion)."""
    if a % p == 0:
        return True
    return pow(a, (p - 1) // 2, p) == 1


def _crt(a1: int, m1: int, a2: int, m2: int) -> int:
    """Chinese Remainder Theorem: find x such that x ≡ a1 (mod m1), x ≡ a2 (mod m2)."""
    m = m1 * m2
    p1 = pow(m2, m1 - 2, m1)
    p2 = pow(m1, m2 - 2, m2)
    return (a1 * m2 * p1 + a2 * m1 * p2) % m


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def skip_if_no_node():
    """Auto-skip all tests if the regtest node is not available."""
    if not is_node_available():
        pytest.skip("BSV regtest node not available")
