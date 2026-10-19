"""F-193 -- the SHA-256 / BLAKE3 compression op caches must not carry one call
site's source location into another compilation.

``sha256.py`` / ``blake3.py`` build their (21k / 10k op) compression bodies once
per process and hand the SAME ``StackOp`` objects to ``emit_op`` on every call.
``emit_op`` used to stamp ``source_loc`` on the object it was given, so the first
call site in the process pinned its location onto the cache for good, and every
later call site (other method, other contract, other compilation) emitted ops
still pointing at the first one. Emitted bytes were never affected -- only the
source map -- but the Python source map became order- and process-dependent.

What this proves: compiling contract A then contract B (different files, the
intrinsic call on different lines) in ONE process, every source-map entry of B
that comes from the compression body reports B's own file and call line, A's
file appears nowhere in B's map, and re-compiling A afterwards still maps to A.
Covers sha256Compress, sha256Finalize (which splices the compress body twice)
and blake3Compress. A positive control checks the entries exist in volume, so
the assertions are not vacuous.

What this does not prove: anything about the other six tiers (probed separately),
or about caches in other codegen modules (none exist: only sha256.py and
blake3.py hold module-level StackOp lists).
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source

SHA_COMPRESS = '''from runar import SmartContract, ByteString, public, assert_, sha256_compress


class {name}(SmartContract):
    expected: ByteString

    def __init__(self, expected: ByteString):
        super().__init__(expected)
        self.expected = expected

    @public
    def verify(self, state: ByteString, block: ByteString):
        result = sha256_compress(state, block)
        assert_(result == self.expected)
'''

SHA_FINALIZE = '''from runar import SmartContract, ByteString, Bigint, public, assert_, sha256_finalize


class {name}(SmartContract):
    expected: ByteString

    def __init__(self, expected: ByteString):
        super().__init__(expected)
        self.expected = expected

    @public
    def verify(self, state: ByteString, remaining: ByteString, n: Bigint):
        result = sha256_finalize(state, remaining, n)
        assert_(result == self.expected)
'''

BLAKE3_COMPRESS = '''from runar import SmartContract, ByteString, public, assert_, blake3_compress


class {name}(SmartContract):
    expected: ByteString

    def __init__(self, expected: ByteString):
        super().__init__(expected)
        self.expected = expected

    @public
    def verify(self, cv: ByteString, block: ByteString):
        result = blake3_compress(cv, block)
        assert_(result == self.expected)
'''

CASES = {
    "sha256Compress": (SHA_COMPRESS, "sha256_compress(state, block)", 15000),
    "sha256Finalize": (SHA_FINALIZE, "sha256_finalize(state, remaining, n)", 15000),
    "blake3Compress": (BLAKE3_COMPRESS, "blake3_compress(cv, block)", 5000),
}


def _compile(tmp_path, template, name, pad, filename):
    # `pad` blank lines shift the call site, so two files never share a line.
    src = template.format(name=name)
    src = src.replace("class ", "\n" * pad + "class ", 1)
    path = tmp_path / filename
    path.write_text(src)
    call_line = next(
        i + 1 for i, ln in enumerate(src.split("\n")) if "result = " in ln
    )
    artifact = compile_from_source(str(path), disable_constant_folding=True)
    return str(path), call_line, artifact.source_map or []


@pytest.mark.parametrize("intrinsic", sorted(CASES))
def test_op_cache_does_not_leak_source_loc_across_compilations(tmp_path, intrinsic):
    template, _needle, min_ops = CASES[intrinsic]

    file_a, line_a, map_a = _compile(tmp_path, template, "ContractA", 0, "A.runar.py")
    file_b, line_b, map_b = _compile(tmp_path, template, "ContractB", 7, "B.runar.py")
    assert line_a != line_b

    # Positive control: A's own map is attributed to A, in volume.
    assert sum(1 for m in map_a if m.source_file == file_a and m.line == line_a) >= min_ops

    # B's map: no entry may point at A, and the compression body points at B's call line.
    leaked = [m for m in map_b if m.source_file != file_b]
    assert not leaked, (
        f"{len(leaked)} of {len(map_b)} entries in B's source map point at "
        f"{leaked[0].source_file}"
    )
    own = sum(1 for m in map_b if m.source_file == file_b and m.line == line_b)
    assert own >= min_ops, f"only {own} entries map to B's call line {line_b}"

    # Compiling A again after B must still map to A (cache not re-poisoned by B).
    file_a2, line_a2, map_a2 = _compile(tmp_path, template, "ContractA", 0, "A.runar.py")
    assert all(m.source_file == file_a2 for m in map_a2)
    assert sum(1 for m in map_a2 if m.line == line_a2) >= min_ops
