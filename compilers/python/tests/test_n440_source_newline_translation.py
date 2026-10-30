"""N-440 -- the Python tier reads a source file byte-faithfully, without
universal-newline translation.

Pre-fix ``_read_file`` opened the file in text mode, so a lone CR inside a
``.runar.go`` backtick raw literal became LF before the tokenizer saw it. Go's
raw-string rule discards the CR (the Go tier pushes 0x41 0x42 for
```41<CR>42```), but this tier saw ``41<LF>42`` and refused it as non-hex.

What this proves: through the real file-reading entry point, a lone CR (or
several) inside a backtick literal (spelled runar.HexToBytes(`...`) since N-448 refuses a bare one) is discarded exactly as in the Go tier
(hex 4142; a CRLF keeps its LF, so it is not tested as hex), and a CRLF-ended copy of a contract compiles to the same script as
its LF-ended copy on every surface tested here.
What it does NOT prove: any other tier (conformance/negatives covers
those), a lone CR in a double-quoted literal (refused by every tier), or a
lone CR used as a line terminator in surfaces other than the ones listed.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from runar_compiler.compiler import compile_from_source

EXAMPLES = Path(__file__).resolve().parents[3] / "examples"

GO_TEMPLATE = (
    "package contract\n\n"
    'import runar "github.com/icellan/runar/packages/runar-go"\n\n'
    "type Bare struct {\n"
    "\trunar.SmartContract\n"
    '\tExpected runar.ByteString `runar:"readonly"`\n'
    "}\n\n"
    "func (c *Bare) Check() {\n"
    "\tx := runar.HexToBytes(`%s`)\n"
    "\trunar.Assert(x == c.Expected)\n"
    "}\n"
)


def _script(path: Path) -> str:
    return compile_from_source(str(path)).script


@pytest.mark.parametrize("body", ["41\r42", "4\r1\r\r4\r2"])
def test_go_backtick_literal_discards_cr(tmp_path: Path, body: str) -> None:
    f = tmp_path / "Bare.runar.go"
    f.write_bytes((GO_TEMPLATE % body).encode("utf-8"))
    g = tmp_path / "Plain.runar.go"
    g.write_bytes((GO_TEMPLATE % "4142").encode("utf-8"))
    assert _script(f) == _script(g)


@pytest.mark.parametrize("ext", ["ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java"])
def test_crlf_copy_compiles_like_lf_copy(tmp_path: Path, ext: str) -> None:
    src = next(EXAMPLES.glob(f"**/p2pkh/P2PKH.runar.{ext}"))
    raw = src.read_bytes().replace(b"\r\n", b"\n")
    lf = tmp_path / ("lf_" + src.name)
    crlf = tmp_path / ("crlf_" + src.name)
    lf.write_bytes(raw)
    crlf.write_bytes(raw.replace(b"\n", b"\r\n"))
    assert _script(crlf) == _script(lf)
