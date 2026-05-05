#!/usr/bin/env python3
"""Test-skip inventory audit.

Discovers every skip-surface marker in the repository test corpus and
cross-references it against the rows in `docs/test-skips.md`. The audit
fails when:

  * A skip site has no documenting row (orphan skip).
  * A documenting row claims a `file:line` that no longer carries a skip
    marker (stale row).

Matching policy mirrors the user-facing audit doc:

  1. Exact `file:line` match wins.
  2. Otherwise, fall back to "exact `file` + the enclosing test name
     appears verbatim somewhere in the row" — used for files where the
     line numbers churn but the test names are stable (e.g. the long
     vitest describe.skipIf cascades in cross-compiler.test.ts).

The lint surface intentionally mirrors `scripts/lint-no-silent-skips.sh`
so a reviewer running either tool sees the same cohort.

Run:
    python3 scripts/audit-test-skips.py

Exit codes:
    0  every skip is documented; every doc row points to a live skip.
    1  one or more orphan skips.
    2  one or more stale rows.
    3  both orphans and stales.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Iterable, NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Skip-pattern surface — keep in sync with scripts/lint-no-silent-skips.sh.
# ---------------------------------------------------------------------------

EXCLUDE_RE = re.compile(
    r"(/dist/|/target/|/build/|/node_modules/|\.zig-cache|/\.gradle/|/zig-out/"
    r"|/coverage/|/\.venv/|/site-packages/|/__pycache__/|\.egg-info/|/vendor/"
    r"|/runar-verification/)"
)

SKIP_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # JavaScript / TypeScript (vitest)
    (
        ".ts .tsx .js",
        re.compile(r"\b(?:describe|it)\.skip\b|\b(?:describe|it)\.skipIf\b"),
    ),
    # Go
    (
        ".go",
        re.compile(r"\bt\.Skip(?:f)?\b"),
    ),
    # Python
    (
        ".py",
        re.compile(
            r"@pytest\.mark\.skip\b|pytest\.mark\.skipif\b|pytest\.skip\(|@unittest\.skip\b"
        ),
    ),
    # Rust — `#[ignore]` and `#[ignore = "..."]` (with reason).
    (
        ".rs",
        re.compile(r"#\[ignore(?:\s*=\s*\"[^\"]*\")?\]|#\[cfg\(ignore\)\]"),
    ),
    # Java (JUnit 5)
    (
        ".java",
        re.compile(
            r"\bAssumptions\.assume(?:True|False)\b|@Disabled\b|@EnabledIfEnvironmentVariable\b|@EnabledIfSystemProperty\b"
        ),
    ),
    # Ruby (RSpec / Minitest). Matches both `skip(...)` and the bare
    # `skip 'reason'` form RSpec accepts.
    (
        ".rb",
        re.compile(r"\b(?:skip|pending|xit|xdescribe)[\s(]"),
    ),
    # Zig — `return error.SkipZigTest` is the standard test-runner skip
    # idiom in 0.16.
    (
        ".zig",
        re.compile(r"return\s+error\.SkipZigTest\b"),
    ),
    # Shell — run-all.sh prints `--- <Lang>: SKIPPED ...` on missing toolchain.
    (
        ".sh",
        re.compile(r"echo .*--- [A-Za-z]+: SKIPPED"),
    ),
]

# Files that report skip-style markers but are NOT test-runner gates and
# don't belong in the inventory. Comparator: full path or basename.
ALLOWLIST_FILES: set[str] = {
    "scripts/lint-no-silent-skips.sh",  # describes patterns
    "scripts/audit-test-skips.py",  # this script
}

# Walked roots — keep in sync with the lint script.
ROOTS = [
    "compilers",
    "packages",
    "conformance",
    "integration",
    "examples",
    "tests",
]

INVENTORY_PATH = REPO_ROOT / "docs" / "test-skips.md"

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class SkipSite(NamedTuple):
    path: str  # relative to REPO_ROOT, POSIX-style
    line: int
    snippet: str


def _files_under(root: Path) -> Iterable[Path]:
    if not root.exists():
        return []
    out = []
    for p, dirs, files in os.walk(root):
        # Apply the exclude regex to directories aggressively so we don't
        # descend into venv / target / node_modules etc.
        rel_p = os.path.relpath(p, REPO_ROOT)
        if EXCLUDE_RE.search("/" + rel_p + "/"):
            dirs[:] = []
            continue
        for f in files:
            full = Path(p) / f
            rel = str(full.relative_to(REPO_ROOT)).replace(os.sep, "/")
            if EXCLUDE_RE.search("/" + rel + "/"):
                continue
            out.append(full)
    return out


_COMMENT_PREFIX_RE = re.compile(r"^\s*(?://|#|--|;|\*\s|/\*)")


def _is_comment_line(line: str, ext: str) -> bool:
    """Cheap heuristic: a line that starts with a single-line comment marker
    is treated as a comment for purposes of skip-site discovery. We do NOT
    try to track block-comment state; skip markers inside a multi-line `/*
    ... */` are vanishingly rare and would still report no live skip if
    accidentally claimed."""
    stripped = line.lstrip()
    if not stripped:
        return False
    # Common single-line comment prefixes across our languages.
    comment_prefixes = {
        ".go": ("//",),
        ".rs": ("//",),
        ".ts": ("//",),
        ".tsx": ("//",),
        ".js": ("//",),
        ".java": ("//",),
        ".zig": ("//",),
        ".py": ("#",),
        ".rb": ("#",),
        ".sh": ("#",),
    }
    for pfx in comment_prefixes.get(ext, ()):
        if stripped.startswith(pfx):
            return True
    return False


def _is_test_file(rel_path: str, ext: str) -> bool:
    """Return True iff `rel_path` looks like a test source file. Skip-pattern
    matching is restricted to test files because production source code
    legitimately uses tokens like `# skip ','` or method names containing
    `skip` and we don't want false positives there."""
    parts = rel_path.split("/")
    name = parts[-1]
    # JS/TS — vitest uses *.test.ts / *.spec.ts; the runar-testing
    # `__tests__` convention is also used.
    if ext in (".ts", ".tsx", ".js"):
        return (
            ".test." in name
            or ".spec." in name
            or "__tests__" in parts
            or name.endswith("_test.ts")
        )
    # Go uses `_test.go`.
    if ext == ".go":
        return name.endswith("_test.go")
    # Python: pytest convention is test_*.py / *_test.py inside tests/ or alongside.
    if ext == ".py":
        return name.startswith("test_") or name.endswith("_test.py")
    # Rust: integration tests live in tests/ subdirs; unit tests inline
    # within src/ are usually flagged with `#[cfg(test)]` blocks. Restricting
    # to tests/ is fine here because the only #[ignore] markers we have are
    # in tests/wallet_client_integration.rs.
    if ext == ".rs":
        return "tests" in parts or name.endswith("_test.rs")
    # Java: src/test/ trees.
    if ext == ".java":
        return "test" in parts and "java" in parts
    # Ruby: RSpec spec/ and Minitest test/.
    if ext == ".rb":
        return (
            "spec" in parts
            or "test" in parts
            or name.endswith("_spec.rb")
            or name.endswith("_test.rb")
        )
    # Zig: any *_test.zig OR src/ files that contain `test "..."` blocks
    # alongside production code. We accept all .zig under packages/ and
    # integration/ since the skip pattern (`return error.SkipZigTest`) is
    # unambiguous.
    if ext == ".zig":
        return True
    # Shell: only run-all.sh (handled separately).
    if ext == ".sh":
        return True
    return False


def discover_skip_sites() -> list[SkipSite]:
    sites: list[SkipSite] = []
    for root_name in ROOTS:
        root = REPO_ROOT / root_name
        for f in _files_under(root):
            ext = f.suffix
            rel = str(f.relative_to(REPO_ROOT)).replace(os.sep, "/")
            if rel in ALLOWLIST_FILES:
                continue
            if not _is_test_file(rel, ext):
                continue
            for label, pat in SKIP_PATTERNS:
                if ext not in label.split():
                    continue
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                for i, line in enumerate(text.splitlines(), 1):
                    if not pat.search(line):
                        continue
                    if _is_comment_line(line, ext):
                        continue
                    sites.append(SkipSite(rel, i, line.strip()))
    # Also pick up integration/run-all.sh (it's not under any of ROOTS,
    # but the run-all.sh has SKIPPED echo).
    runall = REPO_ROOT / "integration" / "run-all.sh"
    if runall.exists():
        text = runall.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"echo .*--- [A-Za-z]+: SKIPPED", line):
                sites.append(SkipSite("integration/run-all.sh", i, line.strip()))
    return sorted(set(sites))


# ---------------------------------------------------------------------------
# Inventory parsing
# ---------------------------------------------------------------------------


class InventoryRow(NamedTuple):
    line_in_md: int
    test_cell: str  # Markdown: pre-`File:line` column (often test names)
    file_line_cell: str  # raw cell content (may carry multiple paths)
    rationale_cell: str
    sites: tuple[tuple[str, int], ...]  # extracted (path, line) pairs


_FILELINE_RE = re.compile(
    r"`?(?P<path>[\w./\-]+\.[A-Za-z0-9]+):(?P<lines>[\d,\s]+)`?"
)


def parse_inventory(md_path: Path) -> list[InventoryRow]:
    if not md_path.exists():
        return []
    rows: list[InventoryRow] = []
    for line_no, raw in enumerate(md_path.read_text(encoding="utf-8").splitlines(), 1):
        # Only consume table rows from the inventory section. Pipe-delimited
        # rows starting with `|` and containing at least 4 cells.
        if not raw.startswith("|"):
            continue
        cells = [c.strip() for c in raw.strip().strip("|").split("|")]
        if len(cells) < 4:
            continue
        # Skip header / divider rows.
        if cells[0].startswith("---") or cells[1].startswith("---"):
            continue
        if "File:line" in cells[1]:
            continue
        test_cell, file_line_cell, _category, rationale_cell = cells[0], cells[1], cells[2], cells[3]
        if not file_line_cell:
            continue
        # Extract every `path.ext:N[,M,...]` chunk in the cell.
        sites: list[tuple[str, int]] = []
        for m in _FILELINE_RE.finditer(file_line_cell):
            path = m.group("path")
            for s in re.split(r"[,\s]+", m.group("lines")):
                if s.isdigit():
                    sites.append((path, int(s)))
        if sites:
            rows.append(InventoryRow(line_no, test_cell, file_line_cell, rationale_cell, tuple(sites)))
    return rows


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------


def enclosing_test_name(path: str, skip_line: int) -> str | None:
    """Walk backwards from `skip_line` looking for a recognizable test
    declaration. Returns the test name if found.
    """
    full = REPO_ROOT / path
    if not full.exists():
        return None
    text = full.read_text(encoding="utf-8", errors="replace").splitlines()
    if skip_line - 1 >= len(text):
        return None
    patterns: list[re.Pattern[str]] = [
        # Go: func TestX(t *testing.T)
        re.compile(r"^func\s+(Test\w+)\s*\("),
        # Python: def test_x(...)
        re.compile(r"^\s*def\s+(test_\w+)\s*\("),
        # Rust: fn name() inside a #[test] block
        re.compile(r"^\s*fn\s+(\w+)\s*\("),
        # JS/TS: describe('name', ... or it('name', ...
        re.compile(r"\b(?:describe|it)(?:\.skipIf)?\s*\(\s*['\"`]([^'\"`]+)['\"`]"),
        # Java: void name() (preceded by @Test)
        re.compile(r"^\s*(?:@\w+\(?[^)]*\)?\s*)*void\s+(\w+)\s*\("),
    ]
    for i in range(skip_line - 1, max(skip_line - 60, -1), -1):
        line = text[i]
        for pat in patterns:
            m = pat.search(line)
            if m:
                return m.group(1)
    return None


def main() -> int:
    sites = discover_skip_sites()
    rows = parse_inventory(INVENTORY_PATH)

    doc_pairs: dict[tuple[str, int], InventoryRow] = {}
    doc_paths_by_path: dict[str, list[InventoryRow]] = {}
    for row in rows:
        for site in row.sites:
            doc_pairs[site] = row
            doc_paths_by_path.setdefault(site[0], []).append(row)

    site_pairs: set[tuple[str, int]] = {(s.path, s.line) for s in sites}

    orphans: list[SkipSite] = []
    for site in sites:
        key = (site.path, site.line)
        if key in doc_pairs:
            continue
        # Test-name fallback.
        name = enclosing_test_name(site.path, site.line)
        if name:
            same_file_rows = doc_paths_by_path.get(site.path, [])
            if any(name in r.test_cell or name in r.rationale_cell for r in same_file_rows):
                continue
        orphans.append(site)

    stales: list[tuple[InventoryRow, str, int]] = []
    for row in rows:
        for path, line in row.sites:
            full = REPO_ROOT / path
            if not full.exists():
                stales.append((row, path, line))
                continue
            try:
                lines_in_file = full.read_text(encoding="utf-8", errors="replace").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            if (path, line) in site_pairs:
                continue
            # Forgive line drift if the same file has at least one live
            # skip and the doc test name still matches that skip.
            siblings = [s for s in sites if s.path == path]
            if siblings:
                cell_text = row.test_cell + " " + row.rationale_cell
                if any(s.snippet and any(tok in cell_text for tok in re.split(r"\s+", s.snippet) if len(tok) > 3) for s in siblings):
                    # Loose match: the cited file still has a live skip,
                    # and the rationale references some token from the
                    # snippet. Keep this looser check disabled for now —
                    # report as stale so the doc gets refreshed.
                    pass
            stales.append((row, path, line))

    rc = 0
    if orphans:
        print("ORPHAN skips (no row in docs/test-skips.md):", file=sys.stderr)
        for s in orphans:
            print(f"  {s.path}:{s.line}  {s.snippet}", file=sys.stderr)
        rc |= 1

    if stales:
        print("STALE inventory rows (file:line no longer carries a skip):", file=sys.stderr)
        for row, path, line in stales:
            print(
                f"  docs/test-skips.md:{row.line_in_md} cites {path}:{line} (no longer a skip site)",
                file=sys.stderr,
            )
        rc |= 2

    if rc == 0:
        print(f"OK — {len(sites)} skip sites; {len(rows)} inventory rows; every site documented, every row live.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
