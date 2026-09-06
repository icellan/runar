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

On top of skip/row reconciliation the audit also checks that the
inventory DOCUMENT is internally consistent, because a table and a
prose footer that disagree let a reader take the footer at face value
and conclude the opposite of the truth:

  * Every physical table row must be parseable — its `File:line` cell
    must yield at least one `path:line`. A row with no parseable
    location is invisible to the reconciliation above, so it can claim
    to document a skip while documenting nothing.
  * Every row's Category must come from the closed set
    {Environmental, Gap, Stale}; an unrecognised category would escape
    the per-category counts below.
  * The `### Gap skips` / `### Stale skips` footers must state a count
    that agrees with the number of rows carrying that category.
  * Every `Gap` row must reference a tracker issue (`#<number>`), so a
    deferred defect cannot be parked in the table anonymously.

Run:
    python3 scripts/audit-test-skips.py

Exit codes (bitwise OR):
    0  every skip is documented; every row is live; the doc agrees with itself.
    1  one or more orphan skips.
    2  one or more stale rows.
    4  the inventory document contradicts itself (unparseable row,
       unknown category, footer/table count mismatch, Gap row with no
       issue reference).
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
    # Java (JUnit 5). `@EnabledIf\w*` / `@DisabledIf\w*` deliberately cover the
    # GENERIC `@EnabledIf("method")` / `@DisabledIf("method")` forms as well as
    # the `...EnvironmentVariable` / `...SystemProperty` specialisations. Only
    # the two specialisations were listed before, so a test disabled with the
    # generic form was invisible to this audit and to the CI lint that wraps it
    # — `FixtureConformanceTest.java:62` sat in exactly that hole.
    (
        ".java",
        re.compile(
            r"\bAssumptions\.assume(?:True|False)\b|@Disabled\b|@EnabledIf\w*|@DisabledIf\w*"
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
    category_cell: str  # Environmental | Gap | Stale
    rationale_cell: str
    sites: tuple[tuple[str, int], ...]  # extracted (path, line) pairs


_FILELINE_RE = re.compile(
    r"`?(?P<path>[\w./\-]+\.[A-Za-z0-9]+):(?P<lines>[\d,\s]+)`?"
)

# Closed category vocabulary, mirroring the "## Categories" prose in the doc.
CATEGORIES = ("Environmental", "Gap", "Stale")

# Categories whose footer section is MANDATORY. Gap and Stale are the two the
# doc promises stay at zero (or stay tracked), so their count is a claim a
# reader acts on — the claim must exist and must be checkable. Environmental is
# the bulk default and carries no summary section; a per-PR count there would
# be churn with nothing to contradict.
FOOTER_REQUIRED = ("Gap", "Stale")

# A Gap row must name the tracker item that owns the missing piece.
_ISSUE_RE = re.compile(r"#\d+")


def parse_inventory(md_path: Path) -> list[InventoryRow]:
    """Every PHYSICAL table row in the inventory, parseable or not.

    Rows with an unparseable `File:line` cell are returned with empty
    `sites` rather than dropped: silently dropping them is what let a row
    claim to document a skip while the reconciliation never saw it.
    `check_inventory_integrity` turns such a row into a hard failure.
    """
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
        test_cell, file_line_cell, category_cell, rationale_cell = (
            cells[0],
            cells[1],
            cells[2],
            cells[3],
        )
        # Extract every `path.ext:N[,M,...]` chunk in the cell.
        sites: list[tuple[str, int]] = []
        for m in _FILELINE_RE.finditer(file_line_cell):
            path = m.group("path")
            for s in re.split(r"[,\s]+", m.group("lines")):
                if s.isdigit():
                    sites.append((path, int(s)))
        rows.append(
            InventoryRow(
                line_no,
                test_cell,
                file_line_cell,
                category_cell,
                rationale_cell,
                tuple(sites),
            )
        )
    return rows


def parse_footer_counts(md_path: Path) -> dict[str, tuple[int | None, int]]:
    """Stated counts from the `### <Category> skips` footer sections.

    Returns {category: (stated_count_or_None, line_in_md)}. A section body
    opening with "None" states 0; otherwise the body must open with an
    integer. `None` for the count means "present but unparseable", which is
    itself a failure — a footer a reader cannot check is a footer that can
    quietly contradict the table.
    """
    out: dict[str, tuple[int | None, int]] = {}
    if not md_path.exists():
        return out
    lines = md_path.read_text(encoding="utf-8").splitlines()
    for i, raw in enumerate(lines):
        m = re.match(r"^###\s+(\w+) skips\s*$", raw.strip())
        if not m or m.group(1) not in CATEGORIES:
            continue
        category = m.group(1)
        body: list[str] = []
        for follow in lines[i + 1 :]:
            if follow.startswith("#"):
                break
            body.append(follow)
        text = " ".join(body).strip()
        stated: int | None = None
        if re.match(r"^\**None\b", text, re.IGNORECASE):
            stated = 0
        else:
            num = re.match(r"^\**(\d+)\b", text)
            if num:
                stated = int(num.group(1))
        out[category] = (stated, i + 1)
    return out


def check_inventory_integrity(
    rows: list[InventoryRow], footers: dict[str, tuple[int | None, int]]
) -> list[str]:
    """Fail on a doc that contradicts itself.

    The audit's reconciliation only ever sees rows it could parse, so a row
    with no `path:line` is a hole in the gate, and a prose footer stating a
    count the table does not support is a claim nothing checks. #149 was an
    open S0 while the Gap footer read "the audit found no gap skips".
    """
    problems: list[str] = []

    for row in rows:
        where = f"docs/test-skips.md:{row.line_in_md}"
        if not row.sites:
            problems.append(
                f"{where}: File:line cell {row.file_line_cell!r} yields no parseable "
                f"`path:line` — an unlocatable row documents nothing and is invisible "
                f"to orphan/stale reconciliation"
            )
        if row.category_cell not in CATEGORIES:
            problems.append(
                f"{where}: category {row.category_cell!r} is not one of "
                f"{'/'.join(CATEGORIES)}"
            )
        if row.category_cell == "Gap" and not _ISSUE_RE.search(
            row.test_cell + " " + row.rationale_cell
        ):
            problems.append(
                f"{where}: Gap row references no tracker issue (`#<number>`) — a "
                f"deferred defect must name the item that owns it"
            )

    for category in CATEGORIES:
        actual = sum(1 for r in rows if r.category_cell == category)
        if category not in footers:
            if category in FOOTER_REQUIRED:
                problems.append(
                    f"docs/test-skips.md: no `### {category} skips` section — that "
                    f"section is mandatory and must state a count ({actual} row(s) "
                    f"in the table)"
                )
            continue
        stated, md_line = footers[category]
        if stated is None:
            problems.append(
                f"docs/test-skips.md:{md_line}: `### {category} skips` section states "
                f"no checkable count — open it with `None` or with a number"
            )
        elif stated != actual:
            problems.append(
                f"docs/test-skips.md:{md_line}: `### {category} skips` states {stated}, "
                f"but the table carries {actual} {category} row(s)"
            )

    return problems


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
    integrity = check_inventory_integrity(rows, parse_footer_counts(INVENTORY_PATH))

    # Reconciliation can only speak about rows that carry a location. Counting
    # the parseable subset separately is what makes the "physical rows ==
    # parsed rows" claim above checkable rather than assumed.
    located_rows = [r for r in rows if r.sites]

    # Match live skips to documented sites WITHOUT depending on exact line
    # numbers. A skip that merely MOVED (line drift) must not read as both an
    # orphan (its new line is undocumented) AND a stale row (its old line is
    # empty) — the failure mode that broke this gate repeatedly on unrelated
    # insertions. Per file: take exact-line matches first, then pair the
    # remainder by skip snippet with CONSUMPTION, so a genuinely ADDED skip
    # (unpaired live) is an orphan and a genuinely REMOVED skip (unpaired doc
    # site) is stale — line drift alone is forgiven (audit #15/#49).
    live_by_file: dict[str, list[SkipSite]] = {}
    for s in sites:
        live_by_file.setdefault(s.path, []).append(s)
    doc_by_file: dict[str, list[tuple[InventoryRow, int]]] = {}
    for row in located_rows:
        for path, line in row.sites:
            doc_by_file.setdefault(path, []).append((row, line))

    def snippet_matches_row(snippet: str, row: InventoryRow) -> bool:
        # A drifted skip keeps its message; pair it to a row that references it —
        # require >=2 distinctive tokens (len>=2, so short subjects like "SLH"/
        # "DSA" survive) of the skip snippet to appear in the row's cells so
        # unrelated messages don't cross-match. This only decides how a DRIFTED
        # (or added/removed) skip pairs to a row; exact-line matches are handled
        # first, and counts still catch genuine adds (orphan) / removes (stale).
        cell = row.test_cell + " " + row.rationale_cell
        toks = [t for t in re.split(r"[^A-Za-z0-9_+]+", snippet) if len(t) >= 2]
        hits = sum(1 for t in toks if t in cell)
        return hits >= 2 or (len(toks) == 1 and toks and toks[0] in cell)

    orphans: list[SkipSite] = []
    stales: list[tuple[InventoryRow, str, int]] = []
    for f in set(live_by_file) | set(doc_by_file):
        live = live_by_file.get(f, [])
        docs = doc_by_file.get(f, [])
        live_lines = {s.line for s in live}
        doc_lines = {line for _, line in docs}
        rem_live = [s for s in live if s.line not in doc_lines]  # drifted or added
        rem_docs = [(row, line) for row, line in docs if line not in live_lines]  # drifted or removed
        used = [False] * len(rem_docs)
        for s in rem_live:
            paired = False
            for i, (row, _line) in enumerate(rem_docs):
                if used[i] or not s.snippet:
                    continue
                if snippet_matches_row(s.snippet, row):
                    used[i] = True
                    paired = True
                    break
            if not paired:
                orphans.append(s)  # a live skip nothing documents = ADDED
        for i, (row, line) in enumerate(rem_docs):
            if not used[i]:
                stales.append((row, f, line))  # a doc site with no live skip = REMOVED

    orphans.sort(key=lambda s: (s.path, s.line))
    stales.sort(key=lambda t: (t[0].line_in_md, t[2]))

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

    if integrity:
        print("INVENTORY document contradicts itself:", file=sys.stderr)
        for p in integrity:
            print(f"  {p}", file=sys.stderr)
        rc |= 4

    if rc == 0:
        print(
            f"OK — {len(sites)} skip sites; {len(rows)} inventory rows "
            f"({len(located_rows)} located); every site documented, every row live, "
            f"table and footers agree."
        )
    return rc


# ---------------------------------------------------------------------------
# Self-test — RED proofs for the integrity gates
#
# A gate nobody has watched fail is indistinguishable from no gate. Each case
# below is a lie this script previously waved through; the assertion is that
# it now produces a problem. Run via `--self-test` (wired into
# scripts/lint-no-silent-skips.sh so CI exercises it on every push).
# ---------------------------------------------------------------------------


def _row(**kw) -> InventoryRow:
    base = dict(
        line_in_md=1,
        test_cell="`someTest`",
        file_line_cell="`a/b_test.go:10`",
        category_cell="Environmental",
        rationale_cell="reason",
        sites=(("a/b_test.go", 10),),
    )
    base.update(kw)
    return InventoryRow(**base)  # type: ignore[arg-type]


def self_test() -> int:
    ok_footers = {"Gap": (0, 100), "Stale": (0, 90)}
    cases: list[tuple[str, list[InventoryRow], dict, str]] = [
        (
            "row with no parseable file:line",
            [_row(file_line_cell="`a/b_test.go`", sites=())],
            ok_footers,
            "no parseable",
        ),
        (
            "category outside the closed set",
            [_row(category_cell="Deferred")],
            ok_footers,
            "not one of",
        ),
        (
            "Gap footer says None while the table carries a Gap row",
            [_row(category_cell="Gap", rationale_cell="blocked on #149")],
            ok_footers,
            "states 0, but the table carries 1",
        ),
        (
            "Gap row with no tracker issue",
            [_row(category_cell="Gap", rationale_cell="not implemented yet")],
            {"Gap": (1, 100), "Stale": (0, 90)},
            "references no tracker issue",
        ),
        (
            "mandatory Gap section missing entirely",
            [_row()],
            {"Stale": (0, 90)},
            "section is mandatory",
        ),
        (
            "Gap footer states an uncheckable count",
            [_row()],
            {"Gap": (None, 100), "Stale": (0, 90)},
            "no checkable count",
        ),
    ]

    failures: list[str] = []
    for name, rows, footers, expect in cases:
        problems = check_inventory_integrity(rows, footers)
        if not any(expect in p for p in problems):
            failures.append(f"{name}: expected a problem containing {expect!r}, got {problems}")

    # A clean document must stay silent, or every gate above is just noise.
    clean = check_inventory_integrity([_row()], ok_footers)
    if clean:
        failures.append(f"clean inventory reported problems: {clean}")

    # The generic JUnit annotation must be discoverable; only the
    # ...EnvironmentVariable / ...SystemProperty specialisations were before.
    java_pat = next(p for label, p in SKIP_PATTERNS if ".java" in label.split())
    for probe in ('@EnabledIf("repoLayoutAvailable")', "@DisabledIf(\"x\")"):
        if not java_pat.search(probe):
            failures.append(f"Java skip pattern does not match {probe!r}")

    for f in failures:
        print(f"SELF-TEST FAILED: {f}", file=sys.stderr)
    if failures:
        return 1
    print(f"OK — self-test: {len(cases)} integrity gates fire, clean input stays silent.")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(main())
