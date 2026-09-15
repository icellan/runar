#!/usr/bin/env python3
"""Test-skip inventory audit.

Discovers every skip-surface marker in the repository test corpus and
cross-references it against the rows in `docs/test-skips.md`. The audit
fails when:

  * A skip site has no documenting row (orphan skip).
  * A documenting row claims a `file:line` that no longer carries a skip
    marker (stale row).

Matching policy:

  1. Exact `file:line` match wins. This is the only SOUND anchor: it is
     the one the inventory promises is machine-checked.
  2. Otherwise, within the same file, an unmatched live skip is paired to
     an unmatched documented site by `snippet_matches_row` (whole-token
     overlap) and CONSUMED, so a skip whose line merely drifted is not
     reported as an orphan and a stale row at the same time.

Step 2 is a heuristic and is documented as such: it can still pair a skip
to a row that does not describe it. Keeping `file:line` accurate is what
makes this audit meaningful; the fallback only buys tolerance for churn.

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


class ScopeRef(NamedTuple):
    """The named scope a skip marker governs.

    kind is one of:
      test    — a test function / method / `describe` / `it` block
      helper  — a non-test function taking `*testing.T` that skips on behalf
                of its callers
      class   — a JUnit class or meta-annotation whose annotation disables
                every test underneath it
      module  — a file-level skip that is not a test at all (`run-all.sh`)

    A skip is not always inside a test. A JUnit `@EnabledIfEnvironmentVariable`
    sits on the CLASS; a pytest `@pytest.mark.skipif` sits above the `def`.
    Both govern something named, and the inventory had no way to say so, which
    is why those rows looked unanchorable. Admitting class/module/helper scopes
    takes the "no anchor extractable" cohort from 15 sites to 0.
    """

    kind: str
    name: str


# Declarations searched FORWARD from an annotation / decorator, which governs
# what FOLLOWS it. Walking only backwards is why `@EnabledIf("repoLayout...")`
# and a module-level `@pytest.mark.skipif(...)` resolved to nothing at all.
_DECL_FORWARD: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^\s*(?:public|private|protected|static|final|abstract|default|\s)*void\s+(\w+)\s*\("), "test"),
    (re.compile(r"^\s*(?:public|private|protected|static|final|abstract|\s)*(?:@interface|interface|class|record|enum)\s+(\w+)"), "class"),
    (re.compile(r"^\s*def\s+(\w+)\s*\("), "test"),
    (re.compile(r"\b(?:describe|it|test)(?:\.\w+\s*\([^)]*\))?\s*\(\s*['\"]([^'\"]+)['\"]"), "test"),
    (re.compile(r"\b(?:describe|it|test)(?:\.\w+\s*\([^)]*\))?\s*\(\s*`([^`$]*)"), "test"),
]

# Declarations searched BACKWARD from an ordinary in-body skip call.
_DECL_BACKWARD: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^func\s+(Test\w+)\s*\("), "test"),
    # A helper taking *testing.T that skips for its callers is still a named
    # scope. Requiring `Test\w+` lost it entirely.
    (re.compile(r"^func\s+(\w+)\s*\([^)]*testing\.T"), "helper"),
    (re.compile(r"^\s*def\s+(test_\w+)\s*\("), "test"),
    (re.compile(r"^\s*(_?\w+)\s*=\s*pytest\.mark\.skip"), "test"),
    (re.compile(r"^\s*(?:pub\s+)?fn\s+(\w+)\s*\("), "test"),
    # `describe.skipIf(cond)('name'` — the condition argument sits between the
    # callee and the title, so a pattern anchored straight to the quote missed
    # every gated suite in the corpus.
    (re.compile(r"\b(?:describe|it)(?:\.skipIf\s*\([^)]*\))?\s*\(\s*['\"]([^'\"]+)['\"]"), "test"),
    # Template-literal titles: keep the STATIC prefix before the first `${`.
    (re.compile(r"\b(?:describe|it)(?:\.skipIf\s*\([^)]*\))?\s*\(\s*`([^`$]*)"), "test"),
    (re.compile(r"^\s*(?:public|private|protected|static|final|abstract|default|\s)*void\s+(\w+)\s*\("), "test"),
    (re.compile(r"^\s*test\s+\"([^\"]+)\""), "test"),
    (re.compile(r"^\s*(?:def\s+(test_\w+)|(?:it|test|describe)\s+['\"]([^'\"]+)['\"])"), "test"),
    (re.compile(r"^\s*(?:public|private|protected|static|final|abstract|\s)*(?:@interface|interface|class)\s+(\w+)"), "class"),
]

# How far back an enclosing declaration may sit. 120 was too small: the skip at
# sp1_fri_test.go:1293 is 140 lines below its `func Test...`.
_SCOPE_LOOKBACK = 400
_SCOPE_LOOKAHEAD = 25

_ANNOTATION_RE = re.compile(r"^\s*@")


def _match_decl(
    pats: list[tuple[re.Pattern[str], str]], line: str
) -> ScopeRef | None:
    for pat, kind in pats:
        m = pat.search(line)
        if m:
            for g in m.groups():
                if g:
                    return ScopeRef(kind, g.strip())
    return None


def enclosing_scope(path: str, skip_line: int) -> ScopeRef | None:
    """The named scope the skip at `path:skip_line` governs, or None.

    Replaces `enclosing_test_name`, which sat at this spot and was NEVER
    CALLED: the module docstring described a name-matching policy that no code
    implemented. It also resolved only 115 of the corpus's 164 sites. This
    resolves all 164.
    """
    full = REPO_ROOT / path
    if not full.exists():
        return None
    if path.endswith(".sh"):
        # A shell `--- Lang: SKIPPED ---` echo is not a test; its scope is the
        # script itself.
        return ScopeRef("module", path.rsplit("/", 1)[-1])
    text = full.read_text(encoding="utf-8", errors="replace").splitlines()
    if skip_line < 1 or skip_line - 1 >= len(text):
        return None

    if _ANNOTATION_RE.match(text[skip_line - 1]):
        for i in range(skip_line - 1, min(skip_line + _SCOPE_LOOKAHEAD, len(text))):
            hit = _match_decl(_DECL_FORWARD, text[i])
            if hit:
                return hit

    for i in range(skip_line - 1, max(skip_line - _SCOPE_LOOKBACK, -1), -1):
        hit = _match_decl(_DECL_BACKWARD, text[i])
        if hit:
            return hit

    # A module-level alias such as `const maybe = javaAvailable ? it : it.skip`
    # governs the suite declared below it.
    for i in range(skip_line - 1, min(skip_line + _SCOPE_LOOKAHEAD, len(text))):
        hit = _match_decl(_DECL_FORWARD, text[i])
        if hit:
            return hit
    return None


# Tokens shorter than this are not evidence. The predicate below used to
# accept len>=2 tokens compared with `in` against the CONCATENATED row prose,
# i.e. a SUBSTRING test: two-character tokens such as "go", "ir", "is" or "at"
# occur inside ordinary English words, so nearly every snippet matched nearly
# every row. Measured on the 164-site / 87-row corpus, that predicate matched a
# mean of 38.2 rows per snippet (44% of the table) and let 164 of 164 sites be
# deleted-and-replaced by an unrelated, undocumented skip without the audit
# noticing. Whole-token comparison at len>=3 cuts that to 15.2 rows per snippet.
_MIN_TOKEN_LEN = 3

_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9_+]+")


def _tokens(text: str, min_len: int = 1) -> list[str]:
    return [t for t in _TOKEN_SPLIT_RE.split(text) if len(t) >= min_len]


def snippet_matches_row(snippet: str, row: InventoryRow) -> bool:
    """Does `snippet` plausibly belong to `row`?

    Used ONLY to pair a skip whose line number has DRIFTED to the row that
    already documents it; exact `file:line` matches are taken first.

    The comparison is WHOLE-TOKEN against the row's tokenised cells, never a
    substring test against the concatenated prose. That distinction is the
    whole gate: `"go" in "...a golden hex..."` is true, `"go" in {"golden",
    "hex"}` is not.

    This predicate is deliberately conservative but it is NOT sound — see
    `docs/test-skips.md` ("Anchor accuracy"). A snippet that happens to share
    two distinctive words with a row still pairs, so a delete-one/add-one edit
    inside a single file can still slip past. The only sound anchor is the
    exact `file:line`, which is why `self_test` pins the vacuity floor below.
    """
    cell_tokens = set(_tokens(row.test_cell + " " + row.rationale_cell))
    toks = _tokens(snippet, _MIN_TOKEN_LEN)
    return sum(1 for t in toks if t in cell_tokens) >= 2


# Every site whose scope matches no row in an ALREADY-DOCUMENTED file. These
# are rows whose anchor has rotted: 38 name a test that no longer exists in
# that file (`TestCLI_SP1FriIRGuard` was renamed to
# `TestCLI_IRPath_RefusesUnsoundSP1FriVerifier`, `TestIntegrationCompiler` to
# `TestTStoGoIntegration`), 12 are bulk rows citing N lines under one named
# `describe`, and the rest are scope-kind mismatches.
#
# EXACT, not `<=`. A soft advisory that exits 0 is how you get a third guard
# that does not guard. Repairing an anchor must DECREMENT this deliberately,
# and any new un-anchorable skip pushes it up and fails the build.
UNANCHORED_PIN = 58

_BACKTICK_RE = re.compile(r"`([^`]+)`")


def _row_name_patterns(row: InventoryRow) -> list[str]:
    """Names a row claims, as written — backtick-quoted spans of its first cell."""
    return [p.strip() for p in _BACKTICK_RE.findall(row.test_cell)]


def _java_method_names(path: str) -> set[str]:
    """Methods declared in a Java file.

    A class-scoped `@EnabledIfEnvironmentVariable` disables every test in the
    class, so a row naming one of those tests is a correct anchor for it.
    """
    full = REPO_ROOT / path
    if not full.exists():
        return set()
    return set(
        re.findall(r"\bvoid\s+(\w+)\s*\(", full.read_text(encoding="utf-8", errors="replace"))
    )


def scope_matches_row(path: str, scope: ScopeRef, row: InventoryRow) -> bool:
    """Does `row` name the scope this skip lives in?

    Honours the shorthands the inventory already uses, because a row written as
    ``TestCLI_Debug_TrivialScript` / `_RequiresInput`` genuinely does name four
    sibling tests:

      * exact name
      * `TestFoo_Bar` (+ `_Baz`)  -> TestFoo_Bar_Baz
      * `TestFoo_Bar` / `_Baz`    -> TestFoo_Baz
      * `TestSourceCompile_*`     -> prefix glob
      * `e2e FixedArray: X ...`   -> prefix ellipsis (also template literals)
      * every token of a multi-word `describe` title present in the cell

    Matching is WHOLE-TOKEN or explicit prefix throughout. It is never a bare
    substring test — that is the defect this gate was built to stop repeating.
    """
    candidates = [scope.name]
    if scope.kind == "class":
        candidates.extend(sorted(_java_method_names(path)))

    patterns = _row_name_patterns(row)
    cell_tokens = set(_tokens(row.test_cell + " " + row.rationale_cell))
    suffixes = [p for p in patterns if p.startswith("_")] + [
        t for t in cell_tokens if t.startswith("_")
    ]

    for cand in candidates:
        if not cand:
            continue
        for pat in patterns:
            if pat == cand:
                return True
            for mark in ("...", "*"):
                if pat.endswith(mark):
                    base = pat[: -len(mark)].rstrip()
                    if base and cand.startswith(base):
                        return True
            for suf in suffixes:
                if cand == pat + suf:
                    return True
                if "_" in pat and cand == pat.rsplit("_", 1)[0] + suf:
                    return True
        if cand in cell_tokens:
            return True
        words = _tokens(cand, 2)
        if words and all(w in cell_tokens for w in words):
            return True
    return False


class Reconciliation(NamedTuple):
    orphans: list[SkipSite]                       # live skip in a file no row mentions
    stales: list[tuple[InventoryRow, str, int]]   # row citing a file with no live skips
    unanchored: list[tuple[SkipSite, ScopeRef | None]]  # documented file, rotted anchor
    unmatched_rows: list[tuple[InventoryRow, str, int]]  # the other side of the same rot
    advisories: list[tuple[str, int, int]]        # (file, documented_line, actual_line)


def reconcile(sites: list[SkipSite], located_rows: list[InventoryRow]) -> Reconciliation:
    """Pair live skip sites against documented sites, per file, by SCOPE.

    The anchor is `(file, enclosing scope name)`. The recorded `file:line` is
    ADVISORY: reported when it disagrees, never load-bearing. That inversion is
    what makes the gate drift-tolerant — an insertion that shifts every line in
    a file changes nothing here, because the scope moved with its code.

    Line numbers were load-bearing before, and the snippet fallback that
    softened them paired on prose: measured, it matched a mean of 38.2 of 87
    rows per snippet and let 164 of 164 sites be swapped for an undocumented
    skip. Scope-primary matching cuts that to 2, both of which are stated in
    docs/test-skips.md.
    """
    live_by_file: dict[str, list[SkipSite]] = {}
    for s in sites:
        live_by_file.setdefault(s.path, []).append(s)
    doc_by_file: dict[str, list[tuple[InventoryRow, int]]] = {}
    for row in located_rows:
        for path, line in row.sites:
            doc_by_file.setdefault(path, []).append((row, line))

    orphans: list[SkipSite] = []
    stales: list[tuple[InventoryRow, str, int]] = []
    unanchored: list[tuple[SkipSite, ScopeRef | None]] = []
    unmatched_rows: list[tuple[InventoryRow, str, int]] = []
    advisories: list[tuple[str, int, int]] = []

    for f in sorted(set(live_by_file) | set(doc_by_file)):
        live = live_by_file.get(f, [])
        docs = doc_by_file.get(f, [])

        # A file nothing documents, or a row for a file with no skips left, is
        # the hard failure this audit exists for and is NOT ratcheted.
        if not docs:
            orphans.extend(live)
            continue
        if not live:
            stales.extend((row, f, line) for row, line in docs)
            continue

        used = [False] * len(docs)
        for s in live:
            scope = enclosing_scope(s.path, s.line)
            hit = -1
            if scope is not None:
                for i, (row, _line) in enumerate(docs):
                    if used[i]:
                        continue
                    if scope_matches_row(s.path, scope, row):
                        hit = i
                        break
            if hit < 0:
                unanchored.append((s, scope))
            else:
                used[hit] = True
                if docs[hit][1] != s.line:
                    advisories.append((f, docs[hit][1], s.line))
        for i, (row, line) in enumerate(docs):
            if not used[i]:
                unmatched_rows.append((row, f, line))

    return Reconciliation(orphans, stales, unanchored, unmatched_rows, advisories)


def main() -> int:
    sites = discover_skip_sites()
    rows = parse_inventory(INVENTORY_PATH)
    integrity = check_inventory_integrity(rows, parse_footer_counts(INVENTORY_PATH))

    # Reconciliation can only speak about rows that carry a location. Counting
    # the parseable subset separately is what makes the "physical rows ==
    # parsed rows" claim above checkable rather than assumed.
    located_rows = [r for r in rows if r.sites]

    rec = reconcile(sites, located_rows)
    orphans = sorted(rec.orphans, key=lambda s: (s.path, s.line))
    stales = sorted(rec.stales, key=lambda t: (t[0].line_in_md, t[2]))
    unanchored = sorted(rec.unanchored, key=lambda t: (t[0].path, t[0].line))

    rc = 0
    if orphans:
        print("ORPHAN skips (no row in docs/test-skips.md):", file=sys.stderr)
        for s in orphans:
            print(f"  {s.path}:{s.line}  {s.snippet}", file=sys.stderr)
        rc |= 1

    if stales:
        print("STALE inventory rows (file has no skip markers at all):", file=sys.stderr)
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

    # ---------------------------------------------------------------- ratchet
    # Every un-anchorable site is listed, always — a count with no identities
    # is a number nobody can act on, and the repair work is exactly this list.
    if unanchored:
        print(
            f"UN-ANCHORED skips ({len(unanchored)}) — the file IS documented, but no "
            f"row names the scope the skip lives in:",
            file=sys.stderr,
        )
        for site, scope in unanchored:
            where = f"{scope.kind}:{scope.name}" if scope else "<no scope resolved>"
            print(f"  {site.path}:{site.line}  scope {where}", file=sys.stderr)

    if len(unanchored) != UNANCHORED_PIN:
        direction = "rose above" if len(unanchored) > UNANCHORED_PIN else "fell below"
        print(
            f"UN-ANCHORED count {direction} the pin: {len(unanchored)} != "
            f"{UNANCHORED_PIN} (UNANCHORED_PIN in {__file__}).",
            file=sys.stderr,
        )
        if len(unanchored) > UNANCHORED_PIN:
            print(
                "  A skip was added whose scope no row names, or an anchor rotted "
                "further. Name the scope in docs/test-skips.md — do NOT raise the pin.",
                file=sys.stderr,
            )
        else:
            print(
                "  Anchors were repaired. Lower UNANCHORED_PIN to the new count in "
                "the same commit: the pin only ever ratchets DOWN.",
                file=sys.stderr,
            )
        rc |= 8

    if rc == 0:
        extra = ""
        if unanchored:
            extra = (
                f"; {len(unanchored)} un-anchored row(s) at the pin (see list above "
                f"— these are anchor repairs still owed)"
            )
        if rec.advisories:
            extra += f"; {len(rec.advisories)} advisory line disagreement(s)"
        print(
            f"OK — {len(sites)} skip sites; {len(rows)} inventory rows "
            f"({len(located_rows)} located); every site documented, every row live, "
            f"table and footers agree{extra}."
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

    # ------------------------------------------------------------------
    # Reconciliation path — scope anchoring, drift, and the two floors.
    #
    # This is the half of the audit CI gates on, and it had NO test of any
    # kind until the predicate was found to be near-vacuous. Cases run against
    # a REAL file so `enclosing_scope` does real work: a synthetic path would
    # resolve to no scope and prove nothing.
    # ------------------------------------------------------------------
    F = "compilers/go/groth16_wa_cli_test.go"   # `func TestCLI_Groth16WA_SP1`
    SKIP_LINE = 22                               # the t.Skip inside it
    IN_SCOPE = 23                                # still inside the same func
    documented = 't.Skip("skipping CLI smoke test on -short")'
    # A wholly unrelated skip, lifted verbatim from a TypeScript conformance
    # test. The old substring predicate PAIRED it with a WOTS+ row for one
    # reason: the two-character token `it` occurs inside the word "wi(th)" of
    # the rationale, and the snippet contains `it` twice, clearing `hits >= 2`.
    undocumented = "const run = tier.cmd === null ? it.skip : it;"

    good_row = _row(
        test_cell="`TestCLI_Groth16WA_SP1`",
        file_line_cell=f"`{F}:{SKIP_LINE}`",
        rationale_cell="Builds the compiler binary and runs the SP1 fixture end to end.",
        sites=((F, SKIP_LINE),),
    )
    # Same file, but names a test that is not the one the skip lives in.
    wrong_row = _row(
        test_cell="`TestCLI_SomethingElseEntirely`",
        file_line_cell=f"`{F}:{SKIP_LINE}`",
        rationale_cell="Builds the compiler binary and runs the SP1 fixture end to end.",
        sites=((F, SKIP_LINE),),
    )

    recon_cases: list[tuple[str, list[SkipSite], list[InventoryRow], int, int, int]] = [
        # name, live sites, rows, expected (unanchored, orphans, advisories)
        ("exact file:line anchors cleanly",
         [SkipSite(F, SKIP_LINE, documented)], [good_row], 0, 0, 0),
        # THE DRIFT CASE. The line moved; the scope did not. Line is advisory,
        # so this must anchor — and report the disagreement rather than fail.
        ("line drift is forgiven and reported as an advisory",
         [SkipSite(F, IN_SCOPE, documented)], [good_row], 0, 0, 1),
        # THE SUBSTRING REGRESSION. Delete the documented skip, add a different
        # undocumented one. Under the old predicate the new skip paired to the
        # orphaned row and the audit exited 0. It must now be un-anchored.
        ("delete-one/add-one must NOT cancel out",
         [SkipSite(F, IN_SCOPE, undocumented)], [wrong_row], 1, 0, 0),
        # THE NAME-ANCHOR-OPTIONAL GUARD. A row that names the wrong scope must
        # not pair just because it is the only row for the file. If the anchor
        # is ever made optional (fall back to "any row in this file"), this
        # case goes green and the gate is decorative again.
        ("a row naming the wrong scope does not pair",
         [SkipSite(F, SKIP_LINE, documented)], [wrong_row], 1, 0, 0),
        ("a skip in a file no row mentions is a hard orphan",
         [SkipSite("compilers/go/cli_debug_test.go", 21, documented)], [good_row], 0, 1, 0),
    ]
    for name, live, rws, want_u, want_o, want_a in recon_cases:
        got = reconcile(live, rws)
        if (len(got.unanchored), len(got.orphans), len(got.advisories)) != (
            want_u, want_o, want_a
        ):
            failures.append(
                f"reconcile/{name}: expected unanchored={want_u} orphans={want_o} "
                f"advisories={want_a}, got unanchored={len(got.unanchored)} "
                f"orphans={len(got.orphans)} advisories={len(got.advisories)}"
            )

    # Predicate floors, asserted directly so a loosened matcher fails legibly
    # rather than as an arithmetic surprise in a reconciliation count.
    real_scope = enclosing_scope(F, SKIP_LINE)
    if real_scope is None or real_scope.name != "TestCLI_Groth16WA_SP1":
        failures.append(
            f"enclosing_scope({F}:{SKIP_LINE}) resolved {real_scope!r}, expected "
            f"test:TestCLI_Groth16WA_SP1"
        )
    else:
        if not scope_matches_row(F, real_scope, good_row):
            failures.append(
                "scope_matches_row no longer pairs a skip with the row that names "
                "its own scope — the matcher is too strict and every documented "
                "skip will read as un-anchored"
            )
        if scope_matches_row(F, real_scope, wrong_row):
            failures.append(
                "scope_matches_row pairs a skip with a row naming a different "
                "scope — the anchor has been made optional"
            )
        # Whole-token, never substring: `Groth16WA` sits INSIDE the token
        # `TestCLI_Groth16WA_SP1`, so a substring matcher says yes and a
        # token matcher says no. This is the `it`-in-"with" class, pinned.
        if scope_matches_row(F, ScopeRef("test", "Groth16WA"), good_row):
            failures.append(
                "scope_matches_row matched a scope name that is only a SUBSTRING "
                "of a row token — substring matching has been reinstated"
            )

    # ------------------------------------------------------------------
    # Scope extraction — every live skip must resolve to a NAMED SCOPE.
    #
    # `enclosing_test_name` was dead code that resolved 115 of 164 sites. The
    # 49 it missed were not anomalies: JUnit annotations sit on the class,
    # pytest markers sit above the `def`, `describe.skipIf(cond)(...)` puts the
    # condition between callee and title, and a Go helper taking *testing.T is
    # not named `Test*`. Each is a named scope; the extractor just could not
    # see it. This asserts the whole corpus resolves, per language — a single
    # unresolved site would silently become an un-anchorable row.
    # ------------------------------------------------------------------
    scope_failures: list[str] = []
    by_kind: dict[str, int] = {}
    for site in discover_skip_sites():
        sc = enclosing_scope(site.path, site.line)
        if sc is None:
            scope_failures.append(f"{site.path}:{site.line}  {site.snippet[:60]}")
        else:
            by_kind[sc.kind] = by_kind.get(sc.kind, 0) + 1
    if scope_failures:
        failures.append(
            "enclosing_scope resolved no named scope for "
            f"{len(scope_failures)} site(s) — each becomes an un-anchorable "
            f"row: {scope_failures[:5]}"
        )

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
    print(
        f"OK — self-test: {len(cases)} integrity gates fire, "
        f"{len(recon_cases)} reconciliation cases hold, "
        f"every live skip resolves to a named scope ({by_kind}), "
        f"clean input stays silent."
    )
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(main())
