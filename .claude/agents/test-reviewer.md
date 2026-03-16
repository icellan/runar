# Task: Synchronize unit test coverage across all languages

## Context
This project implements the same logic in four languages: TypeScript, Go, Rust, and Python.
Each language should have equivalent unit test coverage. Some languages may have tests that
others are missing.

## Test runner commands
- TypeScript: `npm test`
- Go: `go test ./...`
- Rust: `cargo test`
- Python: `pytest`

## Critical rules
- NEVER skip, summarize, sample, or approximate. Every assertion matters.
- NEVER say "due to scale" or "for practical purposes" and then do less work.
  If a step feels too large, break it into smaller pieces. Do not reduce scope.
- If you run into context or output limits, process one module at a time and
  persist results to files. Do not use limits as a reason to do less.

## Step 1: Inventory existing tests

Process one module at a time. For each module in the project:

1. Find all test files for that module across all four languages
2. Read each test file completely
3. Extract every individual assertion. A single test function with a table of
   8 cases = 8 rows. A parametrize with 5 inputs = 5 rows.
4. Append results to `/tmp/test_inventory.md` in this format:

| Language | File | Function Under Test | Test Name | Assertion # | Behavior Asserted | Input | Expected Output |

Work through modules sequentially. After completing each module, write a
progress line: "Completed module X — Y assertions found."

After ALL modules are done, output a summary count:
- Total assertions per language
- Total unique behaviors across all languages

STOP here. Wait for my approval. Do NOT write any code yet.

## Step 2: Build canonical test list and gap report

Work from `/tmp/test_inventory.md`. Process one module at a time.

For each module, produce a gap table and append it to `/tmp/gap_report.md`:

| # | Module | Function | Behavior | Input → Expected | TS | Go | Rust | Python |
|---|--------|----------|----------|------------------|----|----|------|--------|

Number rows globally (not per module). Normalize equivalent behaviors that
may have different names across languages.

After ALL modules are processed, output a summary:
- Total canonical behaviors
- Gaps per language (count of ❌)

STOP here. Wait for my approval.

## Step 3: Implement missing tests

Spawn one sub-agent per language. Each sub-agent receives:
- The path to `/tmp/gap_report.md`
- Instructions to implement only the rows marked ❌ for its language

Each sub-agent must:

1. Read `/tmp/gap_report.md` and filter to its ❌ rows
2. Work through one module at a time
3. Write a test for EVERY ❌ row — no skipping, no batching multiple
   behaviors into one test. One canonical row = one test case.
4. After completing each module, run the full test suite
5. If any tests fail, diagnose:
    - (a) mistake in the test → fix it
    - (b) bug in the source code → leave the failing test, flag it for Step 5
6. After ALL modules are done, report:
    - Each canonical row number implemented
    - File and test name for each
    - Full suite pass/fail
    - Any rows flagged as potential source bugs

Each sub-agent must end its report with:
"Implemented X of Y assigned gaps. Rows not implemented: [list or 'none']."

If any rows are listed as not implemented, explain why for each one.

## Step 4: Verification (STOP after this step)

Re-inventory from scratch. Do NOT reuse the Step 1 inventory.

Re-read every test file again, one module at a time. Rebuild the gap report
and save to `/tmp/gap_report_v2.md`.

Compare `/tmp/gap_report_v2.md` against `/tmp/gap_report.md`:
- Every row that was ❌ should now be ✅
- No row that was ✅ should have become ❌

Also run all four test suites and report results:
npm test
go test ./...
cargo test
pytest

Produce a final status:
- Rows still showing ❌ (list each with row number and reason)
- Test suite pass/fail per language
- Count of regressions (rows that went from ✅ to ❌)

STOP here. Wait for my approval.
If gaps remain, I will ask you to repeat Steps 3–4 for the remaining gaps.

## Step 5: Bug report (STOP after this step)

If any new test fails because the source code produces a wrong result — not
because the test itself is wrong — check whether the equivalent test PASSES
in at least two other languages.

If it does, this confirms a bug in the failing language's implementation.

Produce a bug report:

| Language | Function | Canonical Row # | Expected (from passing languages) | Actual | Confirmed by |
|----------|----------|-----------------|-----------------------------------|--------|--------------|
| Python   | encode() | 7               | "0x1a"                            | "0x1A" | TS ✅ Go ✅   |

STOP here. Wait for my approval before modifying any source code.

## Step 6: Fix confirmed bugs

For each approved bug:
1. Fix the source code in the affected language
2. Re-run that language's FULL test suite — confirm fix and no regressions
3. Report: what changed, before/after behavior, full suite pass/fail

## Definition of done

The task is complete when:
- Step 4 verification shows ✅ for every row in every language
- All four test runner commands exit 0
- No existing tests were broken or removed
- Any source code changes are limited to confirmed bugs (approved in Step 5)

## Constraints
- Do not modify source code UNLESS a bug is confirmed by passing tests in at
  least two other languages AND approved in Step 5
- Do not add new dependencies unless absolutely necessary (and flag it if you do)
- Match the code style and conventions already present in each language's test files
- One test per canonical behavior — do not combine multiple behaviors into one test
- If a behavior cannot be tested in a particular language (e.g., language-specific
  feature), note it in the report rather than forcing it
- NEVER reduce scope due to scale. Break into smaller pieces instead.
- ALWAYS persist intermediate results to files rather than holding everything in context.