# GAP-008 — Bitcoin Script Analyzer port: follow-ups

These items were discovered while porting the analyzer from TS to six other
tiers. They do NOT block the GAP-008 work (the spec faithfully reproduces TS
reference behavior, including quirks, so the cross-tier goldens stay
byte-identical), but they SHOULD be addressed in dedicated follow-up issues.

## 1. `PATHS_TRUNCATED` message arithmetic — 32-bit shift overflow — RESOLVED (spec v1.2)

**Status:** Fixed in spec v1.2 (2026-05-28). All 7 tiers updated;
goldens regenerated; conformance 56/56.

The PATHS_TRUNCATED message now renders the count as
`Script has <N> branch points (2^<N> = <X> paths)` for `numBranches < 53`
(exact decimal) and `Script has <N> branch points (more than 2^53 paths)`
for `numBranches >= 53`. The path-enumeration loop bound is
`min(2^numBranches, MAX_PATHS)` computed in 64-bit arithmetic, so the
truncation finding now fires whenever there are truly more than 256
paths (previously skipped for `numBranches & 31 < 9 && numBranches >= 32`
due to JS 5-bit shift mask). The per-path `choices[b]` extraction now
clamps `b < 31` to avoid JS / Java shift-mask aliasing.

Spec sections updated: §5.1, §7.2, §15. Goldens for `ec-demo` and
`schnorr-zkp` changed (the latter went from 4 paths to 256 paths +
PATHS_TRUNCATED added).

## 2. `MAX_PATHS = 256` may be too small — DEFERRED

**Status:** Deferred. Aesthetic tuning (not a correctness bug). Bumping
the cap to 4096/8192 would inflate goldens roughly linearly with
`numBranches`; cross-tier coordination cost is real but not urgent.
Revisit in a dedicated spec bump.

In the TS reference, the cap is 256. `ec-demo` enumerates exactly 256 of
its >> 2^53 spending paths — almost certainly hiding analysis-relevant
behavior. The conformance gate is byte-identical output, so this cap is
locked in by goldens; but the cap could reasonably be raised to e.g. 4096
once the goldens are regenerated. Stack-Overflow risk: each path's
description string grows with `numBranches`, so for `numBranches >= 32`
the per-path description is ~30 KB — bumping `MAX_PATHS` to 4096 would
inflate goldens roughly linearly.

## 3. `LARGE_SCRIPT` threshold (500_000 bytes) — DEFERRED

**Status:** Deferred. None of the 8 canonical fixtures triggers this
finding, so the threshold has no observable effect on the goldens.
Aesthetic only. Raising to ~5 MB for BSV reality is reasonable, but
requires cross-tier coordination and an updated unit test for each tier
(currently every tier hardcodes `500_001` bytes as a unit-test trigger).

The threshold is hardcoded and chosen for traditional Bitcoin. For BSV
(which Rúnar targets) scripts up to several MB are routinely deployed;
500 KB is no longer a meaningful red flag. Consider raising to e.g. 4 MB
or removing the finding entirely. (None of the 8 canonical fixtures
exercises this finding — `ec-demo` and `schnorr-zkp` are larger than
500 KB but the analyzer treats hex-string length as bytes, which is
off by a factor of 2 — see follow-up 4.)

## 4. `scriptSizeBytes` is computed as `normalizedHex.length / 2`

This is correct. However the path-description and many other fields use
the *opcode offset* in script bytes, while the `LARGE_SCRIPT` threshold
compares against the same `scriptSizeBytes`. The threshold of 500_000
bytes is in **script bytes** (not hex characters), so the comparison is
correct. Noting here only to flag that any future change to the threshold
semantics should be cross-tier-coordinated.

## 5. `sortFindings` second key is `offset ?? Infinity`

This is well-defined in JS but each tier needs to map `Infinity` to its
language's sort key. The spec explicitly states "offset-less findings
sort to the end within their severity bucket"; per-tier implementers
should use either:
- a large sentinel int (e.g. `Int.MAX`) AND check for it correctly,
- or a key-extractor that returns `Option<int>` with `None > Some(n)`.

Not a bug; just a pitfall called out so non-TS tiers don't all
reimplement it differently.

## 6. `UNREACHABLE_AFTER_RETURN` only fires in the linear-fallback path

The path-analyzer's per-path linear analysis also walks opcodes and
emits `UNREACHABLE_AFTER_RETURN`, but only for opcodes that appear
in the *per-path* collected list, after an `OP_RETURN`. None of the 8
fixtures have an `OP_RETURN` followed by more opcodes inside a single
branch, so this case is untested in the conformance goldens.

## 7. `CHECKSIG_RESULT_DROPPED` is intentionally scoped to direct OP_DROP

Other patterns like `OP_CHECKSIG OP_TOALTSTACK OP_DROP` or `OP_CHECKSIG
OP_NIP` are not flagged. This is a deliberate scope limit (low
false-positive rate) but worth documenting. None of the fixtures
exercise the finding.

## 8. Synthetic `RAW_SPAN` opcode (id = -1) unused by the 8 fixtures

`collapseRawScriptSpans` is fully implemented and tier-tested but none
of the 8 canonical fixtures pass `rawScriptSpans`. Tier ports must
still implement and unit-test the collapse algorithm, but cross-tier
byte parity for this feature is not verified by the conformance suite.
Worth adding a 9th tiny fixture that exercises raw_script (e.g.
`asm-raw-script`) once the 7th tier ports land.
