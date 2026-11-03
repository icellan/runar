/**
 * GAP-002 / audit finding #22 — independent source-anchor oracle.
 *
 * `run.ts`'s existing checks (byte-identity vs the committed golden, plus
 * `checkStructural`'s shape/ordering/bounds invariants) are both derived
 * from — or graded purely against the *shape* of — the source-map
 * generator's own output. A generator that consistently emits a WRONG
 * (line, column) for a given opcode passes both checks forever, because:
 *
 *   - the golden was produced by the same generator (`--update`), so
 *     byte-identity always matches;
 *   - `checkStructural` only inspects the mapping table's internal shape
 *     (sorted, in-range, non-empty `sourceFile`, etc.) — it never opens the
 *     source file the mapping claims to point at.
 *
 * This module closes that gap. `checkSourceAnchors` derives "correct" from
 * the ACTUAL SOURCE TEXT on disk, not from the generator's own output: for
 * every mapping it re-reads the real `.runar.*` file (a plain filesystem
 * read, independent of any compiler pass) and verifies the claimed
 * (line, column) lands on a real, in-bounds, non-whitespace, non-comment
 * character that does not split an identifier/keyword token in half. A
 * mapping can satisfy every existing structural invariant and still fail
 * this check — e.g. pointing one character into the middle of `assert(...)`
 * instead of at its start, or past the end of the file, or into a blank
 * line. None of those are expressible as "does this equal the golden" or
 * "is this table well-formed" — they require the source file as a second,
 * independent witness.
 *
 * `checkSourceAnchors` intentionally does NOT re-implement statement-level
 * position derivation (i.e. it does not try to independently recompute
 * "the start of the AST node that produced opcode N") — that would still be
 * coupled to a particular parser's notion of node boundaries. Instead it
 * checks the weaker, but fully generator-independent, necessary condition
 * that must hold for ANY correct mapping regardless of tier-specific
 * granularity: the claimed position must be a plausible token anchor in the
 * real source text. This is deliberately conservative (see "Residual
 * limitations" in README.md) but it is unconditionally sound — it never
 * consults the source-map generator, the golden, or any Rúnar compiler
 * pass, only `fs.readFileSync` + the mapping under test.
 *
 * F-293 — WHOLE-MAP check (`checkAgainstReference`). Every check above is
 * per-mapping, so N identical valid positions pass exactly as well as one:
 * Rust's `if-else` golden maps 17 consecutive opcodes spanning both branch
 * bodies onto the single line of the enclosing `if`, and Zig's
 * `stateful-counter` maps ~420 compiler-injected preamble opcodes onto one
 * method-signature anchor, and neither trips a per-mapping rule. The rule
 * below is relative to the TypeScript tier, which README.md designates the
 * reference, and rests on one fact: hex parity (CLAUDE.md invariant 2) makes
 * opcode N the SAME opcode, produced by the SAME source construct, in every
 * tier. Coordinates differ per surface syntax, so they are never compared;
 * only the PARTITION of opcodes into anchors is:
 *
 *   1. mergedAnchors -- no merging. Two opcodes both tiers map and that the
 *      reference anchors to different constructs must not share one anchor
 *      in the tier (an anchor that is not the innermost construct that
 *      produced the opcode swallows its children). Counted as, per tier
 *      anchor, (distinct reference anchors it covers - 1), summed. Splitting
 *      (tier finer than reference) is allowed: granularity is tier-chosen.
 *   2. extraMappings -- no invention. An opcode the reference leaves
 *      unmapped is, by README ("tiers may omit a mapping for ops the
 *      lowering pass had no sourceLoc for"), compiler-synthesized; mapping
 *      it onto a user line misattributes generated code (this is what turns
 *      a ~10 mapping table into 400+). Counted as opcodes mapped by the tier
 *      and not by the reference.
 *
 * Neither rule is a density ratio: both are exact, tier-independent, and
 * pinned per (fixture, tier) in anchor-known-issues.json. Residual: the
 * reference is trusted (it cannot flag itself); its correctness rests on
 * the per-mapping rules and on review of the committed TS goldens.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface SourceMapping {
  opcodeIndex: number;
  sourceFile: string;
  line: number;
  column: number;
}

export interface SourceMap {
  mappings: SourceMapping[];
}

export type AnchorViolationKind =
  | 'source-file-missing'
  | 'line-out-of-bounds'
  | 'column-out-of-bounds'
  | 'points-at-whitespace'
  | 'points-inside-comment'
  | 'splits-token';

export interface AnchorViolation {
  opcodeIndex: number;
  kind: AnchorViolationKind;
  detail: string;
}

export interface AnchorReport {
  /** No violations AND at least one mapping was independently verifiable. */
  ok: boolean;
  violations: AnchorViolation[];
  /** Mappings with line > 0 that were checked against the real source text. */
  trackedCount: number;
  /** Mappings with line === 0 — treated as "position not tracked" (mirrors
   *  the pre-existing structural carve-out for the Java tier's untracked
   *  surface forms; see README.md "Known gap: Java"). Not anchor-checked
   *  because there is no claimed position to verify. */
  untrackedCount: number;
  totalCount: number;
}

const WORD_CHAR = /[A-Za-z0-9_]/;
const WHITESPACE = /\s/;

// Per-extension line-comment marker. Only formats actually present in the
// source-map fixtures are listed; unknown extensions skip the
// inside-a-comment check rather than risk a false positive.
const LINE_COMMENT_MARKER: Record<string, string> = {
  '.ts': '//',
  '.go': '//',
  '.rs': '//',
  '.zig': '//',
  '.java': '//',
  '.py': '#',
  '.rb': '#',
};

function extOf(sourceFile: string): string {
  const dot = sourceFile.lastIndexOf('.');
  // Handle the compound `.runar.ts` style suffix by matching the final
  // extension segment, which is what determines comment syntax.
  return dot === -1 ? '' : sourceFile.slice(dot);
}

/**
 * Index of the start of a same-line comment, or -1 if none. Tracks simple
 * single/double/backtick string state so a marker character inside a
 * string literal isn't mistaken for a comment start. Deliberately simple —
 * good enough for the small, hand-written contract fixtures this oracle
 * runs against, not a general-purpose lexer.
 */
function findCommentStart(lineText: string, marker: string | undefined): number {
  if (!marker) return -1;
  let inString: string | null = null;
  for (let i = 0; i < lineText.length; i++) {
    const c = lineText[i];
    if (inString) {
      if (c === '\\') { i++; continue; }
      if (c === inString) inString = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { inString = c; continue; }
    if (lineText.startsWith(marker, i)) return i;
  }
  return -1;
}

const fileTextCache = new Map<string, string[] | null>();

function readLines(absPath: string): string[] | null {
  const cached = fileTextCache.get(absPath);
  if (cached !== undefined) return cached;
  if (!existsSync(absPath)) {
    fileTextCache.set(absPath, null);
    return null;
  }
  const lines = readFileSync(absPath, 'utf-8').split(/\r\n|\n/);
  fileTextCache.set(absPath, lines);
  return lines;
}

/**
 * Verify every mapping in `sm` against the real source file it claims to
 * point at, resolved relative to `repoRoot`. Pass a fresh oracle-local
 * cache is implicit (module-level, keyed by absolute path) — callers don't
 * need to manage it.
 */
export function checkSourceAnchors(sm: SourceMap, repoRoot: string): AnchorReport {
  const violations: AnchorViolation[] = [];
  let trackedCount = 0;
  let untrackedCount = 0;

  for (const m of sm.mappings) {
    // line === 0 is the documented "position not tracked" carve-out (see
    // README's structural-invariants section, point 5). There is no claimed
    // position to verify, so it is neither a pass nor a checkable failure —
    // it is counted separately so callers can require trackedCount > 0.
    if (m.line === 0) { untrackedCount++; continue; }
    trackedCount++;

    const absPath = join(repoRoot, m.sourceFile);
    const lines = readLines(absPath);
    if (lines === null) {
      violations.push({ opcodeIndex: m.opcodeIndex, kind: 'source-file-missing', detail: m.sourceFile });
      continue;
    }
    if (m.line < 1 || m.line > lines.length) {
      violations.push({ opcodeIndex: m.opcodeIndex, kind: 'line-out-of-bounds', detail: `line=${m.line}, file has ${lines.length} lines` });
      continue;
    }
    const lineText = lines[m.line - 1];
    if (m.column < 0 || m.column >= lineText.length) {
      violations.push({ opcodeIndex: m.opcodeIndex, kind: 'column-out-of-bounds', detail: `column=${m.column}, line ${m.line} has ${lineText.length} chars: ${JSON.stringify(lineText)}` });
      continue;
    }
    const ch = lineText[m.column];
    if (WHITESPACE.test(ch)) {
      violations.push({ opcodeIndex: m.opcodeIndex, kind: 'points-at-whitespace', detail: `L${m.line}C${m.column} in ${JSON.stringify(lineText)}` });
      continue;
    }
    const commentStart = findCommentStart(lineText, LINE_COMMENT_MARKER[extOf(m.sourceFile)]);
    if (commentStart !== -1 && m.column >= commentStart) {
      violations.push({ opcodeIndex: m.opcodeIndex, kind: 'points-inside-comment', detail: `L${m.line}C${m.column} in ${JSON.stringify(lineText)}` });
      continue;
    }
    const chBefore = m.column > 0 ? lineText[m.column - 1] : undefined;
    if (WORD_CHAR.test(ch) && chBefore !== undefined && WORD_CHAR.test(chBefore)) {
      violations.push({ opcodeIndex: m.opcodeIndex, kind: 'splits-token', detail: `L${m.line}C${m.column} lands mid-token in ${JSON.stringify(lineText)} (char before: ${JSON.stringify(chBefore)})` });
      continue;
    }
  }

  return {
    ok: violations.length === 0 && trackedCount > 0,
    violations,
    trackedCount,
    untrackedCount,
    totalCount: sm.mappings.length,
  };
}

export interface ReferenceShapeReport {
  /** Sum over tier anchors of (distinct reference anchors covered - 1). */
  mergedAnchors: number;
  /** Tracked opcodes the tier maps that the reference does not. */
  extraMappings: number;
}

const anchorKey = (m: SourceMapping): string => `${m.sourceFile}:${m.line}:${m.column}`;

/**
 * Whole-map comparison of `sm` against the reference tier's map for the same
 * fixture (F-293). Untracked (line === 0) mappings are ignored on both sides.
 * See the F-293 paragraph in the file header for the rule and its justification.
 */
export function checkAgainstReference(sm: SourceMap, ref: SourceMap): ReferenceShapeReport {
  const refByOpcode = new Map<number, string>();
  for (const m of ref.mappings) if (m.line > 0) refByOpcode.set(m.opcodeIndex, anchorKey(m));

  const refAnchorsPerTierAnchor = new Map<string, Set<string>>();
  let extraMappings = 0;
  for (const m of sm.mappings) {
    if (m.line === 0) continue;
    const refAnchor = refByOpcode.get(m.opcodeIndex);
    if (refAnchor === undefined) { extraMappings++; continue; }
    const k = anchorKey(m);
    let set = refAnchorsPerTierAnchor.get(k);
    if (!set) { set = new Set(); refAnchorsPerTierAnchor.set(k, set); }
    set.add(refAnchor);
  }
  let mergedAnchors = 0;
  for (const set of refAnchorsPerTierAnchor.values()) mergedAnchors += set.size - 1;
  return { mergedAnchors, extraMappings };
}

// ---------------------------------------------------------------------------
// Known-issues allowlist (mirrors conformance/fold-on-allowlist.json).
// ---------------------------------------------------------------------------

export interface KnownIssueEntry {
  fixture: string;
  tier: string;
  violationCount: number;
  /** Mappings with line > 0 (anchor-checked). Pinned alongside
   *  violationCount so a tier that regresses from "partially tracked with N
   *  violations" to "fully untracked" (trackedCount collapses to 0, as with
   *  the Java tier) is caught even though violationCount alone wouldn't
   *  change (checkSourceAnchors skips line===0 mappings rather than
   *  recording them as violations). */
  trackedCount: number;
  totalCount: number;
  /** F-293 whole-map signature vs the TS reference (checkAgainstReference);
   *  omitted means 0. Pinned exactly, like the three fields above. */
  mergedAnchors?: number;
  extraMappings?: number;
  reason: string;
  tracking?: string;
}

export interface KnownIssuesFile {
  _doc?: string[];
  knownIssues: KnownIssueEntry[];
}

export function loadKnownIssues(path: string): KnownIssuesFile {
  const parsed = JSON.parse(readFileSync(path, 'utf-8')) as KnownIssuesFile;
  for (const entry of parsed.knownIssues) {
    if (!entry.reason || entry.reason.trim().length === 0) {
      throw new Error(`anchor-known-issues.json entry for ${entry.fixture}/${entry.tier} is missing a non-empty "reason"`);
    }
  }
  return parsed;
}

/**
 * Evaluate an AnchorReport against the known-issues allowlist for a given
 * (fixture, tier). Returns ok=true only if:
 *   - there are no violations and every mapping is position-tracked, and no
 *     known-issue entry exists (clean), or
 *   - the full (violationCount, trackedCount, totalCount) signature EXACTLY
 *     matches an allowlisted entry (documented, unchanged pre-existing
 *     issue).
 * Any other outcome (new violations, more/fewer violations than recorded, a
 * tracked-count regression such as a tier collapsing to fully-untracked, or
 * a violation on a pair with no allowlist entry) is a failure — this is what
 * makes the gate regression-sensitive instead of a one-time snapshot.
 */
export function evaluateAgainstKnownIssues(
  fixture: string,
  tier: string,
  report: AnchorReport,
  knownIssues: KnownIssueEntry[],
): { ok: boolean; reason: string } {
  const entry = knownIssues.find((e) => e.fixture === fixture && e.tier === tier);

  if (!entry) {
    if (report.ok) return { ok: true, reason: 'clean' };
    if (report.trackedCount === 0) {
      return { ok: false, reason: `no known-issue entry, but 0/${report.totalCount} mappings are position-tracked (fully degenerate source map)` };
    }
    return { ok: false, reason: `${report.violations.length} anchor violation(s), no known-issue entry recorded — either fix the generator or add a justified entry to anchor-known-issues.json` };
  }

  const matches =
    report.violations.length === entry.violationCount &&
    report.trackedCount === entry.trackedCount &&
    report.totalCount === entry.totalCount;
  if (!matches) {
    return {
      ok: false,
      reason: `anchor-known-issues.json records {violationCount:${entry.violationCount}, trackedCount:${entry.trackedCount}, totalCount:${entry.totalCount}} for ${fixture}/${tier}, but observed {violationCount:${report.violations.length}, trackedCount:${report.trackedCount}, totalCount:${report.totalCount}} — update the allowlist (if this is a deliberate fix or a new regression) with a fresh reason`,
    };
  }
  return { ok: true, reason: `matches recorded known issue: ${entry.reason}` };
}

/**
 * Evaluate a ReferenceShapeReport (F-293) against the allowlist. No entry means
 * (0, 0) is required; an entry must match exactly in both fields, so a fix that
 * lands without removing the entry fails just as a regression does.
 */
export function evaluateShapeAgainstKnownIssues(
  fixture: string,
  tier: string,
  shape: ReferenceShapeReport,
  knownIssues: KnownIssueEntry[],
): { ok: boolean; reason: string } {
  const entry = knownIssues.find((e) => e.fixture === fixture && e.tier === tier);
  const want = { mergedAnchors: entry?.mergedAnchors ?? 0, extraMappings: entry?.extraMappings ?? 0 };
  if (shape.mergedAnchors === want.mergedAnchors && shape.extraMappings === want.extraMappings) {
    return { ok: true, reason: entry ? `matches recorded known issue: ${entry.reason}` : 'clean' };
  }
  return {
    ok: false,
    reason: `${fixture}/${tier} vs the TS reference: observed {mergedAnchors:${shape.mergedAnchors}, extraMappings:${shape.extraMappings}}, anchor-known-issues.json records {mergedAnchors:${want.mergedAnchors}, extraMappings:${want.extraMappings}}${entry ? '' : ' (no entry)'} — fix the generator, or pin the exact signature with a justified reason`,
  };
}
