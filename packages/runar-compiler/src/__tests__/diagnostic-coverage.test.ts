import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { compile } from '../index.js';
import { collectDiagnosticSites, attribute, HOLE, type DiagnosticSite } from './support/diagnostic-sites.js';
import { CORPUS } from './support/diagnostic-corpus.js';

/**
 * R-101 — diagnostic coverage gate.
 *
 * The finding: "Only 12 negative fixtures exist against 119 diagnostic-emission
 * sites in the TS validate+typecheck passes alone… Rejection behaviour is the
 * half of the byte-identity claim that nobody is checking… derive negative
 * fixtures systematically from the diagnostic sites, not ad hoc."
 * Its testable assertion: "a coverage test asserting every diagnostic ID
 * emitted by any tier has at least one negative fixture."
 *
 * Rúnar's diagnostics have no IDs — they are message templates at
 * `makeDiagnostic` call sites — so the identity used here is the template
 * itself, extracted from the sources (`support/diagnostic-sites.ts`) rather
 * than transcribed into a list that rots. Two call sites that produce the same
 * message are the same diagnostic for this purpose: nothing downstream, a
 * reader included, can tell them apart from the message alone.
 *
 * Three properties are enforced, and the third is the ratchet:
 *
 *   1. every corpus entry still provokes the diagnostic it claims;
 *   2. every entry's target names exactly one diagnostic;
 *   3. every diagnostic is covered, or is listed in the baseline with a
 *      reason — and a baseline entry that has BECOME covered fails, so the
 *      number can only go down.
 *
 * Set RUNAR_DIAGNOSTIC_COVERAGE_DUMP=1 to print the uncovered list.
 */

const REPO = resolve(__dirname, '../../../..');
const BASELINE_PATH = resolve(__dirname, 'diagnostic-coverage-baseline.json');
const NEGATIVES = resolve(REPO, 'conformance/negatives');

interface Baseline {
  uncovered: Array<{ id: string; reason: string }>;
}

const sites = collectDiagnosticSites(REPO);

/** Human-readable form of a template: every `${...}` hole becomes `*`. A
 *  corpus entry's `target` is matched against this, so a target can pin the
 *  shape around an interpolation ("Constructor parameter '*' must have"). */
function readable(template: string): string {
  return template.split(HOLE).join('*');
}

/**
 * Sites an entry's `target` names. An EXACT template match wins outright:
 * several messages are prefixes of longer ones ("must end with an assert()
 * call" vs "… or a terminal asm({...})"), and without this rule the shorter
 * one could never be named unambiguously.
 */
function sitesTargetedBy(target: string): DiagnosticSite[] {
  const exact = sites.filter((s) => readable(s.template) === target);
  if (exact.length > 0) return exact;
  return sites.filter((s) => readable(s.template).includes(target));
}

/** Unique diagnostics, keyed by template with its holes shown as `*`; several
 *  call sites can share one. This readable form is what the baseline file
 *  stores, so the checked-in JSON carries no control characters. */
function uniqueIds(all: DiagnosticSite[]): string[] {
  return [...new Set(all.map((s) => readable(s.id)))].sort();
}

/** Compile a source and return every message it produced, or null if it threw. */
function diagnosticsOf(source: string, fileName: string): string[] | null {
  try {
    const res = compile(source, { fileName });
    return res.diagnostics.map((d) => d.message);
  } catch {
    // A parser throw is a legitimate rejection but carries no diagnostic we
    // can attribute — treated as "covers nothing", never as a pass.
    return null;
  }
}

/** ids covered by one source. */
function idsCoveredBy(source: string, fileName: string): Set<string> {
  const hit = new Set<string>();
  const messages = diagnosticsOf(source, fileName) ?? [];
  for (const m of messages) for (const i of attribute(sites, m)) hit.add(readable(sites[i]!.id));
  return hit;
}

describe('R-101 diagnostic coverage', () => {
  it('extracts a diagnostic inventory from the passes themselves', () => {
    // A drop to near-zero means the extractor stopped matching the sources
    // (a rename of makeDiagnostic, a new message shape) and every coverage
    // number below would be vacuously perfect.
    expect(sites.length).toBeGreaterThan(100);
    expect(uniqueIds(sites).length).toBeGreaterThan(90);
  });

  it('every corpus entry names exactly one diagnostic', () => {
    const ambiguous: string[] = [];
    const unknown: string[] = [];
    for (const entry of CORPUS) {
      const matches = [...new Set(sitesTargetedBy(entry.target).map((s) => readable(s.id)))];
      if (matches.length === 0) unknown.push(`${entry.name}: no diagnostic template contains ${JSON.stringify(entry.target)}`);
      else if (matches.length > 1) {
        ambiguous.push(
          `${entry.name}: ${JSON.stringify(entry.target)} matches ${matches.length} diagnostics:\n    ` +
          matches.map((m) => m.replace(/\s+/g, ' ').slice(0, 110)).join('\n    '),
        );
      }
    }
    expect([...unknown, ...ambiguous].join('\n  ')).toBe('');
  });

  it('every corpus entry still provokes the diagnostic it targets', () => {
    const dead: string[] = [];
    for (const entry of CORPUS) {
      const wanted = sitesTargetedBy(entry.target)[0];
      if (!wanted) continue; // reported by the test above
      const fileName = entry.fileName ?? `${entry.name}.runar.ts`;
      const messages = diagnosticsOf(entry.source, fileName);
      if (messages === null) {
        dead.push(`${entry.name}: compile() threw, so no diagnostic could be attributed`);
        continue;
      }
      const covered = idsCoveredBy(entry.source, fileName);
      if (!covered.has(readable(wanted.id))) {
        dead.push(
          `${entry.name}: expected ${JSON.stringify(entry.target)}, got ` +
          (messages.length === 0 ? 'NO diagnostics (the source is accepted)' : messages.map((m) => m.replace(/\s+/g, ' ').slice(0, 100)).join(' | ')),
        );
      }
    }
    expect(dead.join('\n  ')).toBe('');
  });

  it('every diagnostic is covered by a fixture, or baselined with a reason', () => {
    const covered = new Set<string>();

    for (const entry of CORPUS) {
      for (const id of idsCoveredBy(entry.source, entry.fileName ?? `${entry.name}.runar.ts`)) covered.add(id);
    }
    // The seven-tier rejection corpus counts too — those fixtures are stronger
    // (every tier must refuse them), so anything they already reach needs no
    // second entry here.
    for (const f of readdirSync(NEGATIVES).filter((x) => /\.runar\.(ts|sol|move)$/.test(x))) {
      for (const id of idsCoveredBy(readFileSync(join(NEGATIVES, f), 'utf-8'), f)) covered.add(id);
    }

    const all = uniqueIds(sites);
    const uncovered = all.filter((id) => !covered.has(id));

    if (process.env.RUNAR_DIAGNOSTIC_COVERAGE_DUMP === '1') {
      console.log(`covered ${covered.size} / ${all.length}; uncovered ${uncovered.length}`);
      for (const id of uncovered) console.log(`  ${id.replace(/\s+/g, ' ').slice(0, 160)}`);
    }

    expect(existsSync(BASELINE_PATH)).toBe(true);
    const baseline = JSON.parse(readFileSync(BASELINE_PATH, 'utf-8')) as Baseline;
    const baselined = new Map(baseline.uncovered.map((u) => [u.id, u.reason]));

    // (a) nothing may be uncovered unless it is baselined WITH a reason.
    const unexplained = uncovered.filter((id) => !baselined.has(id));
    expect(
      unexplained.length === 0
        ? ''
        : `${unexplained.length} diagnostic(s) have no negative fixture and no baseline entry:\n  ` +
          unexplained.map((id) => id.replace(/\s+/g, ' ').slice(0, 140)).join('\n  '),
    ).toBe('');

    // (b) the ratchet: a baseline entry that is now covered must be deleted,
    //     so the baseline can only shrink.
    const stale = [...baselined.keys()].filter((id) => covered.has(id));
    expect(
      stale.length === 0
        ? ''
        : `${stale.length} baseline entr(y/ies) are now covered — delete them from ` +
          `diagnostic-coverage-baseline.json:\n  ` +
          stale.map((id) => id.replace(/\s+/g, ' ').slice(0, 140)).join('\n  '),
    ).toBe('');

    // (c) a baseline entry naming a diagnostic that no longer exists is also
    //     stale — it would otherwise excuse a future diagnostic with the same
    //     text forever.
    const orphaned = [...baselined.keys()].filter((id) => !all.includes(id));
    expect(
      orphaned.length === 0
        ? ''
        : `${orphaned.length} baseline entr(y/ies) name a diagnostic that no longer exists:\n  ` +
          orphaned.map((id) => id.replace(/\s+/g, ' ').slice(0, 140)).join('\n  '),
    ).toBe('');

    for (const [, reason] of baselined) expect(reason.length).toBeGreaterThan(20);
  });
});
