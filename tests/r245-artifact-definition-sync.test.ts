/**
 * R-245 (CL-GAP-018): `RunarArtifact` and the ABI types are declared
 * independently in THREE files, kept in sync by hand and by nothing else.
 *
 *   packages/runar-compiler/src/ir/artifact.ts
 *   packages/runar-compiler/src/artifact/assembler.ts
 *   packages/runar-ir-schema/src/artifact.ts
 *
 * CLAUDE.md's sync guidance covers a DIFFERENT pair — the two `runar-ast.ts`
 * copies — and says "two places", so a reader following it would keep two of
 * these three aligned and not know about the third.
 *
 * They agree today. What makes the triplication worth a gate rather than a
 * refactor is what the type describes: the artifact is the wire format the seven
 * SDKs read, and the conformance suite compares artifacts across tiers. A field
 * added to one declaration and not the others does not fail to compile — the
 * TypeScript is structurally typed, so an object satisfying the wider interface
 * satisfies the narrower one, and the field simply goes missing wherever the
 * narrower declaration is the one in scope.
 *
 * The test compares the declared field NAMES of each shared interface. It
 * deliberately does not compare types or doc comments: those legitimately differ
 * in precision between the schema package and the compiler's internal view, and
 * a gate that fails on a reworded comment gets disabled.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const SOURCES = {
  'compiler ir': 'packages/runar-compiler/src/ir/artifact.ts',
  'compiler assembler': 'packages/runar-compiler/src/artifact/assembler.ts',
  'ir-schema': 'packages/runar-ir-schema/src/artifact.ts',
} as const;

/**
 * Field names declared directly in `export interface <name> { … }`.
 *
 * Nested object literals are skipped by tracking brace depth, so an inline
 * `sourceMap: { mappings: … }` contributes `sourceMap` and not `mappings`.
 */
function interfaceFields(src: string, name: string): string[] | null {
  const start = src.indexOf(`export interface ${name} {`);
  if (start === -1) return null;
  let depth = 0;
  const fields: string[] = [];
  for (const raw of src.slice(start).split('\n')) {
    const line = raw.trim();
    if (depth === 1) {
      const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\??\s*:/);
      if (m) fields.push(m[1]!);
    }
    depth += (raw.match(/\{/g) ?? []).length;
    depth -= (raw.match(/\}/g) ?? []).length;
    if (depth === 0 && fields.length + 1 > 0 && raw.includes('}')) break;
  }
  return [...new Set(fields)].sort();
}

const read = (rel: string) => readFileSync(join(ROOT, rel), 'utf8');

/** Interfaces declared in more than one of the three files. */
function sharedInterfaces(): string[] {
  const counts = new Map<string, number>();
  for (const rel of Object.values(SOURCES)) {
    for (const m of read(rel).matchAll(/export interface ([A-Za-z0-9_]+) \{/g)) {
      counts.set(m[1]!, (counts.get(m[1]!) ?? 0) + 1);
    }
  }
  return [...counts.entries()].filter(([, n]) => n > 1).map(([k]) => k).sort();
}

describe('R-245: the three artifact declarations stay in step', () => {
  it('the scan finds the declarations it is about', () => {
    const shared = sharedInterfaces();
    expect(shared, 'no interface is declared in more than one file — the scan broke')
      .toContain('RunarArtifact');
    expect(shared.length).toBeGreaterThanOrEqual(2);
  });

  it('every interface declared more than once declares the same fields', () => {
    const drift: string[] = [];
    for (const iface of sharedInterfaces()) {
      const perFile = new Map<string, string[]>();
      for (const [label, rel] of Object.entries(SOURCES)) {
        const fields = interfaceFields(read(rel), iface);
        if (fields) perFile.set(label, fields);
      }
      if (perFile.size < 2) continue;
      const [first, ...rest] = [...perFile.entries()];
      for (const [label, fields] of rest) {
        if (JSON.stringify(fields) !== JSON.stringify(first![1])) {
          drift.push(
            `${iface}: ${first![0]} has [${first![1].join(', ')}] but ${label} has [${fields.join(', ')}]`,
          );
        }
      }
    }
    expect(drift, 'these declarations of one wire type have diverged').toEqual([]);
  });

  it('CLAUDE.md accounts for all three files, not two', () => {
    const claude = read('CLAUDE.md');
    for (const rel of Object.values(SOURCES)) {
      expect(
        claude,
        `${rel} declares the artifact wire type and CLAUDE.md never mentions it`,
      ).toContain(rel);
    }
  });
});
