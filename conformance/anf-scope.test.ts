/**
 * R-181 (CL-BUG-176): ANF binding names are NOT unique within a method, and the
 * architecture doc said they were ("numbered sequentially within each method").
 *
 * Reproduced with a conditional that declares an output in one arm only, so the
 * other arm gets the empty pad `_append_branch_output_concat` emits: the `if`
 * binding is `t18` and so is a binding INSIDE its own else arm. Two kinds of
 * reuse occur across the golden corpus, both deliberate:
 *
 *   - a branch arm rebinds a merged local under its own name (same list twice);
 *   - an arm lowers in its own context, so its temp indices collide with the
 *     parent's.
 *
 * Measured over the 78 golden expected-ir.json files: 21 same-list reuses, 93
 * nested-context reuses.
 *
 * Renaming to make the ANF genuinely SSA would move temp names, and therefore
 * the goldens, in every tier — the finding says so, and that is a coordinated
 * seven-tier change, not a cleanup. Its other remedy is "an explicitly accepted
 * invariant", which is what this file is.
 *
 * The invariant that DOES hold, and the reason the reuse is safe, is ordinary
 * lexical scope: every value reference resolves to a binding earlier in its own
 * list, or in an enclosing list, or to a method parameter. Anything that
 * flattens an arm into its parent must rename first — `remapValueRefs`,
 * `maxTempIndex` and `computeLastUses` are all keyed by name and all assume one
 * context.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const TESTS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), 'tests');

/** Fields of an ANF value that hold a binding name. */
const REF_FIELDS = [
  'left', 'right', 'operand', 'cond', 'value_ref', 'valueRef', 'preimage',
  'satoshis', 'script_bytes', 'scriptBytes', 'object', 'start', 'end',
  'index', 'condition',
];
const LIST_REF_FIELDS = ['args', 'state_values', 'stateValues', 'elements', 'refs'];

type Binding = { name: string; value: Record<string, unknown> };

function refsOf(value: Record<string, unknown>): { field: string; ref: string }[] {
  const out: { field: string; ref: string }[] = [];
  for (const f of REF_FIELDS) {
    const v = value[f];
    // An absent preimage is encoded as the empty string, not as a reference.
    if (typeof v === 'string' && v !== '') out.push({ field: f, ref: v });
  }
  for (const f of LIST_REF_FIELDS) {
    const v = value[f];
    if (Array.isArray(v)) {
      for (const item of v) if (typeof item === 'string' && item !== '') out.push({ field: f, ref: item });
    }
  }
  return out;
}

describe('R-181: ANF references resolve under lexical scope', () => {
  const fixtures = readdirSync(TESTS_DIR).filter((d) =>
    existsSync(join(TESTS_DIR, d, 'expected-ir.json')),
  );

  it('finds the golden corpus', () => {
    expect(fixtures.length).toBeGreaterThan(50);
  });

  it('every value reference names a binding in scope, in every golden', () => {
    const violations: string[] = [];
    let refsChecked = 0;
    let methodsScanned = 0;

    for (const fixture of fixtures) {
      const ir = JSON.parse(
        readFileSync(join(TESTS_DIR, fixture, 'expected-ir.json'), 'utf8'),
      ) as { methods?: { name: string; params?: { name: string }[]; body: Binding[] }[] };

      for (const method of ir.methods ?? []) {
        methodsScanned++;
        const params = new Set((method.params ?? []).map((p) => p.name));

        const walk = (bindings: Binding[], enclosing: Set<string>): void => {
          // A binding is visible to what FOLLOWS it, and to anything nested
          // inside it — not to its own operands.
          const scope = new Set(enclosing);
          for (const b of bindings) {
            for (const { field, ref } of refsOf(b.value)) {
              refsChecked++;
              if (ref.startsWith('@')) continue; // @this / @void sentinels
              if (!scope.has(ref)) {
                violations.push(
                  `${fixture}/${method.name}: binding ${b.name}.${field} references ` +
                    `'${ref}', which is not bound in its scope`,
                );
              }
            }
            for (const key of ['then', 'else', 'body']) {
              const nested = (b.value as Record<string, unknown>)[key];
              if (Array.isArray(nested)) walk(nested as Binding[], scope);
            }
            scope.add(b.name);
          }
        };

        walk(method.body, params);
      }
    }

    expect(methodsScanned).toBeGreaterThan(100);
    expect(refsChecked).toBeGreaterThan(1000);
    expect(violations).toEqual([]);
  });

  it('records that names really are reused, so the scan is not vacuous', () => {
    // If a future change made the ANF genuinely SSA, this would fail and the
    // note in docs/compiler-architecture.md would need updating with it.
    let sameListReuses = 0;
    let nestedReuses = 0;

    for (const fixture of fixtures) {
      const ir = JSON.parse(
        readFileSync(join(TESTS_DIR, fixture, 'expected-ir.json'), 'utf8'),
      ) as { methods?: { name: string; body: Binding[] }[] };

      for (const method of ir.methods ?? []) {
        const walk = (bindings: Binding[], seenAbove: Set<string>): void => {
          const inThisList = new Set<string>();
          for (const b of bindings) {
            if (inThisList.has(b.name)) sameListReuses++;
            else if (seenAbove.has(b.name)) nestedReuses++;
            inThisList.add(b.name);
            for (const key of ['then', 'else', 'body']) {
              const nested = (b.value as Record<string, unknown>)[key];
              if (Array.isArray(nested)) {
                walk(nested as Binding[], new Set([...seenAbove, ...inThisList]));
              }
            }
          }
        };
        walk(method.body, new Set());
      }
    }

    expect(sameListReuses + nestedReuses).toBeGreaterThan(0);
  });
});
