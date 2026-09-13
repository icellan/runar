/**
 * R-303 (GK-TODO-001): the ScriptVM availability matrix is stated in CLAUDE.md
 * and in each affected SDK README, and nowhere a user reads before upgrading.
 *
 * The absence of a ScriptVM in the Zig, Ruby and Java SDKs is policy, not an
 * oversight — no usable upstream BSV script interpreter exists for those
 * runtimes — and the finding does not ask for one. It asks for the one thing
 * that was missing: "v1 release notes list ScriptVM as TS/Go/Python (Rust
 * execute-only) and absent in Zig/Ruby/Java", so nobody upgrades expecting
 * seven of them.
 *
 * This test does not check that prose exists. It derives the matrix from the
 * SDK trees and requires the CHANGELOG to agree with it, so the note cannot
 * outlive the fact: ship a Ruby ScriptVM and this fails until the entry is
 * updated; delete the Python one and it fails the same way.
 */

import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Where each tier's ScriptVM lives, if it has one. */
const SCRIPT_VM_SOURCES: Record<string, string> = {
  TypeScript: 'packages/runar-testing/src/vm/script-vm.ts',
  Go: 'packages/runar-go/script_vm.go',
  Rust: 'packages/runar-rs/src/sdk/script_vm.rs',
  Python: 'packages/runar-py/runar/sdk/script_vm.py',
  Zig: 'packages/runar-zig/src/sdk/script_vm.zig',
  Ruby: 'packages/runar-rb/lib/runar/sdk/script_vm.rb',
  Java: 'packages/runar-java/src/main/java/runar/lang/sdk/ScriptVm.java',
};

function tiersWithScriptVm(): string[] {
  return Object.entries(SCRIPT_VM_SOURCES)
    .filter(([, p]) => existsSync(join(ROOT, p)))
    .map(([tier]) => tier);
}

function tiersWithout(): string[] {
  return Object.entries(SCRIPT_VM_SOURCES)
    .filter(([, p]) => !existsSync(join(ROOT, p)))
    .map(([tier]) => tier);
}

/** The CHANGELOG paragraph that carries the matrix. */
function scriptVmSection(): string {
  const text = readFileSync(join(ROOT, 'CHANGELOG.md'), 'utf8');
  const start = text.indexOf('### Off-chain ScriptVM: which SDKs ship one');
  expect(start, 'the CHANGELOG has no ScriptVM availability section').toBeGreaterThan(-1);
  const rest = text.slice(start + 1);
  const end = rest.indexOf('\n## ');
  return end === -1 ? rest : rest.slice(0, end);
}

/**
 * The table row for one tier: `| Zig | no ScriptVM |` -> "no ScriptVM".
 *
 * Reading the ROW, not the section, is the difference between a guard and a
 * word search. The first version of this test only asked whether the tier's
 * name appeared somewhere in the section — and every tier's name appears there,
 * so it passed with a Ruby ScriptVM planted on disk. Measured, not assumed.
 */
function verdictFor(tier: string): string {
  const section = scriptVmSection();
  const row = section
    .split('\n')
    .find((l) => l.trim().startsWith('|') && l.split('|')[1]?.trim() === tier);
  expect(row, `the ScriptVM table has no row for ${tier}`).toBeDefined();
  return (row!.split('|')[2] ?? '').trim();
}

describe('R-303: the release notes state where ScriptVM exists', () => {
  it('the filesystem scan is not vacuous', () => {
    expect(tiersWithScriptVm().length).toBeGreaterThan(0);
    expect(tiersWithout().length).toBeGreaterThan(0);
  });

  it('marks every tier that ships a ScriptVM as having one', () => {
    for (const tier of tiersWithScriptVm()) {
      const verdict = verdictFor(tier);
      expect(
        verdict.toLowerCase().startsWith('yes'),
        `${tier} ships a ScriptVM (${SCRIPT_VM_SOURCES[tier]}) but the notes say "${verdict}"`,
      ).toBe(true);
    }
  });

  it('marks every tier that does not as having none', () => {
    for (const tier of tiersWithout()) {
      const verdict = verdictFor(tier);
      expect(
        /^no\b/i.test(verdict),
        `${tier} ships no ScriptVM (${SCRIPT_VM_SOURCES[tier]} does not exist) ` +
          `but the notes say "${verdict}"`,
      ).toBe(true);
    }
  });

  it("records Rust's documented divergence rather than listing it as full support", () => {
    // Rust HAS a ScriptVM but cannot step it: upstream `Spend` keeps its stack
    // and program counter crate-private. A reader told "Rust: yes" would plan
    // a step-debugger that cannot be written.
    expect(verdictFor('Rust')).toMatch(/execute-only/i);
  });
});
