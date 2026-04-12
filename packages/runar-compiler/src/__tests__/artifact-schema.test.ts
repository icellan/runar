/**
 * Artifact schema round-trip test.
 *
 * Previously, `validateArtifact()` in runar-ir-schema would reject every
 * real compiler output because the JSON schema at
 * `packages/runar-ir-schema/src/schemas/artifact.schema.json` declared
 * `additionalProperties: false` at the root but only listed a subset of
 * the fields a real artifact carries (missing `anf`, `constructorSlots`,
 * `codeSepIndexSlots`, `codeSeparatorIndex`, `codeSeparatorIndices`,
 * plus `fixedArray` on ABIParam and `isTerminal` on ABIMethod).
 *
 * This test guards against that drift by compiling real contracts end
 * to end, round-tripping the resulting artifact through canonical JSON
 * (to strip bigints to plain integers), and feeding it into the
 * validator. Any new top-level or nested field added to `RunarArtifact`
 * must therefore also be added to the JSON schema, or this test fails.
 */

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { validateArtifact, canonicalJsonStringify } from 'runar-ir-schema';
import { compile } from '../index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const WORKTREE_ROOT = join(__dirname, '..', '..', '..', '..');

function loadExample(relPath: string): string {
  return readFileSync(join(WORKTREE_ROOT, relPath), 'utf-8');
}

/**
 * Round-trip an artifact through canonical JSON so bigint values are
 * serialised as bare JSON integers (and parsed back as plain numbers).
 * This is what the on-disk representation of an artifact looks like
 * to the schema validator, which sees no `bigint` type.
 */
function toPlainJson(data: unknown): unknown {
  return JSON.parse(canonicalJsonStringify(data));
}

describe('artifact schema — real compile output', () => {
  it('validates a minimal stateless P2PKH artifact', () => {
    const source = `
      class P2PKH extends SmartContract {
        readonly pk: PubKey;

        constructor(pk: PubKey) {
          super(pk);
          this.pk = pk;
        }

        public unlock(sig: Sig) {
          assert(checkSig(sig, this.pk));
        }
      }
    `;
    const result = compile(source);
    expect(result.success).toBe(true);
    expect(result.artifact).toBeDefined();
    const result2 = validateArtifact(toPlainJson(result.artifact));
    if (!result2.valid) {
      throw new Error(
        'validateArtifact rejected a fresh P2PKH artifact:\n' +
          result2.errors.map((e) => `  ${e.path}: ${e.message} [${e.keyword}]`).join('\n'),
      );
    }
    expect(result2.valid).toBe(true);
  });

  it('validates the TicTacToe v2 artifact (FixedArray + stateful)', () => {
    const source = loadExample('examples/ts/tic-tac-toe/TicTacToe.v2.runar.ts');
    const result = compile(source, { fileName: 'TicTacToe.v2.runar.ts' });
    expect(result.success).toBe(true);
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.stateFields).toBeDefined();
    // Sanity: FixedArray should be present on state fields.
    const boardField = result.artifact!.stateFields!.find((f) => f.name === 'board');
    expect(boardField).toBeDefined();
    expect(boardField!.fixedArray).toBeDefined();

    const result2 = validateArtifact(toPlainJson(result.artifact));
    if (!result2.valid) {
      throw new Error(
        'validateArtifact rejected a fresh TicTacToe v2 artifact:\n' +
          result2.errors.map((e) => `  ${e.path}: ${e.message} [${e.keyword}]`).join('\n'),
      );
    }
    expect(result2.valid).toBe(true);
  });

  it('validates a stateful artifact with IR debug snapshots included', () => {
    // Include IR to exercise the `ir.anf` / `ir.stack` sub-schemas too.
    const source = `
      class Counter extends StatefulSmartContract {
        count: bigint = 0n;

        constructor() {
          super(0n);
        }

        public increment() {
          this.count = this.count + 1n;
        }
      }
    `;
    // Real compile() does not expose an `includeIR` option, but the
    // artifact always includes `anf` for stateful contracts. That alone
    // exercises the top-level `anf` field against the schema.
    const result = compile(source);
    expect(result.success).toBe(true);
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.anf).toBeDefined();

    const result2 = validateArtifact(toPlainJson(result.artifact));
    if (!result2.valid) {
      throw new Error(
        'validateArtifact rejected a fresh Counter artifact:\n' +
          result2.errors.map((e) => `  ${e.path}: ${e.message} [${e.keyword}]`).join('\n'),
      );
    }
    expect(result2.valid).toBe(true);
  });
});
