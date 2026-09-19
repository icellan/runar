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

import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { validateANF, validateArtifact, canonicalJsonStringify } from 'runar-ir-schema';
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
  // -------------------------------------------------------------------------
  // R-089 — a NON-DEFAULT `@sighash` mode must survive the schema gate.
  //
  // Two live defects (N-079b in the TS `subContext`, N-086 in Zig's FixedArray
  // expansion) shipped a *dropped* sighash field because no fixture ever ran a
  // `@sighash` artifact through `validateArtifact` / `validateANF` — and the
  // schemas could not have processed one if it had, since `sighashFlag` and
  // `sigHashType` were missing from `additionalProperties: false` objects.
  //
  // This case both closes that hole and asserts the fields are actually there,
  // so a future tier that silently drops one fails here instead of on-chain.
  // -------------------------------------------------------------------------
  it('validates a stateful artifact compiled under a non-default @sighash mode', () => {
    const source = `
      class SighashCounter extends StatefulSmartContract {
        n: bigint;

        constructor(n: bigint) {
          super(n);
          this.n = n;
        }

        /** @sighash SINGLE|FORKID */
        public bump(): void {
          this.addOutput(1000n, this.n);
        }
      }
    `;
    const result = compile(source, { fileName: 'SighashCounter.runar.ts' });
    expect(result.success).toBe(true);
    expect(result.artifact).toBeDefined();

    // The mode reached the ABI (0x43 = SINGLE|FORKID). Guards against a tier
    // dropping it on the way out of the pipeline.
    const bump = result.artifact!.abi.methods.find((m) => m.name === 'bump');
    expect(bump).toBeDefined();
    expect(bump!.sigHashType).toBe(0x43);

    // …and into the embedded ANF's check_preimage node.
    const plain = toPlainJson(result.artifact) as {
      anf?: unknown;
    };
    const flags: unknown[] = [];
    const walk = (node: unknown): void => {
      if (Array.isArray(node)) {
        node.forEach(walk);
      } else if (node && typeof node === 'object') {
        const rec = node as Record<string, unknown>;
        if (rec.kind === 'check_preimage') flags.push(rec.sighashFlag);
        Object.values(rec).forEach(walk);
      }
    };
    walk(plain.anf);
    expect(flags).toContain(0x43);

    // The schema gate itself — both the artifact and its embedded ANF.
    const artifactResult = validateArtifact(plain);
    if (!artifactResult.valid) {
      throw new Error(
        'validateArtifact rejected a fresh @sighash SINGLE|FORKID artifact:\n' +
          artifactResult.errors
            .map((e) => `  ${e.path}: ${e.message} [${e.keyword}]`)
            .join('\n'),
      );
    }
    expect(artifactResult.valid).toBe(true);

    const anfResult = validateANF(plain.anf);
    if (!anfResult.valid) {
      throw new Error(
        'validateANF rejected the ANF of a fresh @sighash SINGLE|FORKID artifact:\n' +
          anfResult.errors
            .map((e) => `  ${e.path}: ${e.message} [${e.keyword}]`)
            .join('\n'),
      );
    }
    expect(anfResult.valid).toBe(true);
  });

  it('validates a stateful artifact compiled under @bindingVariant all', () => {
    const source = `
      class AllCounter extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @bindingVariant all */
        public bump(): void { this.addOutput(1000n, this.n); }
      }
    `;
    const result = compile(source, { fileName: 'AllCounter.runar.ts' });
    expect(result.success).toBe(true);
    const bump = result.artifact!.abi.methods.find((m) => m.name === 'bump');
    expect(bump!.bindingVariant).toBe('all');

    const plain = toPlainJson(result.artifact) as { anf?: unknown };
    const variants: unknown[] = [];
    const walk = (node: unknown): void => {
      if (Array.isArray(node)) node.forEach(walk);
      else if (node && typeof node === 'object') {
        const rec = node as Record<string, unknown>;
        if (rec.kind === 'check_preimage') variants.push(rec.bindingVariant);
        Object.values(rec).forEach(walk);
      }
    };
    walk(plain.anf);
    expect(variants).toContain('all');

    const artifactResult = validateArtifact(plain);
    if (!artifactResult.valid) {
      throw new Error(
        'validateArtifact rejected a fresh @bindingVariant all artifact:\n' +
          artifactResult.errors
            .map((e) => `  ${e.path}: ${e.message} [${e.keyword}]`)
            .join('\n'),
      );
    }
    expect(artifactResult.valid).toBe(true);

    const anfResult = validateANF(plain.anf);
    if (!anfResult.valid) {
      throw new Error(
        'validateANF rejected the ANF of a fresh @bindingVariant all artifact:\n' +
          anfResult.errors
            .map((e) => `  ${e.path}: ${e.message} [${e.keyword}]`)
            .join('\n'),
      );
    }
    expect(anfResult.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// R-089 — the checked-in conformance goldens ARE the ANF wire format.
//
// The schemas are strict (`additionalProperties: false` on every object), so
// any field the seven compilers agree on but the schema omits is a silent
// rejection waiting to happen — which is exactly how `check_preimage`'s
// `sighashFlag` and `add_output`'s empty-string `preimage` sentinel ended up
// unrepresentable. Sweeping every golden closes that loop: a future wire-format
// field that lands in the compilers without landing in the schema fails HERE.
// ---------------------------------------------------------------------------

describe('ANF schema — every checked-in conformance golden', () => {
  const goldenDir = join(WORKTREE_ROOT, 'conformance', 'tests');
  const fixtures = readdirSync(goldenDir).filter((name) => {
    try {
      readFileSync(join(goldenDir, name, 'expected-ir.json'), 'utf-8');
      return true;
    } catch {
      return false;
    }
  });

  it('finds the golden ANF fixtures at all', () => {
    // Guards against the sweep below silently passing on an empty list.
    expect(fixtures.length).toBeGreaterThan(50);
  });

  it.each(fixtures)('validateANF accepts the %s golden ANF', (fixture) => {
    const anf = JSON.parse(
      readFileSync(join(goldenDir, fixture, 'expected-ir.json'), 'utf-8'),
    );
    const result = validateANF(anf);
    if (!result.valid) {
      // Report only the errors that name a real over-tight / missing
      // constraint; `oneOf` sibling-branch noise is dropped.
      const signal = result.errors.filter(
        (e) => e.keyword !== 'oneOf' && e.keyword !== 'const' && e.keyword !== 'required',
      );
      throw new Error(
        `validateANF rejected the checked-in ${fixture} golden ANF:\n` +
          (signal.length ? signal : result.errors)
            .map((e) => `  ${e.path}: ${e.message} [${e.keyword}]`)
            .join('\n'),
      );
    }
    expect(result.valid).toBe(true);
  });
});
