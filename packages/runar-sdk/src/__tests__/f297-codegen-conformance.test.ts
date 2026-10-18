// ---------------------------------------------------------------------------
// runar-sdk/__tests__/f297-codegen-conformance.test.ts
//
// F-297 — cross-SDK codegen conformance runner, TypeScript side.
//
// `conformance/sdk-codegen/` exists because a Rust codegen bug (fixed in
// c00cfe7: the generated constructor body referenced a bare param name
// instead of `args.<field>`) slipped through every SDK's own string-pattern
// tests -- none of them compiled the generated wrapper against a real
// compiler. Java, Ruby and Zig ship full MANIFEST-shaped runners; Go ships a
// partial one; Rust and Python got new ones in this same change
// (`packages/runar-rs/tests/f297_codegen_conformance.rs`,
// `packages/runar-py/tests/test_f297_codegen_conformance.py`). TypeScript --
// the reference generator -- had none: `codegen.test.ts` and
// `f246-codegen-installed-templates.test.ts` exercise `generateTypescript`
// but only against hand-built or single-fixture artifacts, with purely
// string-pattern assertions; neither loads the full shared fixture set.
//
// None of the other tiers' runners live at the MANIFEST/README-documented
// `conformance/sdk-codegen/runners/<lang>/` path -- that directory was never
// created for any tier. This file follows the real precedent instead: a
// vitest file in the SDK's own `__tests__/`, loading the shared fixtures
// from `conformance/sdk-codegen/fixtures/`.
//
// Compile-check approach: this package already has a proven pattern for
// exactly this in `f245-codegen-intent-witness-wrapper.test.ts`'s
// `loadWrapper()` -- transpile the generated TS with `ts.transpileModule`
// (strips types, so it is not a type-check) and execute it via `new
// Function('require', 'module', 'exports', js)(...)`, binding the
// `runar-sdk` import to the REAL in-process `RunarContract` /
// `buildP2PKHScript`. This file reuses that shape (duplicated locally since
// the helper is not exported) and, for each fixture, constructs the
// generated class and calls `getLockingScript()` -- enough to prove the
// constructor body, `fromUtxo`/`fromTxId`/`connect`/`getLockingScript`
// delegations, and every method/prepare/finalize declaration actually
// resolve against the real `RunarContract` API at both parse time (would
// throw a SyntaxError) and bind time (an undeclared identifier reference --
// the shape of the original c00cfe7 bug -- throws ReferenceError at module
// execution, which `ts.transpileModule`'s syntax-only pass would not catch).
//
// What this proves:
//   - `generateTypescript` for all 5 shared fixtures emits every structural
//     element the TS generator currently supports, and every generated
//     class can be transpiled, required (with `runar-sdk` bound to the real
//     SDK), constructed, and queried for its locking script without
//     throwing.
//
// What this does not prove:
//   - Full MANIFEST compliance beyond what is asserted below. N-278: both
//     `fromUtxo` and `attachInscription` are now asserted for every fixture
//     (`attachInscription` delegates to `RunarContract.withInscription`), and
//     the delegation is executed against the real `RunarContract`.
//   - A real type-check. `ts.transpileModule` strips types without
//     checking them (matching the existing `loadWrapper` precedent in this
//     package) -- a type-only error in the generated `.d.ts`-equivalent
//     shape would not be caught here. It would be caught by `pnpm run
//     build` (`tsc`), which TEST CADENCE already requires for any TS change.
//   - A real deploy/call/broadcast. Unlike
//     `f245-codegen-intent-witness-wrapper.test.ts`, this file does not run
//     through `MockProvider` -- that test already proves the full
//     deploy+call path works for two real example contracts; this one
//     proves the OTHER four fixture shapes (stateful mixed
//     terminal/non-terminal, no-ctor-params, multi-Sig finalize, Sig +
//     terminal) at least construct and resolve correctly.
//   - Anything about the Go/Rust/Python/Zig/Ruby/Java generators.
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import type { RunarArtifact } from 'runar-ir-schema';
import { RunarContract } from '../contract.js';
import { buildP2PKHScript } from '../script-utils.js';
import { generateTypescript, generateRust, generatePython, generateGo, generateZig } from '../codegen/index.js';

function fixturesDir(rel: string): string {
  return fileURLToPath(new URL(`../../../../conformance/sdk-codegen/fixtures/${rel}`, import.meta.url));
}

function loadFixture(name: string): RunarArtifact {
  return JSON.parse(readFileSync(fixturesDir(name), 'utf8')) as RunarArtifact;
}

/** Transpile + evaluate the generated wrapper, binding `runar-sdk` to this source tree.
 *  Mirrors `loadWrapper` in f245-codegen-intent-witness-wrapper.test.ts. */
function loadWrapper(source: string, className: string): any {
  const js = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const sdk = { RunarContract, buildP2PKHScript };
  const mod = { exports: {} as Record<string, unknown> };
  const req = (id: string) => {
    if (id !== 'runar-sdk') throw new Error(`unexpected import '${id}' in generated wrapper`);
    return sdk;
  };
  new Function('require', 'module', 'exports', js)(req, mod, mod.exports);
  return mod.exports[className];
}

describe('F-297 — cross-SDK codegen conformance (TypeScript runner)', () => {
  describe('p2pkh.json (stateless + Sig param)', () => {
    const artifact = loadFixture('p2pkh.json');
    const src = generateTypescript(artifact);

    it('contains every required structural element', () => {
      expect(src).toContain('export class P2PKHContract');
      expect(src).toContain('static fromUtxo(');
      expect(src).toContain('static async fromTxId(');
      expect(src).toContain('attachInscription(insc: Inscription)');
      expect(src).toContain('this.inner.withInscription(insc)');
      expect(src).toContain('connect(provider: Provider, signer: Signer)');
      expect(src).toContain('getLockingScript()');
      expect(src).toContain('async deploy(');
      expect(src).toContain('async unlock(');
      expect(src).toContain('pubKey:'); // user-visible param after Sig is hidden
      expect(src).toContain('async prepareUnlock(');
      expect(src).toContain('async finalizeUnlock(');
      expect(src).toContain('export interface TerminalOutput');
      expect(src).not.toContain('StatefulCallOptions'); // stateless contract
      expect(src).not.toContain('{{');
    });

    it('constructs and resolves getLockingScript() against the real RunarContract', () => {
      const Wrapper = loadWrapper(src, 'P2PKHContract');
      const wrapper = new Wrapper(artifact, { pubKeyHash: '11'.repeat(20) });
      expect(typeof wrapper.getLockingScript()).toBe('string');
    });
  });

  describe('counter.json (stateful, mixed terminal/non-terminal)', () => {
    const artifact = loadFixture('counter.json');
    const src = generateTypescript(artifact);

    it('contains every required structural element', () => {
      expect(src).toContain('export class CounterContract');
      expect(src).toContain('count:');
      expect(src).toContain('export interface CounterStatefulCallOptions');
      expect(src).toContain('satoshis?:');
      expect(src).toContain('changeAddress?:');
      expect(src).toContain('changePubKey?:');
      expect(src).toContain('newState?:');
      expect(src).toContain('outputs?:');
      expect(src).toContain('export interface TerminalOutput');
      expect(src).toContain('async increment(');
      expect(src).toContain('async reset(');
      expect(src).not.toContain('{{');
    });

    it('constructs and resolves getLockingScript() against the real RunarContract', () => {
      const Wrapper = loadWrapper(src, 'CounterContract');
      const wrapper = new Wrapper(artifact, { count: 0n });
      expect(typeof wrapper.getLockingScript()).toBe('string');
    });
  });

  describe('simple.json (no constructor params)', () => {
    const artifact = loadFixture('simple.json');
    const src = generateTypescript(artifact);

    it('contains the required structural elements', () => {
      expect(src).not.toContain('SimpleConstructorArgs');
      expect(src).toContain('export class SimpleContract');
      expect(src).toContain('constructor(artifact: RunarArtifact)');
      expect(src).toContain('async execute(');
      expect(src).not.toContain('{{');
    });

    it('constructs and resolves getLockingScript() against the real RunarContract', () => {
      const Wrapper = loadWrapper(src, 'SimpleContract');
      const wrapper = new Wrapper(artifact);
      expect(typeof wrapper.getLockingScript()).toBe('string');
    });
  });

  describe('stateful-escrow.json (stateful + multi-Sig)', () => {
    const artifact = loadFixture('stateful-escrow.json');
    const src = generateTypescript(artifact);

    it('emits constructor args, stateful options, and terminal output', () => {
      expect(src).toContain('export class EscrowContract');
      expect(src).toContain('buyer:');
      expect(src).toContain('seller:');
      expect(src).toContain('amount:');
      expect(src).toContain('export interface EscrowStatefulCallOptions');
      expect(src).toContain('export interface TerminalOutput');
    });

    it('emits prepare/finalize for the non-terminal Sig-bearing claim method', () => {
      expect(src).toContain('async claim(');
      expect(src).toContain('async prepareClaim(');
      expect(src).toContain('async finalizeClaim(');
      expect(src).toMatch(/async finalizeClaim\(prepared: PreparedCall,\s*buyerSig: string/);
    });

    it('emits prepare/finalize for the terminal multi-Sig release method, signatures in ABI order', () => {
      expect(src).toContain('async release(');
      expect(src).toContain('async prepareRelease(');
      expect(src).toContain('async finalizeRelease(');
      const finalizeReleaseIdx = src.indexOf('async finalizeRelease(');
      const finalizeReleaseBody = src.slice(finalizeReleaseIdx);
      const buyerIdx = finalizeReleaseBody.indexOf('buyerSig: string');
      const sellerIdx = finalizeReleaseBody.indexOf('sellerSig: string');
      expect(buyerIdx).toBeGreaterThan(-1);
      expect(sellerIdx).toBeGreaterThan(-1);
      expect(buyerIdx).toBeLessThan(sellerIdx);
    });

    it('constructs and resolves getLockingScript() against the real RunarContract', () => {
      const Wrapper = loadWrapper(src, 'EscrowContract');
      const wrapper = new Wrapper(artifact, { buyer: '02'.repeat(33), seller: '03'.repeat(33), amount: 1000n });
      expect(typeof wrapper.getLockingScript()).toBe('string');
    });
  });

  describe('inscribed.json (attachInscription path)', () => {
    const artifact = loadFixture('inscribed.json');
    const src = generateTypescript(artifact);

    it('constructs correctly and emits attachInscription + fromUtxo delegations (N-278)', () => {
      expect(src).toContain('export class InscribedHolderContract');
      expect(src).toContain('owner:');
      expect(src).toContain('async transfer(');
      expect(src).toContain('async prepareTransfer(');
      expect(src).toContain('async finalizeTransfer(');
      expect(src).toContain('attachInscription(insc: Inscription)');
      expect(src).toContain('static fromUtxo(');
      expect(src).not.toContain('{{');
    });

    it('attachInscription splices the envelope and fromUtxo restores it, through the real RunarContract (N-278)', () => {
      const Wrapper = loadWrapper(src, 'InscribedHolderContract');
      const wrapper = new Wrapper(artifact, { owner: '11'.repeat(20) });
      const plain = wrapper.getLockingScript() as string;
      const insc = { contentType: 'text/plain', data: Buffer.from('hello').toString('hex') };
      expect(wrapper.attachInscription(insc)).toBe(wrapper); // chains like withInscription
      const inscribed = wrapper.getLockingScript() as string;
      expect(inscribed).not.toBe(plain);
      expect(inscribed).toContain(Buffer.from('text/plain').toString('hex'));
      const restored = Wrapper.fromUtxo(artifact, { txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 1000, script: inscribed });
      expect(restored.getLockingScript()).toBe(inscribed);
    });

    it('constructs and resolves getLockingScript() against the real RunarContract', () => {
      const Wrapper = loadWrapper(src, 'InscribedHolderContract');
      const wrapper = new Wrapper(artifact, { owner: '11'.repeat(20) });
      expect(typeof wrapper.getLockingScript()).toBe('string');
    });
  });

  // N-278: the TS SDK renders the same shared templates for Go/Rust/Python
  // (`generateGo` etc.), so the typed Rust accessors rely on `buildCodegenContext`
  // producing the same `stateFields` the Rust SDK's own context builder does.
  describe('shared-template outputs carry the N-278 members', () => {
    it('generateRust emits from_utxo, attach_inscription, outputs and typed state accessors', () => {
      const src = generateRust(loadFixture('counter.json'));
      expect(src).toContain('pub fn from_utxo(artifact: RunarArtifact, utxo: &Utxo)');
      expect(src).toContain('pub fn attach_inscription(&mut self, insc: Inscription)');
      expect(src).toContain('pub outputs: Option<Vec<OutputSpec>>,');
      expect(src).toContain('pub fn count(&self) -> Option<BigInt>');
      expect(generateRust(loadFixture('p2pkh.json'))).not.toContain('Option<BigInt>');
    });

    it('generateGo and generatePython emit the from-UTXO factory and attach-inscription method', () => {
      const go = generateGo(loadFixture('p2pkh.json'));
      expect(go).toContain('func P2PKHContractFromUtxo(artifact *runar.RunarArtifact, utxo runar.UTXO)');
      expect(go).toContain('func (c *P2PKHContract) AttachInscription(insc *runar.Inscription) error');
      const py = generatePython(loadFixture('p2pkh.json'));
      expect(py).toContain('def from_utxo(');
      expect(py).toContain('def attach_inscription(self, insc: Inscription)');
    });
  });

  // N-340: the TS SDK's generateZig renders codegen/templates/wrapper.zig.mustache,
  // a different shape from the Zig SDK's own generator (packages/runar-zig/src/
  // sdk_codegen.zig). The member names and signatures asserted here are the ones
  // that generator emits and its runner (sdk_codegen_conformance_test.zig) asserts.
  // Structural only: the template output is not compiled here (no Zig toolchain in
  // vitest), so this proves presence and shape, not that the Zig compiles.
  describe('generateZig carries the fromUtxo / attachInscription members (N-340)', () => {
    for (const [fixture, name] of [
      ['p2pkh.json', 'P2PKH'],
      ['counter.json', 'Counter'],
      ['simple.json', 'Simple'],
      ['stateful-escrow.json', 'Escrow'],
      ['inscribed.json', 'InscribedHolder'],
    ] as const) {
      it(`${fixture}`, () => {
        const src = generateZig(loadFixture(fixture));
        expect(src).toContain(`pub const ${name}Wrapper = struct`);
        expect(src).toContain('const sdk = @import("runar-zig");');
        expect(src).toContain('inner: *sdk.RunarContract,');
        expect(src).toContain('pub fn fromUtxo(');
        expect(src).toContain('utxo: sdk.UTXO,');
        expect(src).toContain('inner.* = try sdk.RunarContract.fromUtxo(allocator, artifact, utxo);');
        expect(src).toContain(`pub fn attachInscription(self: *${name}Wrapper, insc: sdk.Inscription) !void`);
        expect(src).toContain('try self.inner.withInscription(insc);');
        expect(src).not.toContain('{{');
      });
    }
  });

  it('regression proof: loadWrapper rejects an out-of-scope identifier reference', () => {
    // The original c00cfe7 Rust bug was a bare identifier reference, valid
    // syntax but undefined at the point of use. `ts.transpileModule` is
    // syntax-only (like `syn::parse_file` / RubyVM::InstructionSequence) and
    // would NOT catch this -- only executing the module does, via
    // ReferenceError. This proves `loadWrapper`'s execute step (not just its
    // transpile step) is load-bearing for the per-fixture assertions above.
    expect(() => loadWrapper('export const x = thisIdentifierIsNeverBound;', 'x')).toThrow(/thisIdentifierIsNeverBound/);
  });
});
