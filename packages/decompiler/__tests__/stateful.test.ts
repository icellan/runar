/**
 * Stateful contract recovery — end-to-end.
 *
 * Counter (and friends) extend `StatefulSmartContract`, which means the
 * compiler auto-injects a `checkPreimage` prelude + a state-continuation
 * tail around the developer's user code. The decompiler is artifact-aware:
 * when the caller hands it `stateFields` and the artifact's ANF, the new
 * stateful path strips the prelude / continuation, recovers the user
 * surface, and re-compiles to confirm byte-identity.
 *
 * Each test:
 *   1. Compiles a stateful TS source.
 *   2. Calls `decompile()` with `stateFields` + `anf` from the artifact.
 *   3. Confirms `recoveryPath: 'symexec'` (the stateful lifter is part
 *      of the symexec layer, since it lifts back to canonical source).
 *   4. Asserts the recovered source declares `extends StatefulSmartContract`
 *      and (where applicable) explicit `addOutput` / `addRawOutput` /
 *      `addDataOutput` calls.
 *   5. Re-compiles and checks `scriptHex` byte-identity.
 *
 * Aborts to raw_script for shapes outside the recognized continuation
 * pattern are acceptable — those tests use `expect(dec.recoveryPath).toBe`
 * with a clearly-documented justification.
 */

import { describe, it, expect } from 'vitest';
import { hexToBytes } from 'runar-testing';
import { compile } from 'runar-compiler';
import { decompile } from '../src/index.js';

function compileSource(source: string, fileName = 'Test.runar.ts') {
  const r = compile(source, { fileName });
  expect(r.success).toBe(true);
  expect(r.scriptHex).toBeDefined();
  expect(r.artifact).toBeDefined();
  return r;
}

describe('stateful — artifact-driven recovery', () => {
  it('Counter (canonical stateful-counter example) — strips prelude + continuation, round-trips byte-identically', () => {
    // The canonical Counter example. The compiler emits an auto-injected
    // prelude (load_param txPreimage → check_preimage → assert →
    // load_param txPreimage → deserialize_state) and a continuation
    // tail (buildChangeOutput → get_state_script → computeStateOutput →
    // cat → hash256 → extractOutputHash → === → assert).
    //
    // The stateful lifter strips both pieces, recovers the user-visible
    // body (a single this.count = this.count + 1n), and renders as
    // `class Counter extends StatefulSmartContract`.
    const source = `
      import { StatefulSmartContract } from 'runar-lang';
      export class Counter extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
        public increment() { this.count = this.count + 1n; }
        public decrement() { this.count = this.count - 1n; }
      }
    `;
    const r = compileSource(source, 'Counter.runar.ts');
    expect(r.artifact!.stateFields).toBeDefined();
    expect(r.artifact!.stateFields!.length).toBe(1);
    expect(r.artifact!.stateFields![0]!.name).toBe('count');

    const dec = decompile(hexToBytes(r.scriptHex!), {
      stateFields: r.artifact!.stateFields,
      codeSeparatorIndex: r.artifact!.codeSeparatorIndex,
      codeSeparatorIndices: r.artifact!.codeSeparatorIndices,
      parentClass: 'StatefulSmartContract',
      anf: r.artifact!.anf,
      className: 'Counter',
    });
    expect(dec.ok).toBe(true);
    expect(dec.recoveryPath).toBe('symexec');
    expect(dec.source).toContain('extends StatefulSmartContract');
    expect(dec.source).toContain('count: bigint');
    expect(dec.source).toContain('this.count = ');

    // Re-compile and check byte-identity.
    const recompiled = compile(dec.source, { fileName: 'Counter.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(r.scriptHex);
  });

  it('Counter with assert in body — assert survives the strip', () => {
    const source = `
      import { StatefulSmartContract, assert } from 'runar-lang';
      export class Counter extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
        public decrement() {
          assert(this.count > 0n);
          this.count = this.count - 1n;
        }
      }
    `;
    const r = compileSource(source, 'Counter.runar.ts');
    const dec = decompile(hexToBytes(r.scriptHex!), {
      stateFields: r.artifact!.stateFields,
      codeSeparatorIndex: r.artifact!.codeSeparatorIndex,
      codeSeparatorIndices: r.artifact!.codeSeparatorIndices,
      parentClass: 'StatefulSmartContract',
      anf: r.artifact!.anf,
      className: 'Counter',
    });
    expect(dec.ok).toBe(true);
    expect(dec.recoveryPath).toBe('symexec');
    expect(dec.source).toContain('assert(');
    expect(dec.source).toContain('this.count = ');

    const recompiled = compile(dec.source, { fileName: 'Counter.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(r.scriptHex);
  });

  it('RawOutputTest — explicit addRawOutput + addOutput survive the strip', () => {
    // The user-visible body contains BOTH an explicit `this.addRawOutput`
    // (a user-controlled output) AND a multi-output `this.addOutput`
    // (the user-controlled state-continuation form). Both must be
    // recovered as explicit method calls, NOT folded into the
    // auto-continuation tail.
    //
    // The source is deliberately slightly different from the canonical
    // `RawOutputTest` (different push amount) so the template path
    // doesn't match the hex verbatim and we exercise the stateful lifter.
    const source = `
      import { StatefulSmartContract } from 'runar-lang';
      export class RawOutputTest2 extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
        public sendToScript(scriptBytes: ByteString) {
          this.addRawOutput(2000n, scriptBytes);
          this.count = this.count + 1n;
          this.addOutput(0n, this.count);
        }
      }
    `;
    const r = compileSource(source, 'RawOutputTest2.runar.ts');
    const dec = decompile(hexToBytes(r.scriptHex!), {
      stateFields: r.artifact!.stateFields,
      codeSeparatorIndex: r.artifact!.codeSeparatorIndex,
      codeSeparatorIndices: r.artifact!.codeSeparatorIndices,
      parentClass: 'StatefulSmartContract',
      anf: r.artifact!.anf,
      className: 'RawOutputTest2',
    });
    expect(dec.ok).toBe(true);
    expect(dec.recoveryPath).toBe('symexec');
    expect(dec.source).toContain('extends StatefulSmartContract');
    expect(dec.source).toContain('this.addRawOutput(');
    expect(dec.source).toContain('this.addOutput(');

    const recompiled = compile(dec.source, { fileName: 'RawOutputTest2.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(r.scriptHex);
  });

  it('DataOutputTest — explicit addDataOutput survives the strip', () => {
    // Slightly different from canonical to avoid the template path matching.
    const source = `
      import { StatefulSmartContract, ByteString } from 'runar-lang';
      export class DataOutputTest2 extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
        public publish(payload: ByteString) {
          this.count = this.count + 2n;
          this.addDataOutput(0n, payload);
        }
      }
    `;
    const r = compileSource(source, 'DataOutputTest2.runar.ts');
    const dec = decompile(hexToBytes(r.scriptHex!), {
      stateFields: r.artifact!.stateFields,
      codeSeparatorIndex: r.artifact!.codeSeparatorIndex,
      codeSeparatorIndices: r.artifact!.codeSeparatorIndices,
      parentClass: 'StatefulSmartContract',
      anf: r.artifact!.anf,
      className: 'DataOutputTest2',
    });
    expect(dec.ok).toBe(true);
    expect(dec.recoveryPath).toBe('symexec');
    expect(dec.source).toContain('this.addDataOutput(');

    const recompiled = compile(dec.source, { fileName: 'DataOutputTest2.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(r.scriptHex);
  });

  it('Mixed readonly + mutable — readonly survives as a readonly prop, mutable as a state field', () => {
    // A stateful contract with a readonly `threshold` (configured at
    // deploy time) and a mutable `count`. The readonly property baked
    // into the locking script via a constructor placeholder; the mutable
    // property is the state field.
    const source = `
      import { StatefulSmartContract, assert } from 'runar-lang';
      export class CappedCounter extends StatefulSmartContract {
        readonly cap: bigint;
        count: bigint;
        constructor(cap: bigint, count: bigint) {
          super(cap, count);
          this.cap = cap;
          this.count = count;
        }
        public increment() {
          assert(this.count < this.cap);
          this.count = this.count + 1n;
        }
      }
    `;
    const r = compileSource(source, 'CappedCounter.runar.ts');
    expect(r.artifact!.stateFields!.length).toBe(1);
    expect(r.artifact!.stateFields![0]!.name).toBe('count');
    expect(r.artifact!.constructorSlots).toBeDefined();

    const dec = decompile(hexToBytes(r.scriptHex!), {
      stateFields: r.artifact!.stateFields,
      constructorSlots: r.artifact!.constructorSlots,
      codeSeparatorIndex: r.artifact!.codeSeparatorIndex,
      codeSeparatorIndices: r.artifact!.codeSeparatorIndices,
      parentClass: 'StatefulSmartContract',
      anf: r.artifact!.anf,
      className: 'CappedCounter',
    });
    expect(dec.ok).toBe(true);
    expect(dec.recoveryPath).toBe('symexec');
    expect(dec.source).toContain('readonly cap:');
    expect(dec.source).toContain('count: bigint');
    expect(dec.source).toContain('this.cap');

    const recompiled = compile(dec.source, { fileName: 'CappedCounter.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(r.scriptHex);
  });
});

describe('stateful — without artifact info, behavior is unchanged', () => {
  it('omitting stateFields and anf — Counter falls through to the template path (canonical hex match)', () => {
    // Canonical stateful-counter source is in `templates-data.json`. When
    // we DON'T supply artifact info, the template layer matches the hex
    // verbatim and recovers it that way. We assert the recovery path is
    // NOT 'symexec' (which proves the stateful layer didn't fire) but
    // also IS ok (so the call still round-trips).
    const source = `
      import { StatefulSmartContract } from 'runar-lang';
      export class Counter extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
        public increment() { this.count = this.count + 1n; }
        public decrement() { this.count = this.count - 1n; }
      }
    `;
    const r = compileSource(source, 'Counter.runar.ts');
    const dec = decompile(hexToBytes(r.scriptHex!));
    expect(dec.ok).toBe(true);
    // The stateful layer only fires when artifact info is supplied. Without
    // it, the call drops straight to template/symexec/raw_script.
    expect(dec.recoveryPath).not.toBe('symexec');
  });
});
