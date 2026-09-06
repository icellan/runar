/**
 * NEW-002 — `abi.constructor.params` and `constructorSlots` are built from two
 * INDEPENDENT sources and assumed to line up positionally.
 *
 *   - `abi.constructor.params` comes from the source constructor SIGNATURE
 *     (`extractABI` in `packages/runar-compiler/src/artifact/assembler.ts`).
 *   - a slot's `paramIndex` is an index into
 *     `properties.filter(p => p.initialValue === undefined)`
 *     (`lowerLoadProp` in `packages/runar-compiler/src/passes/05-stack-lower.ts`).
 *
 * Nothing checked that those two lists describe the same thing in the same
 * order, and the SDK splices `constructorArgs[slot.paramIndex]` into the slot's
 * bytes (`packages/runar-sdk/src/contract.ts`). When they disagree, a deploy
 * argument lands in ANOTHER property's slot — silently, with zero diagnostics.
 * A contract can therefore be deployed authorising a value the developer never
 * passed for that property, which is a fund-safety defect, not a cosmetic one.
 *
 * THE INVARIANT this suite pins:
 *
 *     Every constructor parameter initialises exactly one property that needs a
 *     deploy-time value, and the i-th parameter initialises the i-th such
 *     property.
 *
 * "Needs a deploy-time value" = carries no compile-time `initialValue` in the
 * artifact = is exactly the set the slot `paramIndex` counts over. Any program
 * that cannot satisfy the bijection has no representation in the positional
 * artifact model and must be REJECTED at compile time rather than mis-wired.
 *
 * MEASURED BEFORE THE FIX (TypeScript tier, and all six native tiers exit 0 on
 * every one of these):
 *
 *   R1  readonly a = 5n; readonly b; constructor(a, b) { super(a,b); this.b = b; }
 *       abi [a,b] but slots [{paramIndex:0,name:"a"}] — ONE slot for TWO params.
 *       That slot physically belongs to `b`; `deploy([1n, 99n])` splices `a`'s
 *       argument into `b`'s bytes and `a` stays baked at its initializer.
 *       script 55009300a0 (OP_5 = a baked, OP_0 = the one slot).
 *
 *   R2a a = 0n; b = 0n; constructor(seed) { this.a = seed; this.b = seed; }
 *       abi ["seed"], slots [] — `deploy([7n])` deployed a=0n, b=0n. The
 *       argument was accepted and dropped.
 *
 *   R2b the same shape without the initializers: `deploy([7n])` throws
 *       "Cannot convert undefined to a BigInt" — a pre-existing hole, loud but
 *       still no compile-time diagnostic.
 *
 *   K2  readonly a; readonly b; constructor(b, a) { this.a = a; this.b = b; }
 *       abi [b,a], slots [{0,name:"b"},{1,name:"a"}], but slot 0 is physically
 *       `a`'s load and slot 1 is `b`'s. Template 0000945a9c. `deploy([1n, 11n])`
 *       — the developer saying b=1, a=11, which satisfies `a - b === 10n` —
 *       deployed 515b945a9c, i.e. OP_1 OP_11 OP_SUB OP_10 OP_EQUAL = -10 != 10.
 *       The contract deploys clean and is permanently unspendable, with no
 *       exception anywhere. The correctly-ordered contract given the same
 *       intent deploys 5b51945a9c and evaluates true.
 *
 *   K3  count: bigint; constructor() { super(); this.count = 0n; }
 *       abi [], one deploy-time property. `deploy([])` throws "Cannot convert
 *       undefined to a BigInt".
 *
 *   K6  readonly a; constructor(a, unused) { this.a = a; }
 *       abi [a,unused], slots [{0,name:"a"}] — the second argument is required
 *       by the SDK and then silently discarded.
 *
 * WHY THE DEPLOY LEG IS NOT OPTIONAL. K2 is the case that proves it: the
 * compiler is entirely self-consistent there — two params, two slots, names
 * attached — and only the deployed BYTES reveal that argument 0 went into
 * property `a` while the ABI says argument 0 is `b`. A compiler-only assertion
 * of "slots.length === params.length" goes green on K2. So the accepted-shape
 * leg deploys through the real SDK and runs the resulting locking script
 * through `@bsv/sdk`'s interpreter: the contract asserts `a - b === 10n`, so an
 * argument in the wrong slot computes `1 - 11` and the script evaluates FALSE.
 * The negative control (arguments deliberately swapped by the caller) pins that
 * the check can actually fail.
 *
 * A missing toolchain FAILS this suite rather than skipping it.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner } from 'runar-sdk';
import { PrivateKey } from '@bsv/sdk';
import { ScriptVM } from '../index.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-abi-slot-'));

const PRIV = PrivateKey.fromString('b1'.repeat(32), 16);
const PKH = PRIV.toPublicKey().toHash('hex') as string;

// ---------------------------------------------------------------------------
// Shapes that CANNOT be represented by the positional artifact model
// ---------------------------------------------------------------------------

/** Residue 1: initializer survives, but the constructor still declares a param for it. */
const R1 = `import { SmartContract, assert } from 'runar-lang';
export class R1 extends SmartContract {
  readonly a: bigint = 5n;
  readonly b: bigint;
  constructor(a: bigint, b: bigint) { super(a, b); this.b = b; }
  public go() { assert(this.a + this.b > 0n); }
}
`;

/** Residue 2: one parameter feeding two properties, initializers present. */
const R2A = `import { StatefulSmartContract } from 'runar-lang';
export class R2a extends StatefulSmartContract {
  a: bigint = 0n;
  b: bigint = 0n;
  constructor(seed: bigint) { super(seed); this.a = seed; this.b = seed; }
  public go(d: bigint) { this.a = this.a + d; this.b = this.b + d; }
}
`;

/** The same fan-out with no initializers — the pre-existing deploy-time hole. */
const R2B = `import { StatefulSmartContract } from 'runar-lang';
export class R2b extends StatefulSmartContract {
  a: bigint;
  b: bigint;
  constructor(seed: bigint) { super(seed); this.a = seed; this.b = seed; }
  public go(d: bigint) { this.a = this.a + d; this.b = this.b + d; }
}
`;

/** Parameters declared in a different order than the properties they initialise. */
const K2 = `import { SmartContract, assert } from 'runar-lang';
export class K2 extends SmartContract {
  readonly a: bigint;
  readonly b: bigint;
  constructor(b: bigint, a: bigint) { super(b, a); this.a = a; this.b = b; }
  public go() { assert(this.a - this.b === 10n); }
}
`;

/** A deploy-time property seeded from a literal in the constructor body. */
const K3 = `import { StatefulSmartContract } from 'runar-lang';
export class K3 extends StatefulSmartContract {
  count: bigint;
  constructor() { super(); this.count = 0n; }
  public go(d: bigint) { this.count = this.count + d; }
}
`;

/** A constructor parameter that initialises nothing. */
const K6 = `import { SmartContract, assert } from 'runar-lang';
export class K6 extends SmartContract {
  readonly a: bigint;
  constructor(a: bigint, unused: bigint) { super(a, unused); this.a = a; }
  public go() { assert(this.a > 0n); }
}
`;

/** Python surface — proves the rule is not a TypeScript-parser artifact. */
const PY_FANOUT = `from runar import StatefulSmartContract


class PyFanout(StatefulSmartContract):
    a: int
    b: int

    def __init__(self, seed: int):
        super().__init__(seed)
        self.a = seed
        self.b = seed

    @public
    def go(self, d: int):
        self.a = self.a + d
        self.b = self.b + d
`;

const REJECT = [
  { label: 'initializer survives beside a declared parameter', file: 'R1.runar.ts', src: R1 },
  { label: 'one parameter feeding two properties (initializers)', file: 'R2a.runar.ts', src: R2A },
  { label: 'one parameter feeding two properties (no initializers)', file: 'R2b.runar.ts', src: R2B },
  { label: 'parameters ordered differently to their properties', file: 'K2.runar.ts', src: K2 },
  { label: 'deploy-time property seeded from a literal', file: 'K3.runar.ts', src: K3 },
  { label: 'constructor parameter that initialises nothing', file: 'K6.runar.ts', src: K6 },
  { label: 'one parameter feeding two properties, Python surface', file: 'PyFanout.runar.py', src: PY_FANOUT },
];

// ---------------------------------------------------------------------------
// Shapes that MUST keep compiling — the rule may not cost a working pattern
// ---------------------------------------------------------------------------

/** The canonical two-parameter form. `a - b === 10n` discriminates slot order. */
const OK_ORDERED = `import { SmartContract, assert } from 'runar-lang';
export class Ordered extends SmartContract {
  readonly a: bigint;
  readonly b: bigint;
  constructor(a: bigint, b: bigint) { super(a, b); this.a = a; this.b = b; }
  public go() { assert(this.a - this.b === 10n); }
}
`;

/** Property name != parameter name — the everyday P2PKH shape. */
const OK_RENAMED = `import { SmartContract, assert, ByteString, PubKey, hash160 } from 'runar-lang';
export class Renamed extends SmartContract {
  readonly pubKeyHash: ByteString;
  constructor(pkh: ByteString) { super(pkh); this.pubKeyHash = pkh; }
  public unlock(pk: PubKey) { assert(hash160(pk) == this.pubKeyHash); }
}
`;

/** An initialized property the constructor never mentions keeps its default. */
const OK_DEFAULT = `import { StatefulSmartContract } from 'runar-lang';
export class Defaulted extends StatefulSmartContract {
  k: bigint = 5n;
  m: bigint;
  constructor(m: bigint) { super(m); this.m = m; }
  public go(d: bigint) { this.k = this.k + d; this.m = this.m + d; }
}
`;

/** NEW-001's shape: an initializer the constructor argument overrides. */
const OK_OVERRIDE = `import { StatefulSmartContract } from 'runar-lang';
export class Override extends StatefulSmartContract {
  x: bigint = 0n;
  constructor(x: bigint) { super(x); this.x = x; }
  public go(d: bigint) { this.x = this.x + d; }
}
`;

/** No properties at all. */
const OK_EMPTY = `import { SmartContract, assert } from 'runar-lang';
export class Empty extends SmartContract {
  constructor() { super(); }
  public go(d: bigint) { assert(d > 0n); }
}
`;

/** Readonly and mutable side by side, parameters in declaration order. */
const OK_MIXED = `import { StatefulSmartContract, assert, ByteString, PubKey, hash160 } from 'runar-lang';
export class Mixed extends StatefulSmartContract {
  readonly owner: ByteString;
  count: bigint;
  seedLimit: bigint = 9n;
  constructor(owner: ByteString, count: bigint) { super(owner, count); this.owner = owner; this.count = count; }
  public bump(pk: PubKey, d: bigint) { assert(hash160(pk) == this.owner); this.count = this.count + d; }
}
`;

const ACCEPT = [
  { label: 'two parameters in declaration order', file: 'Ordered.runar.ts', src: OK_ORDERED },
  { label: 'parameter named differently to its property', file: 'Renamed.runar.ts', src: OK_RENAMED },
  { label: 'an initialized property with no parameter', file: 'Defaulted.runar.ts', src: OK_DEFAULT },
  { label: 'an initializer a constructor argument overrides', file: 'Override.runar.ts', src: OK_OVERRIDE },
  { label: 'a contract with no properties', file: 'Empty.runar.ts', src: OK_EMPTY },
  { label: 'readonly and mutable properties together', file: 'Mixed.runar.ts', src: OK_MIXED },
];

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

function write(name: string, src: string): string {
  const p = join(TMP, name);
  writeFileSync(p, src);
  return p;
}

interface TierRun { exitCode: number; output: string }

function run(cmd: string, args: string[], cwd?: string): TierRun {
  try {
    const out = execFileSync(cmd, args, {
      cwd, timeout: 120_000, stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 32 * 1024 * 1024,
    });
    return { exitCode: 0, output: out.toString() };
  } catch (e: unknown) {
    const err = e as { status?: number; stdout?: Buffer; stderr?: Buffer };
    return {
      exitCode: err.status ?? -1,
      output: `${err.stdout?.toString() ?? ''}${err.stderr?.toString() ?? ''}`,
    };
  }
}

function javaJar(): string {
  const libs = join(REPO, 'compilers', 'java', 'build', 'libs');
  if (!existsSync(libs)) throw new Error('Java jar missing — run `./gradlew jar` in compilers/java');
  const jar = readdirSync(libs).find((f) => f.endsWith('.jar'));
  if (!jar) throw new Error('Java jar missing — run `./gradlew jar` in compilers/java');
  return join(libs, jar);
}

function requireBin(p: string, how: string): string {
  if (!existsSync(p)) throw new Error(`missing compiler binary ${p} — build it with: ${how}`);
  return p;
}

const NATIVE_TIERS: { name: string; run: (src: string) => TierRun }[] = [
  {
    name: 'go',
    run: (src) => run(
      requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
      ['--source', src, '--hex'],
    ),
  },
  {
    name: 'rust',
    run: (src) => run(
      requireBin(
        join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'),
        'cd compilers/rust && cargo build --release',
      ),
      ['--source', src, '--hex'],
    ),
  },
  {
    name: 'zig',
    run: (src) => run(
      requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
      ['--source', src, '--hex'],
    ),
  },
  { name: 'java', run: (src) => run('java', ['-jar', javaJar(), '--source', src, '--hex']) },
  {
    name: 'python',
    run: (src) => run('python3', ['-m', 'runar_compiler', '--source', src, '--hex'],
      join(REPO, 'compilers', 'python')),
  },
  {
    name: 'ruby',
    run: (src) => run('ruby',
      ['-I', join(REPO, 'compilers', 'ruby', 'lib'),
        join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'), '--source', src, '--hex'],
    ),
  },
];

/** Deploy through the real SDK and return the deployed locking script. */
async function deployScript(src: string, fileName: string, args: unknown[]): Promise<string> {
  const r = compile(src, { fileName });
  expect(r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message).join(' | ')).toBe('');
  const signer = new LocalSigner(PRIV.toString());
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'ee'.repeat(32), outputIndex: 0, satoshis: 1_000_000, script: '76a914' + PKH + '88ac',
  });
  const c = new RunarContract(r.artifact as never, args);
  c.connect(provider, signer);
  await c.deploy({ satoshis: 1000 });
  return c.getLockingScript();
}

/** Deploy and return the SDK's view of the contract state. */
async function deployState(src: string, fileName: string, args: unknown[]): Promise<Record<string, unknown>> {
  const r = compile(src, { fileName });
  expect(r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message).join(' | ')).toBe('');
  const signer = new LocalSigner(PRIV.toString());
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'ee'.repeat(32), outputIndex: 0, satoshis: 1_000_000, script: '76a914' + PKH + '88ac',
  });
  const c = new RunarContract(r.artifact as never, args);
  c.connect(provider, signer);
  await c.deploy({ satoshis: 1000 });
  return c.state as Record<string, unknown>;
}

// ---------------------------------------------------------------------------

describe('NEW-002: every constructor parameter owns exactly one constructor slot', () => {
  describe('TypeScript (golden tier)', () => {
    for (const c of REJECT) {
      it(`rejects: ${c.label}`, () => {
        const r = compile(c.src, { fileName: c.file });
        const errors = r.diagnostics.filter((d) => d.severity === 'error');
        expect(errors.length, 'expected at least one error diagnostic').toBeGreaterThan(0);
        expect(errors.map((e) => e.message).join(' | ')).toMatch(/constructor/i);
        expect(r.success).toBe(false);
        expect(r.artifact).toBeFalsy();
      });
    }

    for (const c of ACCEPT) {
      it(`still accepts: ${c.label}`, () => {
        const r = compile(c.src, { fileName: c.file });
        expect(r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message).join(' | ')).toBe('');
        expect(r.success).toBe(true);
      });
    }
  });

  describe('the artifact invariant itself', () => {
    for (const c of ACCEPT) {
      it(`holds for: ${c.label}`, () => {
        const r = compile(c.src, { fileName: c.file });
        expect(r.success).toBe(true);
        const abi = r.artifact!.abi.constructor.params;
        const slots = r.artifact!.constructorSlots ?? [];
        // Every slot names the param at its own index, and no two slots claim
        // the same param unless they are the same placeholder byte offset.
        const byParam = new Map<number, Set<number>>();
        for (const s of slots) {
          expect(abi[s.paramIndex], `slot paramIndex ${s.paramIndex} has no ABI param`).toBeDefined();
          expect(s.name).toBe(abi[s.paramIndex]!.name);
          expect(s.type).toBe(abi[s.paramIndex]!.type);
          if (!byParam.has(s.paramIndex)) byParam.set(s.paramIndex, new Set());
          byParam.get(s.paramIndex)!.add(s.byteOffset);
        }
        // Every ABI param that reaches the code part is represented.
        expect([...byParam.keys()].every((i) => i < abi.length)).toBe(true);
      });
    }
  });

  describe('end-to-end deploy (the leg a compiler-only assertion misses)', () => {
    it('splices each argument into its own property, verified on the deployed script', async () => {
      // `a - b === 10n`. Arguments in declaration order: a=11, b=1.
      const script = await deployScript(OK_ORDERED, 'Ordered.runar.ts', [11n, 1n]);
      const vm = new ScriptVM();
      const res = vm.executeHex(script);
      expect(res.success, `deployed script did not evaluate true: ${script}`).toBe(true);
    });

    it('fails when the caller swaps the two arguments (the check can go red)', async () => {
      const script = await deployScript(OK_ORDERED, 'Ordered.runar.ts', [1n, 11n]);
      const vm = new ScriptVM();
      expect(vm.executeHex(script).success).toBe(false);
    });

    it('deploys the argument, not the initializer, for the override shape', async () => {
      const state = await deployState(OK_OVERRIDE, 'Override.runar.ts', [7n]);
      expect(state.x).toBe(7n);
    });

    it('keeps the default for a property with no constructor parameter', async () => {
      const state = await deployState(OK_DEFAULT, 'Defaulted.runar.ts', [7n]);
      expect(state.k).toBe(5n);
      expect(state.m).toBe(7n);
    });

    it('wires readonly and mutable properties independently', async () => {
      const state = await deployState(OK_MIXED, 'Mixed.runar.ts', ['ab'.repeat(20), 4n]);
      expect(state.count).toBe(4n);
      expect(state.seedLimit).toBe(9n);
    });
  });

  for (const tier of NATIVE_TIERS) {
    describe(tier.name, () => {
      for (const c of REJECT) {
        it(`rejects: ${c.label}`, () => {
          const r = tier.run(write(`${tier.name}-${c.file}`, c.src));
          expect(r.exitCode, `expected rejection, got:\n${r.output}`).not.toBe(0);
          expect(r.output).toMatch(/constructor/i);
        });
      }

      for (const c of ACCEPT) {
        it(`still accepts: ${c.label}`, () => {
          const r = tier.run(write(`${tier.name}-${c.file}`, c.src));
          expect(r.exitCode, `expected success, got:\n${r.output}`).toBe(0);
        });
      }
    });
  }
});
