/**
 * NEW-001 — a property carrying BOTH a literal initializer AND a constructor
 * parameter silently DISCARDED the deploy-time argument.
 *
 *     x: bigint = 0n;
 *     constructor(x: bigint) { super(x); this.x = x; }
 *
 * compiled with zero diagnostics, the artifact ABI advertised
 * `constructor.params: [{name:"x"}]`, and `stateFields[0]` carried
 * `initialValue: 0n`. `new RunarContract(artifact, [7n]).deploy()` therefore
 * deployed `x = 0n` — the developer's argument was accepted and dropped. Delete
 * the initializer and the same deploy yielded `x = 7n`. Wrong deployed state,
 * no warning.
 *
 * THE RULE (constructor wins). A property assigned a constructor PARAMETER in
 * the constructor body carries no compile-time `initialValue`; the initializer
 * degrades to a default that the constructor argument overrides. This is not a
 * new invention — it is the semantics the Zig surface has always shipped, where
 *
 *     count: i64 = 0,
 *     pub fn init(count: i64) C { return .{ .count = count }; }
 *
 * is the IDIOMATIC struct form. `01-parse-zig.ts` stripped the initializer in
 * the parser with the comment "the constructor argument overrides any default …
 * so every compiler must do the same to keep IR identical", and FIVE conformance
 * fixtures depend on it: assert-false-guard, loop-if-merged-locals,
 * merge-locals-prop-updates, merge-locals-shapes, state-bigint-edges all declare
 * `= 0` defaults on their Zig surface while their `expected-ir.json` carries no
 * `initialValue`. 31 of 86 in-repo `.runar.zig` contracts use the shape.
 *
 * So the TypeScript/Solidity/Move/Python/Ruby/Java surfaces were the outliers,
 * and the fix moves the rule out of the Zig parser into a shared lowering step
 * that every surface and every tier applies identically.
 *
 * WHY IT NEEDS THE DEPLOY LEG. A compiler-only assertion would not have caught
 * this: the compiler was self-consistent. The defect only becomes visible when
 * the SDK reads `stateFields[].initialValue` and takes that branch over the
 * constructor argument (`packages/runar-sdk/src/contract.ts`). Both legs stay.
 *
 * WHY THE CROSS-TIER LEG COMPARES IR AND NOT HEX. For a STATEFUL contract the
 * mutable fields live in the state section the SDK appends at deploy, not in the
 * code part, and a constructor slot is itself a 1-byte OP_0 placeholder — so the
 * script hex is IDENTICAL with and without the initializer. Hex parity is
 * therefore vacuous here and would have gone green against the unfixed
 * compiler. The discriminator is the ANF IR's `properties[].initialValue`, which
 * is exactly what each fixture's `expected-ir.json` pins.
 *
 * This also pins a divergence that was ALREADY live before the fix: compiling
 * the same `.runar.ts` source, the zig tier emitted `[{"name":"x",...}]` while
 * go/rust/java/python/ruby/ts all emitted `[{"initialValue":0,"name":"x",...}]`.
 * Six tiers against one, on IR that conformance compares byte for byte — it had
 * simply never fired because no fixture used the shape.
 *
 * A missing toolchain FAILS this suite rather than skipping it.
 *
 * ---------------------------------------------------------------------------
 * NEW-002 (separate defect — recorded here, deliberately NOT fixed by this
 * change, so the next session starts from the measurement rather than
 * rediscovering it).
 *
 * `abi.constructor.params` is built from the source constructor SIGNATURE while
 * the constructor-slot list is built from `properties.filter(p =>
 * p.initialValue === undefined)`. They are two independently-built lists that
 * the artifact assumes align POSITIONALLY, and any surviving initializer
 * desyncs them. Measured on the TS tier before this fix:
 *
 *     readonly a: bigint = 5n;
 *     readonly b: bigint;
 *     constructor(a: bigint, b: bigint) { super(a, b); this.a = a; this.b = b; }
 *     public go() { assert(this.a + this.b > 0n); }
 *
 *   success: true    diagnostics: []
 *   abi   : [{"name":"a","type":"bigint"},{"name":"b","type":"bigint"}]
 *   slots : [{"paramIndex":0,"byteOffset":1,"name":"a","type":"bigint",
 *             "valueEncoding":"scriptnum"}]
 *   script: 55009300a0      (OP_5 = `a` baked, OP_0 = the ONE slot, OP_ADD …)
 *
 * Two ABI params, ONE slot. That slot physically belongs to `b` but is labelled
 * `a` at paramIndex 0, so `deploy([1n, 99n])` splices `a`'s value into `b`'s
 * slot and `b`'s argument is never used.
 *
 * The NEW-001 fix NARROWS this but does not close it: `a` above is assigned a
 * constructor parameter, so its initializer is now dropped, both properties
 * become slots and the two lists realign. The residue is a property whose
 * initializer SURVIVES (not constructor-assigned) while the constructor still
 * declares a parameter for it — nothing rejects that, and the lists desync
 * again. Closing it needs an invariant check that every ABI constructor param
 * maps to exactly one slot. Tracked as NEW-002; deliberately out of scope here.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner } from 'runar-sdk';
import { PrivateKey } from '@bsv/sdk';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-init-ctor-'));

// ---------------------------------------------------------------------------
// Sources. Each "defect" source must compile to the SAME bytes as its control,
// which is the identical contract with the redundant initializer deleted.
// ---------------------------------------------------------------------------

/** Property name == constructor parameter name (the reported repro). */
const TS_SAME = `import { StatefulSmartContract } from 'runar-lang';
export class T extends StatefulSmartContract {
  x: bigint = 0n;
  constructor(x: bigint) { super(x); this.x = x; }
  public go(d: bigint) { this.x = this.x + d; }
}
`;
const TS_SAME_CTRL = TS_SAME.replace('x: bigint = 0n;', 'x: bigint;');

/**
 * Property name != constructor parameter name. Identical hazard, and the shape
 * that actually occurs in-repo — the Zig parser's old name-match strip would
 * NOT have caught it, which is why the rule keys on the constructor ASSIGNMENT.
 */
const TS_SEED = `import { StatefulSmartContract } from 'runar-lang';
export class U extends StatefulSmartContract {
  p: bigint = 0n;
  constructor(seed: bigint) { super(seed); this.p = seed; }
  public go(d: bigint) { this.p = this.p + d; }
}
`;
const TS_SEED_CTRL = TS_SEED.replace('p: bigint = 0n;', 'p: bigint;');

/** The Zig surface's idiomatic form — must lower to the TS form's bytes. */
const ZIG_SAME = `const runar = @import("runar");

pub const T = struct {
    pub const Contract = runar.StatefulSmartContract;

    x: i64 = 0,

    pub fn init(x: i64) T {
        return .{ .x = x };
    }

    pub fn go(self: *T, d: i64) void {
        self.x = self.x + d;
    }
};
`;

/**
 * OVER-STRIP GUARD. `k` has an initializer and is NOT assigned any constructor
 * parameter, so it MUST keep `initialValue: 5n`. If this goes red the rule is
 * too greedy and it has started eating real compile-time defaults.
 */
const TS_KEEP = `import { StatefulSmartContract } from 'runar-lang';
export class K extends StatefulSmartContract {
  k: bigint = 5n;
  m: bigint;
  constructor(m: bigint) { super(m); this.m = m; }
  public go(d: bigint) { this.k = this.k + d; this.m = this.m + d; }
}
`;

/**
 * READONLY / stateless variant. A readonly property is baked into the CODE part
 * rather than the state section, so here the fix is visible as a constructor
 * SLOT appearing where the value used to be baked.
 */
const TS_RO = `import { SmartContract, assert } from 'runar-lang';
export class R extends SmartContract {
  readonly v: bigint = 0n;
  constructor(v: bigint) { super(v); this.v = v; }
  public go(d: bigint) { assert(this.v + d > 0n); }
}
`;
const TS_RO_CTRL = TS_RO.replace('readonly v: bigint = 0n;', 'readonly v: bigint;');

const PRIV = PrivateKey.fromString('b1'.repeat(32), 16);
const PKH = PRIV.toPublicKey().toHash('hex') as string;

function write(name: string, src: string): string {
  const p = join(TMP, name);
  writeFileSync(p, src);
  return p;
}

function hexOf(src: string, fileName: string): string {
  const r = compile(src, { fileName });
  const errs = r.diagnostics.filter((d) => d.severity === 'error');
  expect(errs.map((e) => e.message).join(' | '), `expected ${fileName} to compile`).toBe('');
  expect(r.success).toBe(true);
  return r.artifact!.script;
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

const NATIVE_TIERS: { name: string; run: (src: string, mode: string[]) => TierRun }[] = [
  {
    name: 'go',
    run: (src, mode) => run(
      requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
      ['--source', src, ...mode],
    ),
  },
  {
    name: 'rust',
    run: (src, mode) => run(
      requireBin(
        join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'),
        'cd compilers/rust && cargo build --release',
      ),
      ['--source', src, ...mode],
    ),
  },
  {
    name: 'zig',
    run: (src, mode) => run(
      requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
      ['--source', src, ...mode],
    ),
  },
  { name: 'java', run: (src, mode) => run('java', ['-jar', javaJar(), '--source', src, ...mode]) },
  {
    name: 'python',
    run: (src, mode) => run('python3', ['-m', 'runar_compiler', '--source', src, ...mode],
      join(REPO, 'compilers', 'python')),
  },
  {
    name: 'ruby',
    run: (src, mode) => run('ruby',
      ['-I', join(REPO, 'compilers', 'ruby', 'lib'),
        join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'), '--source', src, ...mode],
    ),
  },
];

interface IrProp { name: string; type: string; readonly: boolean; initialValue?: unknown }

/** The tier's ANF IR `properties` array — the array conformance pins. */
function tierProps(
  tier: { name: string; run: (src: string, mode: string[]) => TierRun },
  file: string,
  src: string,
): IrProp[] {
  const r = tier.run(write(`${tier.name}-${file}`, src), ['--emit-ir']);
  expect(r.exitCode, `${tier.name} failed to compile ${file}:\n${r.output}`).toBe(0);
  const props = (JSON.parse(r.output) as { properties: IrProp[] }).properties;
  // Key order differs between tiers; compare on a canonical shape.
  return props.map((p) => ({
    name: p.name, type: p.type, readonly: p.readonly,
    ...(p.initialValue !== undefined ? { initialValue: p.initialValue } : {}),
  }));
}

/** Deploy through the real SDK and return the state the UTXO was funded with. */
async function deployState(src: string, fileName: string, args: unknown[]): Promise<Record<string, unknown>> {
  const r = compile(src, { fileName });
  expect(r.success, r.diagnostics.map((d) => d.message).join(' | ')).toBe(true);
  const signer = new LocalSigner(PRIV.toString());
  const provider = new MockProvider();
  provider.enableBroadcastValidation();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'ee'.repeat(32), outputIndex: 0, satoshis: 1_000_000, script: '76a914' + PKH + '88ac',
  });
  const c = new RunarContract(r.artifact as never, args);
  c.connect(provider, signer);
  await c.deploy({ satoshis: 1000 });
  return c.state as Record<string, unknown>;
}

describe('NEW-001: a constructor argument overrides a property initializer', () => {
  describe('TypeScript (golden tier)', () => {
    it('drops initialValue when the constructor assigns the property (same name)', () => {
      const r = compile(TS_SAME, { fileName: 'T.runar.ts' });
      expect(r.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
      expect(r.success).toBe(true);
      expect(r.artifact!.stateFields![0]!.name).toBe('x');
      expect(r.artifact!.stateFields![0]!.initialValue).toBeUndefined();
    });

    it('drops initialValue when the constructor param has a DIFFERENT name', () => {
      const r = compile(TS_SEED, { fileName: 'U.runar.ts' });
      expect(r.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
      expect(r.artifact!.stateFields![0]!.name).toBe('p');
      expect(r.artifact!.stateFields![0]!.initialValue).toBeUndefined();
    });

    it('compiles byte-identically to the same contract without the initializer', () => {
      expect(hexOf(TS_SAME, 'T.runar.ts')).toBe(hexOf(TS_SAME_CTRL, 'T.runar.ts'));
      expect(hexOf(TS_SEED, 'U.runar.ts')).toBe(hexOf(TS_SEED_CTRL, 'U.runar.ts'));
    });

    it('KEEPS initialValue for a property the constructor never assigns', () => {
      const r = compile(TS_KEEP, { fileName: 'K.runar.ts' });
      expect(r.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
      const k = r.artifact!.stateFields!.find((f) => f.name === 'k');
      const m = r.artifact!.stateFields!.find((f) => f.name === 'm');
      expect(k!.initialValue).toBe(5n);
      expect(m!.initialValue).toBeUndefined();
    });

    it('lowers the Zig surface form to the same bytes as the TypeScript form', () => {
      expect(hexOf(ZIG_SAME, 'T.runar.zig')).toBe(hexOf(TS_SAME, 'T.runar.ts'));
    });

    it('turns a ctor-assigned READONLY property into a constructor slot', () => {
      const r = compile(TS_RO, { fileName: 'R.runar.ts' });
      expect(r.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
      const ctrl = compile(TS_RO_CTRL, { fileName: 'R.runar.ts' });
      // The initializer must be invisible: same slots as the control, and the
      // slot must exist at all (before the fix `v` was baked and produced none).
      expect(r.artifact!.constructorSlots).toEqual(ctrl.artifact!.constructorSlots);
      expect(r.artifact!.constructorSlots).toHaveLength(1);
      expect(r.artifact!.constructorSlots![0]!.name).toBe('v');
    });
  });

  describe('end-to-end deploy (this is the leg the compiler-only test misses)', () => {
    it('deploys the constructor argument, not the initializer', async () => {
      const state = await deployState(TS_SAME, 'T.runar.ts', [7n]);
      expect(state.x).toBe(7n);
    });

    it('deploys the constructor argument when the param name differs', async () => {
      const state = await deployState(TS_SEED, 'U.runar.ts', [7n]);
      expect(state.p).toBe(7n);
    });

    it('still deploys the initializer for a property with no constructor arg', async () => {
      const state = await deployState(TS_KEEP, 'K.runar.ts', [7n]);
      expect(state.k).toBe(5n);
      expect(state.m).toBe(7n);
    });
  });

  for (const tier of NATIVE_TIERS) {
    describe(tier.name, () => {
      for (const [label, src, ctrl, file] of [
        ['same-named ctor param', TS_SAME, TS_SAME_CTRL, 'T.runar.ts'],
        ['differently-named ctor param', TS_SEED, TS_SEED_CTRL, 'U.runar.ts'],
        ['readonly property', TS_RO, TS_RO_CTRL, 'R.runar.ts'],
      ] as Array<[string, string, string, string]>) {
        it(`lowers ${label} identically to the no-initializer control`, () => {
          expect(tierProps(tier, `a-${file}`, src)).toEqual(tierProps(tier, `b-${file}`, ctrl));
        });
      }

      it('emits no initialValue for a constructor-assigned property', () => {
        expect(tierProps(tier, `x-T.runar.ts`, TS_SAME)).toEqual([
          { name: 'x', type: 'bigint', readonly: false },
        ]);
        expect(tierProps(tier, `y-U.runar.ts`, TS_SEED)).toEqual([
          { name: 'p', type: 'bigint', readonly: false },
        ]);
      });

      it('lowers the Zig surface form to the TypeScript form', () => {
        expect(tierProps(tier, 'z-T.runar.zig', ZIG_SAME))
          .toEqual(tierProps(tier, 'zc-T.runar.ts', TS_SAME));
      });

      it('KEEPS the initializer the constructor never assigns', () => {
        expect(tierProps(tier, 'k-K.runar.ts', TS_KEEP)).toEqual([
          { name: 'k', type: 'bigint', readonly: false, initialValue: 5 },
          { name: 'm', type: 'bigint', readonly: false },
        ]);
      });

      it('agrees with the TypeScript tier on script hex', () => {
        const r = tier.run(write(`${tier.name}-h-T.runar.ts`, TS_SAME), ['--hex']);
        expect(r.exitCode, r.output).toBe(0);
        expect(r.output.trim()).toBe(hexOf(TS_SAME, 'T.runar.ts'));
      });
    });
  }
});
