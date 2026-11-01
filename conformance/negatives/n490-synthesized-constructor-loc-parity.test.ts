import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BrokenTier, REPO, Tier, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-490 — a constructor the surface does not let you write is anchored at the
 * contract declaration, not at a fake `1:0`.
 *
 * `.runar.go`, `.runar.rs` and `.runar.move` have no constructor syntax, a
 * `.runar.sol` contract may omit its `constructor`, and a `.runar.zig` contract
 * either omits `init` or writes one whose `super(...)` call and property
 * assignments (`return .{ .f = v }`) are implied. In all those cases the
 * parsers synthesized the constructor statements at line 1, column 0, which is
 * not a source position, and the tiers did not even agree on that (1:1 here,
 * the `init` return statement there, no column at all elsewhere).
 *
 * The anchor (TS reference, user decision R193): the token that names the
 * declaration's kind — the `struct` keyword of the contract struct on
 * `.runar.go` (`type X struct`), `.runar.rs` (`pub struct X`, after any
 * `#[runar::contract]` attribute), `.runar.move` (`resource struct X`) and
 * `.runar.zig` (`pub const X = struct`), and the `contract` keyword on
 * `.runar.sol`. One keyword token per surface: no optional modifier (`pub`,
 * `resource`, an attribute) moves it. A written Zig `init` keeps its own
 * position for the constructor node; only the statements it implies move.
 *
 * Two channels, because no single one reaches every tier:
 *  - the artifact's ANF constructor bindings (`anf.methods[constructor].body[].sourceLoc`):
 *    TS, Go, Zig and Java emit it with 0-based columns. Rust emits every ANF
 *    column 1-based (all bindings, not just these — pre-existing, not this
 *    item), so its row is the same line and column + 1. Python and Ruby emit
 *    no `sourceLoc` on any ANF binding (pre-existing, not this item).
 *  - the `StatefulSmartContract has no mutable properties` warning, which every
 *    validator anchors at the constructor: Go, Rust, Python, Ruby and Java
 *    print its `file:line:col`; the TS and Zig CLIs print warnings without a
 *    location (pre-existing, not this item).
 * Every expected position below is pinned literally from the source text,
 * never copied from a compiler's output.
 *
 * What this proves: for each fixture, every tier that exposes a constructor
 * location through either channel reports the declaration keyword's
 * line:column (the `init` position for the Zig `init` warning), and the
 * tiers that do not expose one are pinned as such, so a tier that starts or
 * stops emitting one fails here.
 * What it does NOT prove: the Python and Ruby ANF anchors (unobservable in
 * their artifact; their parsers are fixed alongside and covered by the
 * warning channel only); the TS / Zig warning anchor (no location printed);
 * fold-on artifacts; a Zig `init` that does not end in `return .{ ... }`.
 * (N-501: the Zig tier used to refuse a `.runar.zig` contract with no `init`;
 * it now synthesizes the constructor from the field list like TS, and the
 * last test pins the all-tier verdict and bytes.)
 */

const TIERS = buildSourceTiers();
const OUT = mkdtempSync(join(tmpdir(), 'n490-ctor-loc-'));

/** A stateful contract with only a readonly property and no constructor. */
const NO_CTOR_SOL = `pragma runar ^0.1.0;

contract NoCtor is StatefulSmartContract {
    PubKey immutable owner;

    function claim(Sig sig) public {
        require(checkSig(sig, this.owner));
    }
}
`;

/** The same on `.runar.zig` with no \`init\`. */
const NO_INIT_ZIG = `const runar = @import("runar");

pub const NoInit = struct {
    pub const Contract = runar.StatefulSmartContract;

    owner: runar.PubKey,

    pub fn claim(self: *const NoInit, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.owner));
    }
};
`;

function crafted(name: string, text: string): string {
  const dir = join(OUT, name.replace(/\W/g, '_'));
  mkdirSync(dir, { recursive: true });
  const file = join(dir, name);
  writeFileSync(file, text);
  return file;
}

const ex = (p: string): string => join(REPO, 'examples', p);

interface Case {
  file: string;
  /** Declaration keyword, `line:0-based column`. */
  decl: string;
  /** Where the constructor-anchored warning is printed (the decl unless an `init` is written). */
  warn: string | null;
}

const CASES: Case[] = [
  { file: ex('go/all-readonly-cleanstack/AllReadonlyCleanstack.runar.go'), decl: '32:27', warn: '32:27' },
  { file: ex('rust/all-readonly-cleanstack/AllReadonlyCleanstack.runar.rs'), decl: '13:0', warn: '13:0' },
  // `pub struct`: the anchor is `struct`, not `pub`. Stateful with a mutable
  // field, so no warning.
  { file: ex('rust/stateful-counter/Counter.runar.rs'), decl: '28:4', warn: null },
  { file: ex('move/all-readonly-cleanstack/AllReadonlyCleanstack.runar.move'), decl: '15:13', warn: '15:13' },
  // A written `init` (line 17) returning `.{ .owner = owner }`: the
  // constructor node is the `init`, the implied super() and assignment
  // statements are at the declaration.
  { file: ex('zig/all-readonly-cleanstack/AllReadonlyCleanstack.runar.zig'), decl: '12:34', warn: '17:4' },
  { file: crafted('NoCtor.runar.sol', NO_CTOR_SOL), decl: '3:0', warn: '3:0' },
];

const NO_INIT_ZIG_CASE: Case = { file: crafted('NoInit.runar.zig', NO_INIT_ZIG), decl: '3:19', warn: '3:19' };

/** Per-tier argv that writes the full artifact JSON (as artifact-flag-parity.test.ts). */
function compileArtifact(tier: Tier, src: string): Record<string, any> {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  let args: string[];
  let file: string | null = null;
  if (tier.id === 'ts') {
    file = mkdtempSync(join(OUT, 'ts-'));
    args = [src, '-o', file, '--disable-constant-folding'];
  } else if (tier.id === 'zig') {
    args = ['compile', src];
  } else if (tier.id === 'java') {
    file = join(mkdtempSync(join(OUT, 'java-')), 'artifact.json');
    args = ['--source', src, '--emit-artifact', file];
  } else {
    args = ['--source', src];
  }
  const argv = [...tier.prefix, ...args];
  const res = spawnSync(tier.cmd, argv, { cwd: tier.cwd, encoding: 'utf-8', timeout: tier.timeoutMs, maxBuffer: 64 * 1024 * 1024 });
  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;
  if (res.error) throw new BrokenTier(`${where} could not run: ${res.error.message}`);
  if (res.status !== 0) throw new BrokenTier(`${where} exited ${res.status}: ${`${res.stderr}\n${res.stdout}`.slice(0, 600)}`);
  let text = res.stdout ?? '';
  if (tier.id === 'ts') {
    const jsons = readdirSync(file!).filter((f) => f.endsWith('.json'));
    if (jsons.length !== 1) throw new BrokenTier(`${where} wrote ${jsons.length} artifacts`);
    text = readFileSync(join(file!, jsons[0]!), 'utf8');
  } else if (file !== null) {
    text = readFileSync(file, 'utf8');
  }
  return JSON.parse(text) as Record<string, any>;
}

/** The distinct `line:col` of the constructor's ANF bindings (`null` = none carries one). */
function ctorAnfLocs(artifact: Record<string, any>): Array<string | null> {
  const ctor = (artifact.anf?.methods as Array<Record<string, any>> | undefined)?.find((m) => m.name === 'constructor');
  if (ctor === undefined) throw new Error('artifact carries no ANF constructor');
  const body = ctor.body as Array<{ sourceLoc?: { line: number; column: number } }>;
  expect(body.length).toBeGreaterThan(0);
  return [...new Set(body.map((b) => (b.sourceLoc ? `${b.sourceLoc.line}:${b.sourceLoc.column}` : null)))];
}

/** What each tier must report on the ANF channel for a declaration at `decl`. */
function expectedAnf(tierId: string, decl: string): Array<string | null> {
  if (tierId === 'python' || tierId === 'ruby') return [null];
  if (tierId === 'rust') {
    const [l, c] = decl.split(':').map(Number);
    return [`${l}:${c! + 1}`];
  }
  return [decl];
}

const WARNING = 'StatefulSmartContract has no mutable properties';

/** The `L:C` printed in front of the warning, `null` when it carries none. */
function warningLoc(diag: string, fileName: string): string | null {
  const line = diag.split('\n').find((l) => l.includes(WARNING));
  if (line === undefined) throw new Error(`no ${JSON.stringify(WARNING)} warning in:\n${diag.slice(0, 600)}`);
  const esc = fileName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = line.match(new RegExp(`${esc}:(\\d+)(?::(\\d+))?:`));
  if (m === null) return null;
  return `${m[1]}:${m[2] ?? '<none>'}`;
}

function expectedWarn(tierId: string, warn: string): string | null {
  return tierId === 'ts' || tierId === 'zig' ? null : warn;
}

const base = (f: string): string => f.split('/').pop()!;

describe('N-490: a synthesized constructor is anchored at the contract declaration in every tier', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const c of [...CASES, NO_INIT_ZIG_CASE]) {
    const tiers = TIERS;
    it(`${base(c.file)}: ANF constructor bindings at ${c.decl}`, () => {
      const got = Object.fromEntries(tiers.map((t) => [t.id, ctorAnfLocs(compileArtifact(t, c.file))]));
      expect(got).toEqual(Object.fromEntries(tiers.map((t) => [t.id, expectedAnf(t.id, c.decl)])));
    }, 900_000);

    if (c.warn !== null) {
      const warn = c.warn;
      it(`${base(c.file)}: constructor-anchored warning at ${warn}`, () => {
        const got: Record<string, string | null> = {};
        for (const tier of tiers) {
          const r = judge(tier, c.file);
          expect(r.verdict, `${tier.id} must accept ${base(c.file)}`).toBe('accepted');
          got[tier.id] = warningLoc(r.diag, base(c.file));
        }
        expect(got).toEqual(Object.fromEntries(tiers.map((t) => [t.id, expectedWarn(t.id, warn)])));
      }, 900_000);
    }
  }

  /**
   * N-501: a `.runar.zig` StatefulSmartContract with no `init` is accepted by
   * every tier, and every tier emits the same locking script for it. TS (the
   * reference, `createFallbackConstructor` in 01-parse-zig.ts) synthesizes
   * `constructor(owner) { super(owner); this.owner = owner; }` from the
   * fields without an initializer — every property is assigned from a
   * constructor argument, so acceptance is sound. Zig used to build an empty
   * constructor and its validator then refused with "property must be
   * assigned in the constructor".
   * Proves: same accept verdict and byte-identical script hex (fold-off) in
   * all seven tiers. Does not prove: fold-on output, a no-`init` contract
   * with a defaulted field (the TS rule excludes it from the parameters; the
   * Zig unit test in parse_zig.zig pins that shape), on-chain execution.
   */
  it('NoInit.runar.zig: all seven tiers accept it with identical script hex', () => {
    const hex = Object.fromEntries(TIERS.map((t) => [t.id, compileArtifact(t, NO_INIT_ZIG_CASE.file).script as string]));
    const ts = hex.ts!;
    expect(ts).toMatch(/^[0-9a-f]+$/);
    expect(hex).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, ts])));
  }, 900_000);
});
