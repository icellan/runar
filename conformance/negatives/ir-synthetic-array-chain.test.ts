import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileFromANF, loadANFFromJSON } from '../../packages/runar-compiler/src/index.js';
import {
  BrokenTier,
  IR_TIER_IDS,
  REPO,
  Tier,
  buildIrTiers,
  compileHex,
} from './tier-harness.js';
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

/**
 * N-096 — one `syntheticArrayChain` validity rule on the `--ir` path, in all
 * seven tiers, with one diagnostic.
 *
 * The chain is what the expand-fixed-arrays pass attaches to each scalar leaf
 * of a FixedArray property, and what the artifact assembler consumes, one
 * level per pass, to regroup the leaves into one ABI / state entry. On `--ir`
 * it arrives from outside the compiler. The F-105 probe (basic-p2pkh plus a
 * property whose chain is 1100 levels deep) split the tiers five ways: Go
 * PANICKED in the regrouper (exit 2), Rust and Ruby refused at the regrouper's
 * 1024-pass cap, Python and Java published the property as a scalar
 * constructor parameter, Zig dropped it from the ABI, and TS (which assembles
 * no artifact on this path) compiled it.
 *
 * The rule, checked when the IR is loaded, property by property in order:
 *   1. at most 1023 levels: the regrouper's 1024 passes are the only bound the
 *      pipeline has, and a chain any deeper is one it cannot regroup;
 *   2. every level has 0 <= index < length;
 *   3. level k's base is level k-1's `<base>__<index>`, and the property is
 *      named `<innermost base>__<innermost index>` — the names the pass mints;
 *   4. the leaves sharing a root form exactly one expansion: contiguous, in
 *      row-major order from element 0, the same type and level lengths, and
 *      complete.
 * Every refusal reads
 *   IR validation: malformed syntheticArrayChain on property '<p>': <detail>
 *
 * What this does NOT prove: anything about the SOURCE path (the frontend
 * writes chains that satisfy the rule by construction; a source FixedArray
 * nested deeper than 1023 levels is not covered here), or the artifact's
 * regrouped ABI shape for accepted IR (the `--hex` lane compares bytes only).
 */

const PREFIX = 'IR validation: malformed syntheticArrayChain on property';

type Ir = {
  properties: Array<Record<string, unknown>>;
  methods: Array<Record<string, unknown>>;
  [k: string]: unknown;
};

const golden = (fixture: string): { ir: Ir; hex: string } => {
  const dir = join(REPO, 'conformance/tests', fixture);
  return {
    ir: JSON.parse(readFileSync(join(dir, 'expected-ir.json'), 'utf8')) as Ir,
    hex: readFileSync(join(dir, 'expected-script.hex'), 'utf8').trim().toLowerCase(),
  };
};

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const level = (base: string, index: number, length: number) => ({ base, index, length });

/** A property chain the pass would write for `root`, `depth` levels of length 1. */
function deepLeaf(root: string, depth: number): Record<string, unknown> {
  const chain = [];
  let base = root;
  for (let k = 0; k < depth; k++) {
    chain.push(level(base, 0, 1));
    base = `${base}__0`;
  }
  return { name: base, type: 'bigint', readonly: true, initialValue: 7, syntheticArrayChain: chain };
}

const FAI = golden('fixed-array-index');

/** fixed-array-index with `table: FixedArray<bigint, 4>` respelled as a 2x2 nested array. */
function nestedFai(): Ir {
  const rename: Record<string, string> = {
    table__0: 'table__0__0',
    table__1: 'table__0__1',
    table__2: 'table__1__0',
    table__3: 'table__1__1',
  };
  let json = JSON.stringify(FAI.ir);
  for (const [from, to] of Object.entries(rename)) json = json.split(`"${from}"`).join(`"${to}"`);
  const ir = JSON.parse(json) as Ir;
  ir.properties.forEach((p, i) => {
    const [a, b] = [Math.floor(i / 2), i % 2];
    p.syntheticArrayChain = [level('table', a, 2), level(`table__${a}`, b, 2)];
  });
  return ir;
}

/** basic-p2pkh plus the F-105 probe's `deep` property (verbatim at the default depth). */
function f105Probe(depth = 1100): Ir {
  const ir = clone(golden('basic-p2pkh').ir);
  ir.properties.splice(1, 0, {
    name: 'deep',
    type: 'bigint',
    readonly: true,
    syntheticArrayChain: Array.from({ length: depth }, () => level('deep', 0, 1)),
  });
  return ir;
}

const ACCEPT: Array<{ name: string; ir: Ir; hex: string }> = [
  { name: 'fixed-array-index golden', ir: FAI.ir, hex: FAI.hex },
  { name: 'fixed-array-write golden', ...golden('fixed-array-write') },
  { name: 'fixed-array-index as a nested 2x2 array', ir: nestedFai(), hex: FAI.hex },
  {
    name: 'fixed-array-index plus a 1023-level chain (the bound)',
    ir: (() => {
      const ir = clone(FAI.ir);
      ir.properties.push(deepLeaf('deep', 1023));
      return ir;
    })(),
    hex: FAI.hex,
  },
];

interface Case {
  name: string;
  ir: Ir;
  error: string;
}

const mutate = (base: Ir, fn: (ir: Ir) => void): Ir => {
  const ir = clone(base);
  fn(ir);
  return ir;
};
const msg = (prop: string, detail: string) => `${PREFIX} '${prop}': ${detail}`;

const CASES: Case[] = [
  {
    name: 'f105-probe-1100-levels',
    ir: f105Probe(),
    error: msg('deep', '1100 levels exceed the limit of 1023'),
  },
  {
    name: 'probe-at-1024-levels',
    ir: f105Probe(1024),
    error: msg('deep', '1024 levels exceed the limit of 1023'),
  },
  {
    name: 'index-equals-length',
    ir: mutate(FAI.ir, (ir) => {
      ir.properties[3]!.syntheticArrayChain = [level('table', 4, 4)];
    }),
    error: msg('table__3', 'level 0 has index 4 and length 4; expand-fixed-arrays writes 0 <= index < length'),
  },
  {
    name: 'length-zero',
    ir: mutate(FAI.ir, (ir) => {
      ir.properties[0]!.syntheticArrayChain = [level('table', 0, 0)];
    }),
    error: msg('table__0', 'level 0 has index 0 and length 0; expand-fixed-arrays writes 0 <= index < length'),
  },
  {
    name: 'nested-level-base-mismatch',
    ir: mutate(nestedFai(), (ir) => {
      ir.properties[1]!.syntheticArrayChain = [level('table', 0, 2), level('table__1', 1, 2)];
    }),
    error: msg('table__0__1', "level 1 has base 'table__1'; expand-fixed-arrays writes 'table__0'"),
  },
  {
    name: 'leaf-name-mismatch',
    ir: mutate(FAI.ir, (ir) => {
      ir.properties[2]!.syntheticArrayChain = [level('table', 1, 4)];
    }),
    error: msg('table__2', "its innermost level is element 1 of 'table'; expand-fixed-arrays names that property 'table__1'"),
  },
  {
    name: 'sibling-length-mismatch',
    ir: mutate(FAI.ir, (ir) => {
      ir.properties[2]!.syntheticArrayChain = [level('table', 2, 5)];
    }),
    error: msg('table__2', "'table' expects its element 'table__2' here (type bigint, level lengths [4])"),
  },
  {
    name: 'family-starts-at-element-1',
    ir: mutate(FAI.ir, (ir) => {
      const [a, b] = [ir.properties[0]!, ir.properties[1]!];
      ir.properties[0] = b;
      ir.properties[1] = a;
    }),
    error: msg('table__1', "'table' expects its element 'table__0' here (type bigint, level lengths [4])"),
  },
  {
    name: 'family-ends-early',
    ir: mutate(FAI.ir, (ir) => {
      delete ir.properties[3]!.syntheticArrayChain;
    }),
    error: msg('table__2', "'table' ends here, before its element 'table__3'"),
  },
  {
    name: 'nested-family-ends-early',
    ir: mutate(nestedFai(), (ir) => {
      delete ir.properties[3]!.syntheticArrayChain;
    }),
    error: msg('table__1__0', "'table' ends here, before its element 'table__1__1'"),
  },
  {
    name: 'family-reopened',
    ir: mutate(FAI.ir, (ir) => {
      ir.properties.push({
        name: 'table__4',
        type: 'bigint',
        readonly: true,
        initialValue: 50,
        syntheticArrayChain: [level('table', 4, 5)],
      });
    }),
    error: msg('table__4', "'table' already ended before this property"),
  },
];

const DIR = mkdtempSync(join(tmpdir(), 'n096-ir-synthetic-array-chain-'));
const write = (name: string, ir: unknown): string => {
  const p = join(DIR, `${name}.ir.json`);
  writeFileSync(p, JSON.stringify(ir));
  return p;
};

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

const tsHex = (ir: unknown): string =>
  compileFromANF(loadANFFromJSON(JSON.stringify(ir)), { disableConstantFolding: true })
    .scriptHex.toLowerCase();

/** Run a tier's `--ir` CLI; no interpretation beyond "it ran to completion". */
function runIr(tier: Tier, input: string): { status: number; out: string; diag: string } {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...tier.argsFor(input)];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;
  if (res.error) throw new BrokenTier(`${where} could not run: ${res.error.message}`);
  if (res.signal !== null) throw new BrokenTier(`${where} killed by ${res.signal}`);
  if (res.status === null) throw new BrokenTier(`${where}: no exit status`);
  return {
    status: res.status,
    out: (res.stdout ?? '').trim(),
    diag: `${res.stderr ?? ''}\n${res.stdout ?? ''}`,
  };
}

describe('N-096: --ir syntheticArrayChain validity (all 7 tiers)', () => {
  // -- vacuity guards --------------------------------------------------------

  it('every case differs from every accepted program, and the probe is in the corpus', () => {
    const accepted = ACCEPT.map((a) => JSON.stringify(a.ir));
    for (const c of CASES) {
      expect(accepted, c.name).not.toContain(JSON.stringify(c.ir));
      expect(c.error.startsWith(PREFIX), c.name).toBe(true);
    }
    expect(CASES.map((c) => c.name)).toContain('f105-probe-1100-levels');
  });

  it('the matrix names all six IR-capable CLI tiers', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (isCiEnv(process.env)) expect(missing).toEqual([]);
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  // -- accepted programs: the golden bytes in all seven tiers -----------------

  for (const a of ACCEPT) {
    it(`all tiers compile ${a.name} to the golden bytes`, () => {
      expect(tsHex(a.ir)).toBe(a.hex);
      const input = write(a.name.replace(/[^a-z0-9]+/gi, '-'), a.ir);
      for (const tier of available) {
        expect(compileHex(tier, input), `${tier.id} on ${a.name}`).toBe(a.hex);
      }
    });
  }

  // -- TypeScript: in process -------------------------------------------------

  for (const c of CASES) {
    it(`ts refuses ${c.name} with the shared diagnostic`, () => {
      let message = '<accepted>';
      try {
        tsHex(c.ir);
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toBe(c.error);
    });
  }

  // -- the six --ir CLIs -------------------------------------------------------

  for (const tier of available) {
    for (const c of CASES) {
      it(`${tier.id} refuses ${c.name} with the shared diagnostic, without crashing`, () => {
        const { status, out, diag } = runIr(tier, write(c.name, c.ir));
        expect(status, `${tier.id} accepted ${c.name} (emitted "${out.slice(0, 80)}")`).not.toBe(0);
        // A panic / uncaught exception is not a refusal: Go exited 2 here.
        expect(diag).not.toMatch(/panic|Traceback|Exception in thread|stack backtrace/);
        expect(diag).toContain(c.error);
      });
    }
  }
});
