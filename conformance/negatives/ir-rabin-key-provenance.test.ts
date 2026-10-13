import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compile, compileFromANF, loadANFFromJSON } from '../../packages/runar-compiler/src/index.js';
import { BrokenTier, IR_TIER_IDS, REPO, Tier, buildIrTiers, compileHex } from './tier-harness.js';

/**
 * N-205 (b) — verifyRabinSig key provenance on the `--ir` path, in all seven
 * tiers, with one diagnostic per rule.
 *
 * F-286 made the frontend refuse a spender-chosen Rabin modulus, and N-205 (a)
 * a spender-chosen write into a mutable key property. `--ir` skips the
 * frontend, so before this an ANF program whose verifyRabinSig 4th argument is
 * a `load_param` — the spender passes n = 1, sig = 0 and forges any message —
 * compiled in every tier, as did one whose `update_prop` / `add_output` slot
 * put a `load_param` into the key the next spend verifies against.
 *
 * The loader rule (packages/runar-compiler/src/ir/rabin-key-provenance.ts) is
 * F-286's trust relation on ANF: `load_prop`, an integer `load_const`, a
 * `load_const "@ref:x"` alias of a trusted ref, or a private method's
 * `load_param` that every `method_call` site binds to a trusted ref. So the
 * frontend's own output for the helper / alias / literal-write shapes still
 * loads (ACCEPT below, hex compared across all tiers).
 *
 * What this proves: every tier refuses each hostile IR below with the shared
 * diagnostic and without crashing, and compiles each accepted IR to the same
 * bytes as TS.
 * What it does NOT prove: anything about the source path (each tier's N-205 /
 * F-286 frontend tests and conformance/negatives N240–N242 cover that), or
 * that an accepted program's key is a strong one.
 */

const RABIN_PUBKEY =
  'verifyRabinSig public key (4th argument) must be a contract property or a literal; ' +
  'a spender-supplied Rabin modulus lets anyone forge a signature';
const keyWrite = (prop: string) =>
  `verifyRabinSig public key property '${prop}' may only be assigned a contract property or a literal ` +
  'outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature';
const refuse = (method: string, detail: string) => `IR validation: method '${method}': ${detail}`;

type Binding = { name: string; value: Record<string, unknown> };
type Method = { name: string; params: Array<{ name: string; type: string }>; body: Binding[]; isPublic: boolean };
type Ir = { properties: Array<Record<string, unknown>>; methods: Method[]; [k: string]: unknown };

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const mutate = (base: Ir, fn: (ir: Ir) => void): Ir => {
  const ir = clone(base);
  fn(ir);
  return ir;
};
const method = (ir: Ir, name: string): Method => ir.methods.find((m) => m.name === name)!;
const binding = (m: Method, name: string): Binding => {
  const b = m.body.find((x) => x.name === name);
  if (!b) throw new Error(`no binding ${name} in ${m.name}`);
  return b;
};

/** The frontend's own fold-OFF ANF for `source`, as wire JSON (bigints as numbers). */
function irOf(source: string, fileName: string): Ir {
  const r = compile(source, { fileName, disableConstantFolding: true });
  if (!r.success || !r.anf) throw new Error(`${fileName}: ${r.diagnostics.map((d) => d.message).join('; ')}`);
  const json = JSON.stringify(r.anf, (k, v: unknown) => {
    if (k === 'sourceLoc') return undefined;
    if (typeof v === 'bigint') {
      if (v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(v);
      return `${v}n`;
    }
    return v;
  });
  return JSON.parse(json) as Ir;
}

const ORACLE: Ir = JSON.parse(
  readFileSync(join(REPO, 'conformance/tests/oracle-price/expected-ir.json'), 'utf8'),
) as Ir;
const ORACLE_HEX = readFileSync(join(REPO, 'conformance/tests/oracle-price/expected-script.hex'), 'utf8')
  .trim()
  .toLowerCase();

/** Stateless: the key reaches verifyRabinSig through a const alias and a private helper. */
const HELPER = irOf(
  `
import { SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class RabinHelper extends SmartContract {
  readonly pk: RabinPubKey;

  constructor(pk: RabinPubKey) {
    super(pk);
    this.pk = pk;
  }

  private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString, n: bigint) {
    const kk = this.pk;
    assert(this.check(msg, sig, padding, kk));
    assert(n > 0n);
  }
}
`,
  'RabinHelper.runar.ts',
);

/** Stateful: a mutable key property, rewritten from a readonly property. */
const ROTATE = irOf(
  `
import { StatefulSmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class RabinRotate extends StatefulSmartContract {
  key: RabinPubKey;
  count: bigint;
  readonly backup: RabinPubKey;

  constructor(key: RabinPubKey, count: bigint, backup: RabinPubKey) {
    super(key, count, backup);
    this.key = key;
    this.count = count;
    this.backup = backup;
  }

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {
    assert(verifyRabinSig(msg, sig, padding, this.key));
  }

  public rotate(newKey: RabinPubKey) {
    this.key = this.backup;
    this.count = this.count + newKey;
    assert(true);
  }
}
`,
  'RabinRotate.runar.ts',
);

/** Stateful: the key carried into the next output through addOutput. */
const CARRY = irOf(
  `
import { StatefulSmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class RabinCarry extends StatefulSmartContract {
  key: RabinPubKey;
  count: bigint;

  constructor(key: RabinPubKey, count: bigint) {
    super(key, count);
    this.key = key;
    this.count = count;
  }

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {
    assert(verifyRabinSig(msg, sig, padding, this.key));
  }

  public carry(newKey: RabinPubKey) {
    this.addOutput(1000n, this.key, this.count + newKey);
    assert(true);
  }
}
`,
  'RabinCarry.runar.ts',
);

/** Stateless: a literal key, and a let-alias rebound in an if-arm (F-286 accepts both). */
const LITERAL_AND_ALIAS = irOf(
  `
import { SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class RabinAlias extends SmartContract {
  readonly pk: RabinPubKey;
  readonly pk2: RabinPubKey;

  constructor(pk: RabinPubKey, pk2: RabinPubKey) {
    super(pk, pk2);
    this.pk = pk;
    this.pk2 = pk2;
  }

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {
    let k = this.pk;
    if (sig > 0n) {
      k = this.pk2;
    }
    assert(verifyRabinSig(msg, sig, padding, k));
    assert(verifyRabinSig(msg, sig, padding, 1000003n));
  }
}
`,
  'RabinAlias.runar.ts',
);

/** Stateful: key writes inside if-arms — the if/else phi form and the multi-write arm. */
const IF_WRITES = irOf(
  `
import { StatefulSmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class RabinIfWrite extends StatefulSmartContract {
  key: RabinPubKey;
  count: bigint;
  readonly backup: RabinPubKey;

  constructor(key: RabinPubKey, count: bigint, backup: RabinPubKey) {
    super(key, count, backup);
    this.key = key;
    this.count = count;
    this.backup = backup;
  }

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {
    assert(verifyRabinSig(msg, sig, padding, this.key));
  }

  public phi(n: bigint) {
    if (n > 0n) {
      this.key = 5n;
    } else {
      this.key = this.backup;
    }
    assert(true);
  }

  public multi(n: bigint) {
    let k = this.backup;
    if (n > 0n) {
      this.count = n;
      k = this.key;
      this.key = 5n;
    }
    this.key = k;
    assert(true);
  }
}
`,
  'RabinIfWrite.runar.ts',
);

/** The binding a method's `update_prop <prop>` writes. */
function updateValue(m: Method, prop: string): Binding {
  const up = m.body.find((b) => b.value.kind === 'update_prop' && b.value.name === prop)!;
  return binding(m, up.value.value as string);
}

const ACCEPT: Array<{ name: string; ir: Ir }> = [
  { name: 'oracle-price golden', ir: ORACLE },
  { name: 'key through a const alias and a private helper', ir: HELPER },
  { name: 'mutable key rewritten from a readonly property', ir: ROTATE },
  { name: 'mutable key carried in its addOutput slot', ir: CARRY },
  { name: 'literal key and a let-alias rebound in an if-arm', ir: LITERAL_AND_ALIAS },
  { name: 'mutable key written inside if-arms', ir: IF_WRITES },
];

interface Case {
  name: string;
  ir: Ir;
  error: string;
}

const CASES: Case[] = [
  {
    // The F-286 attack, on IR: the spender passes the modulus.
    name: 'key-is-public-load-param',
    ir: mutate(ORACLE, (ir) => {
      const settle = method(ir, 'settle');
      settle.params.push({ name: 'n', type: 'RabinPubKey' });
      binding(settle, 't5').value = { kind: 'load_param', name: 'n' };
    }),
    error: refuse('settle', RABIN_PUBKEY),
  },
  {
    name: 'key-is-alias-of-load-param',
    ir: mutate(ORACLE, (ir) => {
      const settle = method(ir, 'settle');
      settle.params.push({ name: 'n', type: 'RabinPubKey' });
      binding(settle, 't5').value = { kind: 'load_param', name: 'n' };
      const at = settle.body.findIndex((b) => b.name === 't5');
      settle.body.splice(at + 1, 0, { name: 'k', value: { kind: 'load_const', value: '@ref:t5' } });
      (binding(settle, 't6').value.args as string[])[3] = 'k';
    }),
    error: refuse('settle', RABIN_PUBKEY),
  },
  {
    name: 'key-is-byte-string-const',
    ir: mutate(ORACLE, (ir) => {
      binding(method(ir, 'settle'), 't5').value = { kind: 'load_const', value: '01' };
    }),
    error: refuse('settle', RABIN_PUBKEY),
  },
  {
    // The helper's call site now passes a public parameter.
    name: 'helper-call-site-passes-load-param',
    ir: mutate(HELPER, (ir) => {
      const settle = method(ir, 'settle');
      const kk = binding(settle, 'kk');
      binding(settle, (kk.value.value as string).slice(5)).value = { kind: 'load_param', name: 'n' };
    }),
    error: refuse('check', RABIN_PUBKEY),
  },
  {
    name: 'helper-never-called',
    ir: mutate(HELPER, (ir) => {
      const settle = method(ir, 'settle');
      const call = settle.body.find((b) => b.value.kind === 'method_call')!;
      // Keep the binding name the assert reads, drop the call.
      call.value = { kind: 'load_const', value: true };
    }),
    error: refuse('check', RABIN_PUBKEY),
  },
  {
    // N-205 (a) on IR: the spender writes the next modulus.
    name: 'update-prop-key-from-load-param',
    ir: mutate(ROTATE, (ir) => {
      updateValue(method(ir, 'rotate'), 'key').value = { kind: 'load_param', name: 'newKey' };
    }),
    error: refuse('rotate', keyWrite('key')),
  },
  {
    // One arm of the if/else phi now carries the spender's value.
    name: 'if-phi-arm-from-load-param',
    ir: mutate(IF_WRITES, (ir) => {
      const phi = method(ir, 'phi');
      const ifValue = updateValue(phi, 'key').value;
      const then = ifValue.then as Binding[];
      then[then.length - 1]!.value = { kind: 'load_param', name: 'n' };
    }),
    error: refuse('phi', keyWrite('key')),
  },
  {
    name: 'add-output-key-slot-from-load-param',
    ir: mutate(CARRY, (ir) => {
      const carry = method(ir, 'carry');
      const out = carry.body.find((b) => b.value.kind === 'add_output')!;
      binding(carry, (out.value.stateValues as string[])[0]!).value = { kind: 'load_param', name: 'newKey' };
    }),
    error: refuse('carry', keyWrite('key')),
  },
];

const DIR = mkdtempSync(join(tmpdir(), 'n205-ir-rabin-key-'));
const write = (name: string, ir: unknown): string => {
  const p = join(DIR, `${name}.ir.json`);
  writeFileSync(p, JSON.stringify(ir));
  return p;
};

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

const tsHex = (ir: unknown): string =>
  compileFromANF(loadANFFromJSON(JSON.stringify(ir)), { disableConstantFolding: true }).scriptHex.toLowerCase();

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
  return { status: res.status, out: (res.stdout ?? '').trim(), diag: `${res.stderr ?? ''}\n${res.stdout ?? ''}` };
}

describe('N-205 (b): --ir verifyRabinSig key provenance (all 7 tiers)', () => {
  it('every case differs from every accepted program', () => {
    const accepted = ACCEPT.map((a) => JSON.stringify(a.ir));
    for (const c of CASES) expect(accepted, c.name).not.toContain(JSON.stringify(c.ir));
  });

  it('the matrix names all seven IR-capable tiers', () => {
    expect(TIERS.map((t) => t.id).sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (process.env.CI === 'true') expect(missing).toEqual([]);
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  it('the oracle-price golden still compiles to its golden bytes on the IR path', () => {
    expect(tsHex(ORACLE)).toBe(ORACLE_HEX);
  });

  for (const a of ACCEPT) {
    it(`all tiers compile ${a.name} to the same bytes as TS`, () => {
      const hex = tsHex(a.ir);
      const input = write(a.name.replace(/[^a-z0-9]+/gi, '-'), a.ir);
      for (const tier of available) {
        expect(compileHex(tier, input), `${tier.id} on ${a.name}`).toBe(hex);
      }
    });
  }

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

  for (const tier of available) {
    for (const c of CASES) {
      it(`${tier.id} refuses ${c.name} with the shared diagnostic, without crashing`, () => {
        const { status, out, diag } = runIr(tier, write(c.name, c.ir));
        expect(status, `${tier.id} accepted ${c.name} (emitted "${out.slice(0, 80)}")`).not.toBe(0);
        expect(diag).not.toMatch(/panic|Traceback|Exception in thread|stack backtrace/);
        expect(diag).toContain(c.error);
      });
    }
  }
});
