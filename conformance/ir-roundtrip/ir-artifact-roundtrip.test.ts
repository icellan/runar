import { describe, it, expect, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compile, loadANFFromJSON } from '../../packages/runar-compiler/src/index.js';
import { validateANF } from '../../packages/runar-ir-schema/src/index.js';
import type { RunarArtifact } from '../../packages/runar-ir-schema/src/index.js';
import { RunarContract } from '../../packages/runar-sdk/src/contract.js';
import { MockProvider } from '../../packages/runar-sdk/src/providers/mock.js';
import { LocalSigner } from '../../packages/runar-sdk/src/signers/local.js';
import { buildP2PKHScript } from '../../packages/runar-sdk/src/script-utils.js';
import { BrokenTier, IR_TIER_IDS, REPO, Tier, buildSourceTiers } from '../negatives/tier-harness.js';

/**
 * F-038 (+ F-065, F-066, F-070, F-088) — `--emit-ir` -> `--ir` is lossless.
 *
 * The defect: `parentClass` and a method's `@sighash` mode lived on every
 * tier's in-memory ANF only (Go `json:"-"`, Rust `serde(skip)`, Python/Ruby/
 * Java exclusion lists), so a program written with `--emit-ir` and compiled
 * by a second process with `--ir` produced the same script but an artifact
 * WITHOUT `parentClass` (Zig: with the wrong one, `SmartContract`) and
 * WITHOUT `abi.methods[].sigHashType`. The SDK reads both to sign:
 *   - no parentClass -> it falls back to `stateFields non-empty`, which is
 *     false for a StatefulSmartContract with zero mutable fields, so it signs
 *     the FULL script instead of the issue-#44 OP_CODESEPARATOR subscript and
 *     the user's checkSig fails on chain;
 *   - no sigHashType -> it builds an ALL|FORKID preimage for a covenant that
 *     asserts ALL|ANYONECANPAY|FORKID, and the covenant fails on chain.
 *
 * What this proves, for each of the six `--ir` tiers on five probes (stateful
 * with zero mutable fields, stateful FixedArray, stateful non-default sighash,
 * stateless non-default sighash, UnsafeSmartContract): the emitted IR is valid
 * against the canonical schema and carries both keys; the `--ir` artifact
 * equals the direct `--source` artifact on script, parentClass, abi and
 * stateFields; and the two SDK-visible harms above are gone — the TS SDK
 * spends each tier's `--ir` artifact under MockProvider's strict `Spend`.
 * For TS, which has no artifact-producing `--ir` CLI, the ANF it emits carries
 * both keys and survives `loadANFFromJSON`.
 *
 * What it does not prove: every fixture (`conformance/runner --ir-roundtrip`
 * sweeps all of them), or anything about artifact fields this item did not
 * touch (Java's artifact still does not regroup FixedArray leaves on EITHER
 * path, so its direct and `--ir` stateFields agree with each other only).
 */

const HERE = __dirname;
const PROBES: { file: string; parentClass: string; sigHash?: Record<string, number> }[] = [
  { file: join(REPO, 'examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts'), parentClass: 'StatefulSmartContract' },
  { file: join(REPO, 'examples/ts/fixed-array-write/ArrayWrite.runar.ts'), parentClass: 'StatefulSmartContract' },
  { file: join(REPO, 'examples/ts/asm-raw-script/Anyone.runar.ts'), parentClass: 'UnsafeSmartContract' },
  { file: join(HERE, 'SighashSingle.runar.ts'), parentClass: 'SmartContract', sigHash: { unlock: 0x43 } },
  { file: join(HERE, 'SighashCounter.runar.ts'), parentClass: 'StatefulSmartContract', sigHash: { increment: 0xc1 } },
];

const DIR = mkdtempSync(join(tmpdir(), 'f038-ir-roundtrip-'));
afterAll(() => rmSync(DIR, { recursive: true, force: true }));

const TIERS: Tier[] = buildSourceTiers().filter((t) => t.id !== 'ts');
const available = TIERS.filter((t) => t.cmd !== null);

function run(tier: Tier, args: string[]): string {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...args];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;
  if (res.error) throw new BrokenTier(`${where} could not run: ${res.error.message}`);
  if (res.status !== 0) throw new Error(`${where} exited ${res.status}: ${res.stderr}`);
  return res.stdout;
}

/** The artifact JSON a tier writes for `--source <f>` or for `--ir <f>`. */
function artifact(tier: Tier, mode: 'source' | 'ir', input: string, out: string): RunarArtifact {
  if (tier.id === 'java') {
    // Java prints IR on stdout by default; its artifact goes to --emit-artifact.
    run(tier, [mode === 'source' ? '--source' : '--ir', input, '--emit-artifact', out]);
    return JSON.parse(readFileSync(out, 'utf-8')) as RunarArtifact;
  }
  const args =
    mode === 'source'
      ? ['--source', input]
      : tier.id === 'zig'
        ? ['compile-ir', input]
        : ['--ir', input];
  return JSON.parse(run(tier, args)) as RunarArtifact;
}

interface RoundTrip {
  direct: RunarArtifact;
  viaIr: RunarArtifact;
  ir: Record<string, unknown>;
}

const cache = new Map<string, RoundTrip>();
function roundTrip(tier: Tier, file: string): RoundTrip {
  const key = `${tier.id}:${file}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const stem = join(DIR, `${tier.id}-${file.split('/').pop()!.replace('.runar.ts', '')}`);
  const direct = artifact(tier, 'source', file, `${stem}.direct.json`);
  const irText = run(tier, ['--source', file, '--emit-ir']);
  writeFileSync(`${stem}.ir.json`, irText);
  const viaIr = artifact(tier, 'ir', `${stem}.ir.json`, `${stem}.via-ir.json`);
  const result = { direct, viaIr, ir: JSON.parse(irText) as Record<string, unknown> };
  cache.set(key, result);
  return result;
}

type IrMethod = { name: string; sigHashType?: number };

/** The sigHashType a probe's method must carry (`constructor` is a method name here). */
function expectedSigHash(probe: (typeof PROBES)[number], method: string): number | undefined {
  return probe.sigHash && Object.hasOwn(probe.sigHash, method) ? probe.sigHash[method] : undefined;
}

describe('F-038: --emit-ir -> --ir reproduces the --source artifact', () => {
  it('every --ir tier is built (strict in CI, ">=2" locally)', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...IR_TIER_IDS].sort());
    if (process.env.CI === 'true') expect(TIERS.filter((t) => t.cmd === null)).toEqual([]);
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  // -- TS: the reference emits the keys and its loader keeps them ------------
  for (const probe of PROBES) {
    const name = probe.file.split('/').pop()!;
    it(`ts: ${name} ANF carries parentClass and sigHashType through loadANFFromJSON`, () => {
      const result = compile(readFileSync(probe.file, 'utf-8'), { fileName: probe.file });
      expect(result.success, JSON.stringify(result.diagnostics)).toBe(true);
      const anf = result.anf!;
      expect(validateANF(JSON.parse(JSON.stringify(anf, (_k, v) => (typeof v === 'bigint' ? Number(v) : v)))).valid).toBe(true);
      const reloaded = loadANFFromJSON(JSON.stringify(anf, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v)));
      for (const p of [anf, reloaded]) {
        expect(p.parentClass).toBe(probe.parentClass);
        expect(p.parentClass).toBe(result.artifact!.parentClass);
        for (const m of p.methods) expect(m.sigHashType, m.name).toBe(expectedSigHash(probe, m.name));
      }
    });
  }

  // -- the six --ir tiers ----------------------------------------------------
  for (const tier of available) {
    for (const probe of PROBES) {
      const name = probe.file.split('/').pop()!;

      it(`${tier.id}: ${name} --emit-ir is schema-valid and carries both keys`, () => {
        const { ir, direct } = roundTrip(tier, probe.file);
        const v = validateANF(ir);
        expect(v.valid ? [] : v.errors).toEqual([]);
        expect(ir.parentClass).toBe(probe.parentClass);
        expect(direct.parentClass).toBe(probe.parentClass);
        for (const m of ir.methods as IrMethod[]) {
          expect(m.sigHashType, m.name).toBe(expectedSigHash(probe, m.name));
        }
      });

      it(`${tier.id}: ${name} --ir artifact equals the --source artifact`, () => {
        const { direct, viaIr } = roundTrip(tier, probe.file);
        expect(viaIr.script).toBe(direct.script);
        expect(viaIr.parentClass).toBe(direct.parentClass);
        expect(viaIr.abi).toEqual(direct.abi);
        expect(viaIr.stateFields).toEqual(direct.stateFields);
        for (const [method, flag] of Object.entries(probe.sigHash ?? {})) {
          expect(direct.abi.methods.find((m) => m.name === method)?.sigHashType).toBe(flag);
        }
      });
    }
  }

  // -- F-070: the SDK spends each tier's --ir artifact -----------------------

  const PRIV = '0000000000000000000000000000000000000000000000000000000000000001';
  async function funded() {
    const signer = new LocalSigner(PRIV);
    const pubKeyHex = await signer.getPublicKey();
    // Fee floor off: the SDK under-pays the 100 sat/KB relay floor on a
    // zero-mutable-field StatefulSmartContract call (57 of 99 sats, on the
    // --source artifact too: a separate SDK fee-estimation gap, not this
    // item). Script validation under strict Spend is unaffected.
    const provider = new MockProvider('testnet', { enforceFeeFloor: false });
    provider.addUtxo(await signer.getAddress(), {
      txid: 'aa'.repeat(32),
      outputIndex: 0,
      satoshis: 1_000_000,
      script: buildP2PKHScript(pubKeyHex),
    });
    return { signer, provider, pubKeyHex };
  }

  // A StatefulSmartContract with zero mutable fields has empty stateFields, so
  // the SDK treats its txPreimage as a caller arg (null = SDK-computed).
  async function spendZeroMutable(art: RunarArtifact) {
    const { signer, provider, pubKeyHex } = await funded();
    const contract = new RunarContract(art, [pubKeyHex]);
    await contract.deploy(provider, signer, { satoshis: 50_000 });
    // MockProvider validates every broadcast with @bsv/sdk Spend (strict).
    return contract.call('claim', [null, null], provider, signer);
  }
  async function spendCounter(art: RunarArtifact) {
    const { signer, provider } = await funded();
    const contract = new RunarContract(art, [0n]);
    await contract.deploy(provider, signer, { satoshis: 50_000 });
    return contract.call('increment', [], provider, signer);
  }
  const TXID = { txid: expect.stringMatching(/^[0-9a-f]{64}$/) };

  for (const tier of available) {
    it(`${tier.id}: control - the --source artifacts spend (else the --ir checks are vacuous)`, async () => {
      await expect(spendZeroMutable(roundTrip(tier, PROBES[0]!.file).direct)).resolves.toMatchObject(TXID);
      await expect(spendCounter(roundTrip(tier, PROBES[4]!.file).direct)).resolves.toMatchObject(TXID);
    });

    it(`${tier.id}: the --ir artifact of a zero-mutable-field StatefulSmartContract spends (issue-#44 trim)`, async () => {
      const { viaIr } = roundTrip(tier, PROBES[0]!.file);
      expect(viaIr.stateFields ?? []).toEqual([]);
      await expect(spendZeroMutable(viaIr)).resolves.toMatchObject(TXID);
    });

    it(`${tier.id}: the --ir artifact of an ALL|ANYONECANPAY|FORKID covenant spends`, async () => {
      await expect(spendCounter(roundTrip(tier, PROBES[4]!.file).viaIr)).resolves.toMatchObject(TXID);
    });
  }
});
