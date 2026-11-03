/**
 * F-024 (CL-BUG-079) — the auto-injected single-output state continuation
 * conserves no value.
 *
 * A stateful public method that mutates state without `this.addOutput(...)`
 * gets three compiler-injected witness params: `_changePKH`, `_changeAmount`
 * and `_newAmount`. The continuation assert is
 *
 *   hash256( <_newAmount LE8> ‖ codePart ‖ OP_RETURN ‖ newState
 *            ‖ [P2PKH(_changePKH), value _changeAmount] ) == hashOutputs
 *
 * and `lowerComputeStateOutput` extracts the preimage's real input amount and
 * DROPS it (05-stack-lower.ts, "Consume preimage ref (no longer needed — we use
 * _codePart and _newAmount)"). Nothing compares `_newAmount` with the input
 * value. So ANY spender who can satisfy the method body — for the `Counter`
 * example, anybody — sets
 *
 *   _newAmount    = 1
 *   _changeAmount = inputSats - 1 - fee
 *   _changePKH    = attackerPKH
 *
 * and the tx's real outputs are exactly what the script hashes: the state
 * advances correctly (count + 1, the chain survives at 1 sat) and the rest of
 * the locked value lands in the attacker's P2PKH.
 *
 * The attack tx is built by the SHIPPED TS SDK through its public call options
 * (`satoshis: 1`, `changeAddress: <attacker>`), from an attacker who owns no
 * UTXOs at all, so every sat of the change comes out of the contract. The
 * verdict comes from `@bsv/sdk`'s production `Spend` interpreter against the
 * real BIP-143 preimage (`validateContractInput`). No `TestContract`, no ANF
 * interpreter.
 *
 * Artifacts: the conformance fixture `stateful-counter`
 * (examples/ts/stateful-counter/Counter.runar.ts) compiled by each tier's own
 * compiler (TS in-process, the six native tiers via their CLIs). The parity
 * block pins that every tier emits the same script, so one verdict per tier is
 * the same verdict seven times; it is still run seven times so a tier that
 * diverges later cannot hide.
 *
 * What this proves: for each of the seven tiers, the compiled covenant accepts
 * (today) / must reject (after the fix) a spend that keeps the state chain alive
 * at 1 sat and pays the rest of the input value to an arbitrary third party.
 * The honest control (continuation keeps the full input value) is accepted, so
 * the harness is not rejecting everything.
 *
 * The rule the fix enforces (user decision R14): the compiler injects
 * `assert(_newAmount >= extractAmount(txPreimage))` into every default
 * single-output continuation. A DEPOSIT (`_newAmount > input`, the extra sats
 * paid by a funding input) must therefore stay spendable; the third block pins
 * that, so a fix that over-tightens to `== input` goes red here.
 *
 * Harness note (attempt 2): MockProvider validates every broadcast with the
 * same `Spend` interpreter, so after the fix it refuses the drain tx and
 * `contract.call` throws. `RecordingProvider` keeps that validation ON and only
 * remembers the last tx handed to `broadcast()`, so the attack's shape and the
 * independent `validateContractInput` verdict are still checked on the exact
 * bytes the SDK built.
 *
 * What this does NOT prove: anything about methods that use
 * `addOutput`/`addRawOutput` (their amounts are author-written expressions) or
 * about terminal methods (no continuation; the author owns the whole output
 * set). It does not prove any stricter business rule (e.g. TicTacToe's
 * `== input + bet`); authors state those with `continuationAmount()`.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript } from 'runar-sdk';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-f024-'));

const COUNTER_FILE = 'Counter.runar.ts';
const COUNTER_SRC = readFileSync(join(REPO, 'examples', 'ts', 'stateful-counter', COUNTER_FILE), 'utf8');

const CONTRACT_SATS = 10_000;

function requireBin(p: string, how: string): string {
  if (!existsSync(p)) throw new Error(`missing compiler binary ${p} — build it with: ${how}`);
  return p;
}

function javaJar(): string {
  const libs = join(REPO, 'compilers', 'java', 'build', 'libs');
  const jar = existsSync(libs) ? readdirSync(libs).find((f) => f.endsWith('.jar')) : undefined;
  if (!jar) throw new Error('Java jar missing — run `gradle jar` in compilers/java');
  return join(libs, jar);
}

function run(cmd: string, args: string[], cwd?: string): string {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 120_000, maxBuffer: 32 * 1024 * 1024 });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} exited ${r.status}: ${r.stderr}`);
  return r.stdout;
}

let seq = 0;
function writeTmp(fileName: string, src: string): string {
  const dir = join(TMP, String(seq++));
  mkdirSync(dir);
  const p = join(dir, fileName);
  writeFileSync(p, src);
  return p;
}

const TIERS: { name: string; artifact: () => RunarArtifact }[] = [
  {
    name: 'ts',
    artifact: () => {
      const r = compile(COUNTER_SRC, { fileName: COUNTER_FILE });
      if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
      return r.artifact as unknown as RunarArtifact;
    },
  },
  {
    name: 'go',
    artifact: () => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
      ['--source', writeTmp(COUNTER_FILE, COUNTER_SRC)],
    )),
  },
  {
    name: 'rust',
    artifact: () => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'),
      ['--source', writeTmp(COUNTER_FILE, COUNTER_SRC)],
    )),
  },
  {
    name: 'python',
    artifact: () => JSON.parse(run('python3', ['-m', 'runar_compiler', '--source', writeTmp(COUNTER_FILE, COUNTER_SRC)], join(REPO, 'compilers', 'python'))),
  },
  {
    name: 'zig',
    artifact: () => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
      ['--source', writeTmp(COUNTER_FILE, COUNTER_SRC)],
    )),
  },
  {
    name: 'ruby',
    artifact: () => JSON.parse(run('ruby', [
      '-I', join(REPO, 'compilers', 'ruby', 'lib'),
      join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'),
      '--source', writeTmp(COUNTER_FILE, COUNTER_SRC),
    ])),
  },
  {
    name: 'java',
    artifact: () => {
      const out = writeTmp('artifact.json', '');
      run('java', ['-jar', javaJar(), '--source', writeTmp(COUNTER_FILE, COUNTER_SRC), '--emit-artifact', out]);
      return JSON.parse(readFileSync(out, 'utf8'));
    },
  },
];

/**
 * MockProvider with its broadcast validation left ON that remembers the last
 * tx it was asked to broadcast, whether or not validation then refused it.
 */
class RecordingProvider extends MockProvider {
  lastAttempt: Transaction | undefined;
  override async broadcast(tx: Transaction): Promise<string> {
    this.lastAttempt = tx;
    return super.broadcast(tx);
  }
}

interface CallEvidence {
  accepted: boolean;
  /** First line of the `Spend` interpreter's error when it rejected input 0. */
  scriptError?: string;
  error?: string;
  callTx?: Transaction;
  deployTx?: Transaction;
  state?: Record<string, unknown>;
}

/**
 * The victim ('alice') deploys Counter(count = 5) holding CONTRACT_SATS, then
 * the caller ('eve') calls `increment`. `newSatoshis` is `_newAmount`;
 * `changeToPKH` is `_changePKH`. With `callerFunded = false` the caller owns NO
 * UTXOs, so every sat in the call tx's outputs came out of the contract.
 */
async function callIncrement(
  artifact: RunarArtifact,
  newSatoshis: number | undefined,
  changeToPKH: string,
  callerFunded: boolean,
): Promise<CallEvidence> {
  const victim = testKey('alice');
  const victimSigner = new LocalSigner(victim.privKey);
  const caller = new LocalSigner(testKey('eve').privKey);
  const provider = new RecordingProvider();
  provider.addUtxo(await victimSigner.getAddress(), {
    txid: victim.privKey.slice(0, 64),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(victim.pubKey),
  });
  const contract = new RunarContract(artifact, [5n]);
  await contract.deploy(provider, victimSigner, { satoshis: CONTRACT_SATS });
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  if (callerFunded) {
    const eve = testKey('eve');
    provider.addUtxo(await caller.getAddress(), {
      txid: eve.privKey.slice(0, 64),
      outputIndex: 0,
      satoshis: 50_000,
      script: buildP2PKHScript(eve.pubKey),
    });
  }

  const opts: { satoshis?: number; changeAddress: string } = { changeAddress: changeToPKH };
  if (newSatoshis !== undefined) opts.satoshis = newSatoshis;
  provider.lastAttempt = undefined;
  let error: string | undefined;
  try {
    await contract.call('increment', [], provider, caller, opts);
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }
  const attempted = provider.lastAttempt as Transaction | undefined;
  if (!attempted) return { accepted: false, error: error ?? 'no call tx was built', deployTx };
  // Round-trip through hex so the verdict runs on the serialized bytes.
  const callTx = Transaction.fromHex(attempted.toHex());
  // `Spend.validate()` throws on a script failure rather than returning false.
  let accepted: boolean;
  let scriptError: string | undefined;
  try {
    accepted = validateContractInput(callTx, 0, deployTx, 0);
  } catch (e) {
    accepted = false;
    scriptError = e instanceof Error ? e.message.split('\n')[0] : String(e);
  }
  return {
    accepted,
    ...(scriptError !== undefined ? { scriptError } : {}),
    ...(error !== undefined ? { error } : {}),
    callTx,
    deployTx,
    state: contract.state as Record<string, unknown>,
  };
}

describe('F-024 stateful-counter — all seven tiers emit one script', () => {
  it('every tier compiles Counter to the same locking-script template', () => {
    const hexes = TIERS.map((t) => [t.name, t.artifact().script] as const);
    for (const [name, hex] of hexes) expect(hex, `${name} diverges from ts`).toBe(hexes[0]![1]);
  });
});

for (const tier of TIERS) {
  describe(`F-024 [${tier.name}] — the default continuation must conserve the input value`, () => {
    const artifact = tier.artifact();
    const increment = artifact.abi.methods.find((m) => m.name === 'increment')!;
    const attacker = testKey('eve');

    it('increment carries the injected _changePKH / _changeAmount / _newAmount witness params', () => {
      const names = increment.params.map((p) => p.name);
      expect(names).toEqual(expect.arrayContaining(['_changePKH', '_changeAmount', '_newAmount', 'txPreimage']));
    });

    it('control: an honest increment that keeps the full input value is ACCEPTED', async () => {
      // The caller pays the fee from its own UTXO; the continuation keeps all
      // CONTRACT_SATS (the SDK's default _newAmount = the input's satoshis).
      const v = await callIncrement(artifact, undefined, attacker.pubKeyHash, true);
      expect(v.error, v.error).toBeUndefined();
      expect(v.accepted).toBe(true);
      expect(v.state).toEqual({ count: 6n });
      expect(v.callTx!.outputs[0]!.satoshis).toBe(CONTRACT_SATS);
    });

    it('ATTACK: _newAmount = 1, change = input - 1 - fee to the attacker is REJECTED', async () => {
      const v = await callIncrement(artifact, 1, attacker.pubKeyHash, false);
      // The drain tx must have been built exactly as described, so a rejection
      // after the fix is a script verdict, not an SDK refusal of an odd shape.
      // The only error allowed is MockProvider's own Spend-based refusal of the
      // contract input (input 0) at broadcast time.
      if (v.error !== undefined) {
        expect(v.error).toMatch(/refusing to broadcast invalid transaction \(C8\): input 0: /);
      }
      expect(v.callTx, v.error).toBeDefined();
      const tx = v.callTx!;
      expect(tx.inputs.length, 'caller owns no UTXOs: the contract is the only input').toBe(1);
      expect(tx.outputs.length).toBe(2);
      expect(tx.outputs[0]!.satoshis, '_newAmount').toBe(1);
      expect(tx.outputs[1]!.lockingScript.toHex()).toBe(buildP2PKHScript(attacker.pubKeyHash));
      const fee = CONTRACT_SATS - 1 - tx.outputs[1]!.satoshis!;
      expect(fee).toBeGreaterThan(0);
      expect(fee).toBeLessThan(1_000);
      // Before the fix the state still advances (every off-chain state check
      // is satisfied); after it, the refused broadcast leaves the state alone.
      if (v.error === undefined) expect(v.state).toEqual({ count: 6n });

      expect(
        v.accepted,
        `the covenant let ${tx.outputs[1]!.satoshis} of ${CONTRACT_SATS} sats leave the contract to ${attacker.pubKeyHash}`,
      ).toBe(false);
    });

    it('DEPOSIT: _newAmount = input + 5000, paid by the caller\'s funding input, is ACCEPTED', async () => {
      const v = await callIncrement(artifact, CONTRACT_SATS + 5_000, attacker.pubKeyHash, true);
      expect(v.error, v.error).toBeUndefined();
      expect(v.callTx!.inputs.length, 'contract input + caller funding input').toBe(2);
      expect(v.callTx!.outputs[0]!.satoshis).toBe(CONTRACT_SATS + 5_000);
      expect(v.accepted).toBe(true);
      expect(v.state).toEqual({ count: 6n });
    });
  });
}
