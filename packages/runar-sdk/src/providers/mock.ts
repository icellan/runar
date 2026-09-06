// ---------------------------------------------------------------------------
// runar-sdk/providers/mock.ts — Mock provider for testing
// ---------------------------------------------------------------------------

import { Spend, LockingScript, type Transaction } from '@bsv/sdk';
import { detachUnlockingScript } from '../spend-safety.js';
import type { Provider } from './provider.js';
import { txToTransactionData } from './provider.js';
import type { TransactionData, UTXO } from '../types.js';
import { InputLimits } from 'runar-ir-schema';
import { assertScriptHexUnderLimit } from '../errors.js';

/**
 * Deep-review finding C8 (part 2): offline validation of a transaction's
 * KNOWN inputs (script validity via @bsv/sdk's production `Spend`
 * interpreter, plus a fee-sanity check when every input is known) before
 * `MockProvider.broadcast()` acks it.
 *
 * Deliberately self-contained rather than imported from `contract.ts`'s
 * `dryRunContractInput` (same @bsv/sdk `Spend` shape, different call site):
 * that would create a `providers/mock.ts` <-> `contract.ts` dependency in
 * the wrong direction (providers are a leaf module). Keep both thin
 * wrappers in sync if `Spend`'s constructor shape ever changes.
 *
 * `otherInputs` below is the raw filtered `tx.inputs` slice, unlike
 * `dryRunContractInput`'s per-entry stubbing — see the P2 comment there for
 * why both are equivalent (only `sourceTXID`/`sourceOutputIndex`/`sequence`
 * are read off each entry by BIP-143 sighash construction).
 */
/** The outpoint key `validateBroadcastTx` looks an input up by: prefer the
 * explicit `sourceTXID` @bsv/sdk permits on an input, and fall back to
 * hashing the attached `sourceTransaction` (the shape `WalletProvider`'s EF
 * assembly and issue #107's broadcaster-injection tests use) — an input that
 * carries neither can never match a known outpoint. */
function inputOutpointKey(input: Transaction['inputs'][number]): string {
  const txid = input.sourceTXID ?? input.sourceTransaction?.id('hex');
  return `${txid}:${input.sourceOutputIndex}`;
}

function validateBroadcastTx(
  tx: Transaction,
  knownOutpoints: ReadonlyMap<string, { script: string; satoshis: number }>,
  feeRate: number,
  enforceFeeFloor: boolean,
): { valid: boolean; error?: string; validated: number; skipped: number } {
  // P2: @bsv/sdk's `Spend.isRelaxed()` returns true whenever
  // `transactionVersion > 1`, which silently disables push-only,
  // clean-stack, low-S, and minimal-number enforcement for the WHOLE spend
  // (locking-script rules are unaffected, but unlocking-script maleability
  // checks are not). Every builder in this SDK uses version 1 today, so C8
  // validation here is strict — but nothing else guards that invariant, and
  // a future version bump (e.g. for BIP-68 relative locktime) would
  // silently downgrade every check this gate performs with no signal.
  if (tx.version > 1) {
    // eslint-disable-next-line no-console
    console.warn(
      `MockProvider: broadcasting a version ${tx.version} transaction — @bsv/sdk's Spend treats ` +
        'transactionVersion > 1 as "relaxed" and skips push-only/clean-stack/low-S/minimal-number ' +
        'checks (C8/P2). Validation for this broadcast is weaker than the version-1 default.',
    );
  }

  let allInputsKnown = true;
  let totalKnownIn = 0;
  let validated = 0;
  let skipped = 0;
  let firstUnknownOutpoint: string | undefined;

  for (let i = 0; i < tx.inputs.length; i++) {
    const input = tx.inputs[i]!;
    const outpoint = inputOutpointKey(input);
    const known = knownOutpoints.get(outpoint);
    if (!known) {
      allInputsKnown = false;
      skipped++;
      if (firstUnknownOutpoint === undefined) firstUnknownOutpoint = outpoint;
      continue;
    }
    validated++;
    totalKnownIn += known.satoshis;

    const otherInputs = tx.inputs.filter((_, j) => j !== i);
    try {
      const spend = new Spend({
        sourceTXID: input.sourceTXID!,
        sourceOutputIndex: input.sourceOutputIndex,
        sourceSatoshis: known.satoshis,
        lockingScript: LockingScript.fromHex(known.script),
        transactionVersion: tx.version,
        otherInputs,
        outputs: tx.outputs,
        inputIndex: i,
        // NEW-005: `Spend` mutates the script it executes in place. `tx` is the
        // CALLER's live transaction object, so validating it must not leave it
        // unevaluable — hand `Spend` a private copy. See spend-safety.ts.
        unlockingScript: detachUnlockingScript(input.unlockingScript!),
        inputSequence: input.sequence ?? 0xffffffff,
        lockTime: tx.lockTime,
      });
      // P2: @bsv/sdk's `Spend.validate()` never actually returns `false` —
      // every failure path throws `ScriptEvaluationError` instead (see
      // `scriptEvaluationError()` in its source), so this branch is dead;
      // every rejection observed in practice exits through the `catch`
      // below. Kept as defensive belt-and-braces in case a future @bsv/sdk
      // version reverts to returning a boolean.
      if (!spend.validate()) {
        return { valid: false, error: `input ${i}: script evaluated to false`, validated, skipped };
      }
    } catch (e) {
      return {
        valid: false,
        error: `input ${i}: ${e instanceof Error ? e.message : String(e)}`,
        validated,
        skipped,
      };
    }
  }

  // P1-1: a tx with inputs that validated NONE of them is not "passing
  // validation" — it never ran a single `Spend`. Previously this fell
  // through to `{ valid: true }` because the fee check below is also gated
  // on `allInputsKnown`, so an entirely-unregistered-input broadcast was
  // acked exactly like a genuinely-validated one. Fail closed instead and
  // name the offending outpoint + how to register it.
  if (tx.inputs.length > 0 && validated === 0) {
    return {
      valid: false,
      error:
        `no inputs could be validated: ${tx.inputs.length} input(s), all unknown ` +
        `(e.g. ${firstUnknownOutpoint}) — register the funding UTXO via addUtxo() / ` +
        'addContractUtxo() / addTransaction() before broadcasting',
      validated,
      skipped,
    };
  }

  if (allInputsKnown) {
    // P1-2: an output with no satoshis value set is a bug, not a free pass
    // to spend nothing on it — `o.satoshis ?? 0` previously hid that.
    // (Realistically this is a `{ change: true }` output whose amount
    // `Transaction.fee()` was never called to compute.)
    let totalOut = 0;
    for (let i = 0; i < tx.outputs.length; i++) {
      const o = tx.outputs[i]!;
      if (o.satoshis === undefined) {
        return {
          valid: false,
          error: `output ${i}: satoshis is undefined (call tx.fee() to compute a "change" output before broadcasting)`,
          validated,
          skipped,
        };
      }
      totalOut += o.satoshis;
    }

    if (enforceFeeFloor) {
      // P1-2: conservation alone (outputs <= inputs) lets a zero-fee or
      // dust-fee tx through. Require the same fee model the SDK's own
      // builders use (`estimateDeployFee` / `estimateCallFee`):
      // ceil(txSize * feeRate / 1000).
      const txSizeBytes = tx.toHex().length / 2;
      const requiredFee = Math.ceil((txSizeBytes * feeRate) / 1000);
      const actualFee = totalKnownIn - totalOut;
      if (actualFee < requiredFee) {
        return {
          valid: false,
          error:
            `fee too low: paid ${actualFee} sats, required >= ${requiredFee} sats ` +
            `(tx size ${txSizeBytes}B @ ${feeRate} sat/KB)`,
          validated,
          skipped,
        };
      }
    } else if (totalOut > totalKnownIn) {
      return {
        valid: false,
        error: `underfunded: outputs (${totalOut} sats) exceed known inputs (${totalKnownIn} sats)`,
        validated,
        skipped,
      };
    }
  }

  return { valid: true, validated, skipped };
}

/**
 * In-memory mock provider for unit tests and local development.
 *
 * Allows injecting transactions and UTXOs, and records broadcasts for
 * assertion in tests.
 */
export class MockProvider implements Provider {
  private readonly transactions: Map<string, TransactionData> = new Map();
  private readonly rawTransactions: Map<string, string> = new Map();
  private readonly utxos: Map<string, UTXO[]> = new Map();
  private readonly contractUtxos: Map<string, UTXO> = new Map();
  private readonly broadcastedTxs: string[] = [];
  private readonly broadcastedTxObjects: Transaction[] = [];
  private readonly network: 'mainnet' | 'testnet';
  private broadcastCount = 0;
  private feeRate = 100;
  /**
   * Deep-review C8 (part 2) / testing-gap remediation Phase A1: broadcast
   * validation is default-ON. Tests that genuinely need an always-ack
   * provider must opt out explicitly (constructor `{ validateBroadcasts:
   * false }`, `disableBroadcastValidation()`, or the allowlisted
   * `newAlwaysAckMockProvider()` factory below) and are tracked by the
   * machine-checked allowlist in `always-ack-allowlist.json`.
   */
  private validateBroadcasts = true;
  /**
   * Testing-gap remediation P1-2: when `validateBroadcasts` is on and every
   * input is known, require the tx to pay at least the fee the SDK's own
   * `estimateDeployFee`/`estimateCallFee` model would (`ceil(txSize *
   * feeRate / 1000)`), not merely `outputs <= inputs`. Default-ON, distinct
   * from `validateBroadcasts`: turning this off still runs the real `Spend`
   * interpreter and the conservation check, it only stops requiring a
   * real-world fee. For tests that intentionally underpay — use
   * `disableFeeFloor()` / `{ enforceFeeFloor: false }`, named separately
   * from the always-ack escape hatches so it isn't mistaken for one.
   */
  private enforceFeeFloor = true;
  /** outpoint ("txid:vout") -> { script, satoshis } for every UTXO this
   * provider has been told about (via addUtxo/addContractUtxo/addTransaction)
   * or has itself produced via a prior broadcast(). Used by
   * `validateBroadcastTx` to check script validity / fee sanity for the
   * inputs it actually knows the value+script of. */
  private readonly knownOutpoints: Map<string, { script: string; satoshis: number }> = new Map();
  /** Cumulative counts of inputs actually run through `Spend.validate()`
   * (`validated`) vs. skipped because their outpoint was never registered
   * (`skipped`), across every `broadcast()` call made while validation was
   * enabled. See `getValidationStats()` (P1-1). */
  private validatedInputCount = 0;
  private skippedInputCount = 0;

  constructor(
    network: 'mainnet' | 'testnet' = 'testnet',
    opts?: { validateBroadcasts?: boolean; enforceFeeFloor?: boolean },
  ) {
    this.network = network;
    if (opts?.validateBroadcasts !== undefined) {
      this.validateBroadcasts = opts.validateBroadcasts;
    }
    if (opts?.enforceFeeFloor !== undefined) {
      this.enforceFeeFloor = opts.enforceFeeFloor;
    }
  }

  // -------------------------------------------------------------------------
  // Test data injection
  // -------------------------------------------------------------------------

  addTransaction(tx: TransactionData): void {
    this.transactions.set(tx.txid, tx);
    if (tx.raw) {
      this.rawTransactions.set(tx.txid, tx.raw);
    }
    for (let i = 0; i < tx.outputs.length; i++) {
      const out = tx.outputs[i]!;
      this.knownOutpoints.set(`${tx.txid}:${i}`, { script: out.script, satoshis: out.satoshis });
    }
  }

  addUtxo(address: string, utxo: UTXO): void {
    const existing = this.utxos.get(address) ?? [];
    existing.push(utxo);
    this.utxos.set(address, existing);
    this.knownOutpoints.set(`${utxo.txid}:${utxo.outputIndex}`, { script: utxo.script, satoshis: utxo.satoshis });
  }

  addContractUtxo(scriptHash: string, utxo: UTXO): void {
    this.contractUtxos.set(scriptHash, utxo);
    this.knownOutpoints.set(`${utxo.txid}:${utxo.outputIndex}`, { script: utxo.script, satoshis: utxo.satoshis });
  }

  /**
   * Toggle validation of `broadcast()`ed transactions (deep-review C8 part
   * 2): checks script validity (via @bsv/sdk's `Spend`) for every input
   * whose UTXO this provider knows about, and — when ALL inputs are known —
   * rejects a tx whose outputs exceed its inputs. `broadcast()` throws
   * instead of returning a fake txid when validation fails.
   *
   * Default is ON (testing-gap remediation Phase A1) — kept here for
   * back-compat with call sites that explicitly re-enable validation (e.g.
   * after constructing with `{ validateBroadcasts: false }`). Prefer the
   * constructor option or `disableBroadcastValidation()` for opting out.
   */
  enableBroadcastValidation(enabled = true): void {
    this.validateBroadcasts = enabled;
  }

  /**
   * Opt out of broadcast validation (testing-gap remediation Phase A1 /
   * A2): restores the legacy always-ack behaviour. Only for tests on the
   * machine-checked `always-ack-allowlist.json` — fund-path deploy/call
   * tests must not use this.
   */
  disableBroadcastValidation(): void {
    this.validateBroadcasts = false;
  }

  /**
   * Toggle the fee-floor check (testing-gap remediation P1-2) independently
   * of `validateBroadcasts`: on by default, requires the broadcast tx to pay
   * at least `ceil(txSize * feeRate / 1000)` sats when every input is known.
   */
  enableFeeFloor(enabled = true): void {
    this.enforceFeeFloor = enabled;
  }

  /**
   * Opt out of the fee-floor check only (testing-gap remediation P1-2): the
   * real `Spend` interpreter and the outputs-<=-inputs conservation check
   * still run. For tests that intentionally build a zero-fee or
   * below-market-rate tx (e.g. issue #116's exact-cover case) — distinct
   * from `disableBroadcastValidation()`, which also stops running `Spend`.
   */
  disableFeeFloor(): void {
    this.enforceFeeFloor = false;
  }

  /** Get all raw tx hexes that were broadcast through this provider. */
  getBroadcastedTxs(): readonly string[] {
    return this.broadcastedTxs;
  }

  /** Get all Transaction objects that were broadcast through this provider. */
  getBroadcastedTxObjects(): readonly Transaction[] {
    return this.broadcastedTxObjects;
  }

  /**
   * Cumulative count of inputs actually run through `Spend.validate()`
   * (`validated`) vs. inputs skipped because their outpoint was never
   * registered via `addUtxo`/`addContractUtxo`/`addTransaction` (`skipped`),
   * across every `broadcast()` call made while validation was enabled
   * (testing-gap remediation P1-1). Lets a test assert its broadcasts
   * weren't "validated" vacuously — `validated === 0` after a broadcast
   * means no script actually ran.
   */
  getValidationStats(): { validated: number; skipped: number } {
    return { validated: this.validatedInputCount, skipped: this.skippedInputCount };
  }

  // -------------------------------------------------------------------------
  // Provider implementation
  // -------------------------------------------------------------------------

  async getTransaction(txid: string): Promise<TransactionData> {
    const tx = this.transactions.get(txid);
    if (!tx) {
      throw new Error(`MockProvider: transaction ${txid} not found`);
    }
    return tx;
  }

  async broadcast(tx: Transaction): Promise<string> {
    if (this.validateBroadcasts) {
      const result = validateBroadcastTx(tx, this.knownOutpoints, this.feeRate, this.enforceFeeFloor);
      this.validatedInputCount += result.validated;
      this.skippedInputCount += result.skipped;
      if (!result.valid) {
        throw new Error(
          `MockProvider: refusing to broadcast invalid transaction (C8)${result.error ? `: ${result.error}` : ''}.`,
        );
      }
    }

    const rawTx = tx.toHex();
    this.broadcastedTxs.push(rawTx);
    this.broadcastedTxObjects.push(tx);
    this.broadcastCount++;

    // Generate a deterministic fake txid purely from the raw tx hex.
    // Same transaction → same txid (real Bitcoin semantics: txid = hash of tx bytes).
    const fakeTxid = sha256Hex(`mock-broadcast-${rawTx}`);

    // Auto-store raw hex for subsequent getRawTransaction lookups
    this.rawTransactions.set(fakeTxid, rawTx);

    // Audit finding C4: register the broadcast tx so `getTransaction()`
    // resolves it. Previously only `rawTransactions` + `knownOutpoints` were
    // populated, so `getTransaction(txid)` threw "transaction not found" for
    // a tx this provider had just acked. `RunarContract.deploy()` /
    // `finalizeCall()` caught that and returned an empty-`inputs`/`outputs`
    // shell, making every post-broadcast `result.tx.outputs` assertion in the
    // suite vacuous. Unknown txids still throw — see `getTransaction`.
    this.transactions.set(fakeTxid, txToTransactionData(fakeTxid, tx));

    // Register this tx's own outputs as known outpoints so a subsequent
    // chained call (spending the continuation this broadcast just created)
    // can also be validated.
    for (let i = 0; i < tx.outputs.length; i++) {
      const out = tx.outputs[i]!;
      this.knownOutpoints.set(`${fakeTxid}:${i}`, {
        script: out.lockingScript.toHex(),
        satoshis: out.satoshis ?? 0,
      });
    }

    return fakeTxid;
  }

  async getUtxos(address: string): Promise<UTXO[]> {
    const utxos = this.utxos.get(address) ?? [];
    // DoS-bound: reject pathological scripts from the provider layer BEFORE
    // they propagate into signature / broadcast paths.
    for (const u of utxos) {
      if (u.script) {
        assertScriptHexUnderLimit(
          u.script, InputLimits.MAX_SCRIPT_BYTES,
          `MockProvider.getUtxos(${address})`,
        );
      }
    }
    return utxos;
  }

  async getContractUtxo(scriptHash: string): Promise<UTXO | null> {
    const utxo = this.contractUtxos.get(scriptHash) ?? null;
    if (utxo && utxo.script) {
      assertScriptHexUnderLimit(
        utxo.script, InputLimits.MAX_SCRIPT_BYTES,
        `MockProvider.getContractUtxo(${scriptHash})`,
      );
    }
    return utxo;
  }

  getNetwork(): 'mainnet' | 'testnet' {
    return this.network;
  }

  async getFeeRate(): Promise<number> {
    return this.feeRate;
  }

  async getRawTransaction(txid: string): Promise<string> {
    const raw = this.rawTransactions.get(txid);
    if (raw) return raw;
    const tx = this.transactions.get(txid);
    if (!tx) {
      throw new Error(`MockProvider: transaction ${txid} not found`);
    }
    if (!tx.raw) {
      throw new Error(`MockProvider: transaction ${txid} has no raw hex`);
    }
    return tx.raw;
  }

  /** Set the fee rate returned by getFeeRate() (for testing). */
  setFeeRate(rate: number): void {
    this.feeRate = rate;
  }
}

/**
 * Convenience factory for an always-ack `MockProvider` (testing-gap
 * remediation Phase A1). `broadcast()` never validates the tx it's given.
 *
 * FOR ALLOWLISTED TESTS ONLY — every call site must have a corresponding
 * entry in `always-ack-allowlist.json` (see `always-ack-allowlist.test.ts`),
 * which fails CI for any unlisted use of this factory or the other
 * always-ack opt-outs. Fund-path deploy/call tests must not use this.
 */
export function newAlwaysAckMockProvider(network: 'mainnet' | 'testnet' = 'testnet'): MockProvider {
  return new MockProvider(network, { validateBroadcasts: false });
}

// ---------------------------------------------------------------------------
// Minimal hex sha256 for deterministic fake txids (no external deps)
// ---------------------------------------------------------------------------

function sha256Hex(input: string): string {
  // Simple deterministic hash for mock purposes — not cryptographically
  // secure. Produces a 64-char hex string that looks like a txid.
  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h0 = Math.imul(h0 ^ c, 0x01000193) >>> 0;
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ c, 0x01000193) >>> 0;
    h3 = Math.imul(h3 ^ c, 0x01000193) >>> 0;
  }
  return [h0, h1, h2, h3, h0 ^ h2, h1 ^ h3, h0 ^ h1, h2 ^ h3]
    .map((n) => (n >>> 0).toString(16).padStart(8, '0'))
    .join('');
}
