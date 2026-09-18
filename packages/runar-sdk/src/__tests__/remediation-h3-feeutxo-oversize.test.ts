/**
 * H3 (#118): warn when a terminal-call feeUtxo dwarfs the actual fee.
 *
 * A feeUtxo is consumed ENTIRELY as fee — there is no change output, because
 * the covenant binds the exact terminal output set. An oversized feeUtxo
 * therefore silently BURNS the excess. The SDK should emit a runtime
 * console.warn when feeUtxo.satoshis significantly exceeds the terminal tx's
 * estimated fee, so the caller notices before broadcasting.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import type { UTXO } from '../types.js';

const METHOD_KEY = '00'.repeat(31) + '03';
const FUNDING_KEY = '00'.repeat(31) + '07';

const TRIVIAL_ARTIFACT: RunarArtifact = {
  version: 'runar-v0.1.0',
  compilerVersion: '0.1.0',
  contractName: 'Escrow',
  asm: '',
  buildTimestamp: '2026-03-02T00:00:00.000Z',
  script: '51', // OP_TRUE
  abi: { constructor: { params: [] }, methods: [{ name: 'settle', params: [], isPublic: true }] },
};

const CONTRACT_SATS = 50_000;
const PAYOUT = '76a914' + 'bb'.repeat(20) + '88ac';

async function setup() {
  const methodSigner = new LocalSigner(METHOD_KEY);
  // Shares #118's terminal-payout setup (fee 0 without feeUtxo) — opt out
  // of P1-2's fee floor only; Spend + conservation still run.
  //
  // M-1: that sentence used to be false in this file's own execution. The
  // `feeUtxo` each case builds inline was never registered with the
  // provider, so `allInputsKnown` was false and the conservation check was
  // skipped alongside the fee floor — leaving `expect(burnWarned(warn))` as
  // the only assertion on the whole broadcast. `registerFeeUtxo()` below
  // registers it, so conservation genuinely runs and the comment is true.
  const provider = new MockProvider('testnet', { enforceFeeFloor: false });
  const methodAddr = await methodSigner.getAddress();
  provider.addUtxo(methodAddr, {
    txid: 'cc'.repeat(32),
    outputIndex: 0,
    satoshis: 200_000,
    script: buildP2PKHScript(await methodSigner.getPublicKey()),
  });
  const contract = new RunarContract(TRIVIAL_ARTIFACT, []);
  await contract.deploy(provider, methodSigner, { satoshis: CONTRACT_SATS });
  return { methodSigner, provider, contract };
}

/**
 * Register the inline `feeUtxo` with the provider (M-1) and return it, so
 * `MockProvider.broadcast()` can run `Spend` over that input and evaluate
 * value conservation over the whole tx instead of skipping both.
 */
function registerFeeUtxo(provider: MockProvider, utxo: UTXO): UTXO {
  provider.addUtxo('fee-funder', utxo);
  return utxo;
}

/** True when a console.warn call carried the H3 burn advisory. */
function burnWarned(spy: ReturnType<typeof vi.spyOn>): boolean {
  return spy.mock.calls.some(
    (args) => typeof args[0] === 'string' && args[0].includes('feeUtxo') && args[0].includes('BURNED'),
  );
}

describe('H3 (#118): oversized feeUtxo burn warning', () => {
  afterEach(() => vi.restoreAllMocks());

  it('warns when feeUtxo.satoshis dwarfs the terminal tx fee', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { methodSigner, provider, contract } = await setup();
    const fundingSigner = new LocalSigner(FUNDING_KEY);
    const feeScript = buildP2PKHScript(await fundingSigner.getPublicKey());
    // ~30-sat real fee at the mock's 100 sat/KB rate; 500,000 sats is ~15000x.
    const feeUtxo = registerFeeUtxo(provider, {
      txid: 'ee'.repeat(32), outputIndex: 1, satoshis: 500_000, script: feeScript,
    });

    await contract.call('settle', [], provider, methodSigner, {
      terminalOutputs: [{ scriptHex: PAYOUT, satoshis: CONTRACT_SATS }],
      feeUtxo,
      fundingSigner,
    });

    expect(burnWarned(warn)).toBe(true);
  });

  it('does NOT warn when the feeUtxo is right-sized', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { methodSigner, provider, contract } = await setup();
    const fundingSigner = new LocalSigner(FUNDING_KEY);
    const feeScript = buildP2PKHScript(await fundingSigner.getPublicKey());
    // Close to the ~30-sat estimated fee — no meaningful excess burned.
    const feeUtxo = registerFeeUtxo(provider, {
      txid: 'ee'.repeat(32), outputIndex: 1, satoshis: 100, script: feeScript,
    });

    await contract.call('settle', [], provider, methodSigner, {
      terminalOutputs: [{ scriptHex: PAYOUT, satoshis: CONTRACT_SATS }],
      feeUtxo,
      fundingSigner,
    });

    expect(burnWarned(warn)).toBe(false);
  });

  it('does not warn when no feeUtxo is supplied', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { methodSigner, provider, contract } = await setup();
    await contract.call('settle', [], provider, methodSigner, {
      terminalOutputs: [{ scriptHex: PAYOUT, satoshis: CONTRACT_SATS }],
    });
    expect(burnWarned(warn)).toBe(false);
  });
});
