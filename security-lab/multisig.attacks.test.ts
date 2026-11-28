import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { build, spendStateless, signFor, asm, key } from './harness.js';

const SRC = 'examples/ts/multisig-2of3/MultiSig2of3.runar.ts';
const source = readFileSync(SRC, 'utf8');

function compiled(pks: [string, string, string]) {
  return build(source, SRC, { pk1: pks[0], pk2: pks[1], pk3: pks[2] });
}

const HONEST: [string, string, string] = ['alice', 'bob', 'charlie'].map((n) => key(n).pubKey) as [string, string, string];

describe('2-of-3 MULTISIG attacks', () => {
  it('baseline: two honest sigs', () => {
    const c = compiled(HONEST);
    console.log('ASM:', asm(c.scriptHex));
    const r = spendStateless(c, { stack: [signFor('alice', c.scriptHex), signFor('bob', c.scriptHex)] });
    console.log('baseline (alice+bob):', r.ok, r.error?.split('\n')[0]);
    expect(r.ok).toBe(true);
  });

  it('M1 every key pair works, in script order', () => {
    const c = compiled(HONEST);
    for (const a of ['alice', 'bob', 'charlie']) {
      for (const b of ['alice', 'bob', 'charlie']) {
        if (a === b) continue;
        const r = spendStateless(c, { stack: [signFor(a, c.scriptHex), signFor(b, c.scriptHex)] });
        console.log(`M1 ${a}+${b}: ${r.ok ? 'ACCEPT' : 'reject'}`);
      }
    }
  });

  it('M2 ONE signature duplicated satisfies 2-of-3 when keys repeat', () => {
    // Deployment where the same key is passed twice (a very easy deployer
    // mistake, and nothing in the compiler or SDK warns about it).
    const dup: [string, string, string] = [key('charlie').pubKey, key('bob').pubKey, key('charlie').pubKey];
    const c = compiled(dup);
    const r = spendStateless(c, { stack: [signFor('charlie', c.scriptHex), signFor('charlie', c.scriptHex)] });
    console.log('M2 charlie alone on a pk1==pk3 vault:', r.ok, r.error?.split('\n')[0]);
  });

  it('M3 all three keys identical: a single signer controls the vault', () => {
    const solo: [string, string, string] = [key('charlie').pubKey, key('charlie').pubKey, key('charlie').pubKey];
    const c = compiled(solo);
    const r = spendStateless(c, { stack: [signFor('charlie', c.scriptHex), signFor('charlie', c.scriptHex)] });
    console.log('M3 charlie-only 2-of-3:', r.ok, '| script size', c.scriptHex.length / 2);
    expect(r.ok).toBe(true);
  });

  it('M4 arity: extra / missing unlocking items', () => {
    const c = compiled(HONEST);
    const one = spendStateless(c, { stack: [signFor('alice', c.scriptHex)] });
    const three = spendStateless(c, { stack: [signFor('alice', c.scriptHex), signFor('bob', c.scriptHex), signFor('charlie', c.scriptHex)] });
    const junkBelow = spendStateless(c, { stack: ['aabbcc', signFor('alice', c.scriptHex), signFor('bob', c.scriptHex)] });
    console.log('M4 one sig only:', one.ok, '|', one.error?.split('\n')[0]);
    console.log('M4 three sigs (one extra):', three.ok, '|', three.error?.split('\n')[0]);
    console.log('M4 junk under witness:', junkBelow.ok, '|', junkBelow.error?.split('\n')[0]);
  });

  it('M5 signature placed in the pubkey slot / garbage witness', () => {
    const c = compiled(HONEST);
    const swap = spendStateless(c, { stack: [key('alice').pubKey, signFor('bob', c.scriptHex)] });
    const emptySig = spendStateless(c, { stack: [new Uint8Array(0), signFor('bob', c.scriptHex)] });
    console.log('M5 pubkey-as-sig:', swap.ok, '|', swap.error?.split('\n')[0]);
    console.log('M5 empty sig:', emptySig.ok, '|', emptySig.error?.split('\n')[0]);
  });

  // The example source is plain 2-of-3, `MultiSig2of3.runar.ts` being
  //   public release(s1: Sig, s2: Sig) { assert(checkMultiSig([this.pk1,this.pk2,this.pk3], 2)); }
  // with no `@sighash` in sight, so there is no declared mode to ignore: the
  // script is simply `2 <s1> <s2> 3 <pk1> <pk2> <pk3> 3 OP_CHECKMULTISIG`, and
  // OP_CHECKMULTISIG honours whatever hashType each signature carries.
  //
  // What is exposed is the same boundary as the escrow (see
  // `escrow.attacks.test.ts` A6): with `NONE`, `SINGLE` or `ANYONECANPAY`
  // unlocking extra stack positions, a 3-item witness becomes
  //   [sig_of_spender, redemptionScript, ...]
  // and `redemptionScript`, whose first byte is 0x41, is read as a second
  // signature valid for hashType ALL — signed over whichever outputs the spender
  // assembled. Two honest approvals of "pay X" then ride a transaction paying Y,
  // with the extra bytes only ever having to satisfy the *public key* slot of the
  // first signer, which is the honest one. A further wrinkle unique to multisig:
  // any participant alone can carry the whole witness. `ANYONECANPAY` modes drop
  // the other inputs from the digest entirely, so one of the three keyholders can
  // take a signature meant for a cooperative spend and reuse it in a transaction
  // where they are the only contributor, without the second signer's intent being
  // bound to anything else in it.
  //
  // A stateful contract with the same keys is bound by D25's continuation check
  // instead; this one is stateless, so nothing is. LIVE on main: F-4.
  it('M6 sighash downgrade on a multisig vault — none of the modes is bound', () => {
    const c = compiled(HONEST);
    const ctx = { outputs: [{ script: '0014' + key('alice').pubKeyHash, satoshis: 99_500 }], sourceSatoshis: 100_000 };
    const accepted: string[] = [];
    for (const [name, scope] of [['ALL|FORKID', 0x41], ['NONE|FORKID', 0x42], ['SINGLE|FORKID', 0x43], ['ALL|ANYONECANPAY|FORKID', 0xc1], ['NONE|ANYONECANPAY|FORKID', 0xc2], ['SINGLE|ANYONECANPAY|FORKID', 0xc3]] as Array<[string, number]>) {
      const r = spendStateless(c, {
        stack: [signFor('alice', c.scriptHex, ctx, scope), signFor('bob', c.scriptHex, ctx, scope)],
        ctx,
      });
      if (r.ok) accepted.push(name);
      console.log(`M6 ${name}: ${r.ok ? 'ACCEPT' : 'reject'}`);
    }
    // Still open: every mode is accepted, so the vault does not constrain what a
    // signer agreed to. Pinning the mode would leave only the first line.
    expect(accepted).toEqual(['ALL|FORKID', 'NONE|FORKID', 'SINGLE|FORKID', 'ALL|ANYONECANPAY|FORKID', 'NONE|ANYONECANPAY|FORKID', 'SINGLE|ANYONECANPAY|FORKID']);
  });

  it('M7 sigs from a DIFFERENT vault with the same keys (replay across UTXOs)', () => {
    // Two vaults, same three keys, different funding. A signature is bound to
    // an outpoint + amount, so vault B must not accept vault A's witness.
    const a = compiled(HONEST);
    const b = compiled(HONEST);
    const ctxA = { sourceSatoshis: 100_000, otherInputs: [{ sourceTXID: '11'.repeat(32), sourceOutputIndex: 0, sequence: 0xffffffff, satoshis: 1, script: '0014' + '00'.repeat(20) }] };
    const witnessForA = [signFor('alice', a.scriptHex, ctxA), signFor('bob', a.scriptHex, ctxA)];
    const onA = spendStateless(a, { stack: witnessForA, ctx: ctxA });
    const onB = spendStateless(b, { stack: witnessForA, ctx: { ...ctxA, sourceSatoshis: 99_999 } });
    console.log('M7 on vault A:', onA.ok, '| replayed onto vault B with a different input amount:', onB.ok, onB.error?.split('\n')[0]);
  });
});
