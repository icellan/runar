import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { build, spendStateless, signFor, key, asm, type StackItem } from './harness.js';

const SRC = 'examples/ts/escrow/Escrow.runar.ts';
const source = readFileSync(SRC, 'utf8');

// buyer = alice, seller = bob, arbiter = charlie (real curve points)
function compiled() {
  return build(source, SRC, {
    buyer: key('alice').pubKey,
    seller: key('bob').pubKey,
    arbiter: key('charlie').pubKey,
  });
}

const ALL_SCOPES: Array<[string, number]> = [
  ['ALL|FORKID', 0x41],
  ['NONE|FORKID', 0x42],
  ['SINGLE|FORKID', 0x43],
  ['ALL|ANYONECANPAY|FORKID', 0xc1],
  ['NONE|ANYONECANPAY|FORKID', 0xc2],
  ['SINGLE|ANYONECANPAY|FORKID', 0xc3],
];

describe('ESCROW attacks', () => {
  it('baseline: <sellerSig> <arbiterSig> <selector 0>', () => {
    const c = compiled();
    console.log('ASM:', asm(c.scriptHex));
    const a = spendStateless(c, { stack: [signFor('bob', c.scriptHex), signFor('charlie', c.scriptHex), 0n] });
    console.log('baseline release:', a.ok, a.error);
    expect(a.ok).toBe(true);
  });

  it('sanity: buyer sig in the seller slot is rejected', () => {
    const c = compiled();
    const r = spendStateless(c, { stack: [signFor('alice', c.scriptHex), signFor('charlie', c.scriptHex), 0n] });
    console.log('buyer-in-seller-slot:', r.ok, r.error?.split('\n')[0]);
    expect(r.ok).toBe(false);
  });

  it('A1 arity: drop the arbiter signature', () => {
    const c = compiled();
    const r = spendStateless(c, { stack: [signFor('bob', c.scriptHex), 0n] });
    console.log('A1 drop arbiter sig:', r.ok, r.error?.split('\n')[0]);
  });

  it('A2 arbiter signature replaced by an empty push', () => {
    const c = compiled();
    const r = spendStateless(c, { stack: [signFor('bob', c.scriptHex), new Uint8Array(0), 0n] });
    console.log('A2 empty arbiter sig:', r.ok, r.error?.split('\n')[0]);
  });

  it('A3 extra junk under the witness (stack depth is not checked?)', () => {
    const c = compiled();
    const r = spendStateless(c, { stack: ['deadbeef', signFor('bob', c.scriptHex), signFor('charlie', c.scriptHex), 0n] });
    console.log('A3 junk under witness:', r.ok, r.error?.split('\n')[0]);
  });

  it('A4 extra junk ON TOP of the selector', () => {
    const c = compiled();
    const r = spendStateless(c, { stack: [signFor('bob', c.scriptHex), signFor('charlie', c.scriptHex), 0n, 1n] });
    console.log('A4 junk above selector:', r.ok, r.error?.split('\n')[0]);
  });

  it('A5 selector probing', () => {
    const c = compiled();
    const sigs = [signFor('bob', c.scriptHex), signFor('charlie', c.scriptHex)];
    const cases: Array<[string, StackItem]> = [
      ['0', 0n],
      ['1', 1n],
      ['2', 2n],
      ['-1', -1n],
      ['0 padded to 4 bytes', { raw: new Uint8Array([0x04, 0x00, 0x00, 0x00, 0x00]) }],
      ['256', 256n],
      ['2^31', 2n ** 31n],
      ['empty string', new Uint8Array(0)],
      ['ascii "0"', '30'],
    ];
    for (const [name, sel] of cases) {
      const r = spendStateless(c, { stack: [...sigs, sel] });
      console.log(`A5 selector=${name}: ok=${r.ok} err=${(r.error ?? '').split('\n')[0]}`);
    }
  });

  it('A6 sighash downgrade: which hashTypes does the covenant accept?', () => {
    const c = compiled();
    const ctx = { outputs: [{ script: '0014' + key('bob').pubKeyHash, satoshis: 99_000 }], sourceSatoshis: 100_000 };
    for (const [name, scope] of ALL_SCOPES) {
      const r = spendStateless(c, {
        stack: [signFor('bob', c.scriptHex, ctx, scope), signFor('charlie', c.scriptHex, ctx, scope), 0n],
        ctx,
      });
      console.log(`A6 ${name}: accepted=${r.ok}`);
    }
  });

  it('A7 arbiter signature taken over a DIFFERENT output set', () => {
    const c = compiled();
    const sellerCtx = { outputs: [{ script: '0014' + key('bob').pubKeyHash, satoshis: 99_000 }], sourceSatoshis: 100_000 };
    const arbCtx = {
      outputs: [
        { script: '0014' + key('bob').pubKeyHash, satoshis: 50_000 },
        { script: '0014' + key('alice').pubKeyHash, satoshis: 49_000 },
      ],
      sourceSatoshis: 100_000,
    };
    const honest = spendStateless(c, {
      stack: [signFor('bob', c.scriptHex, sellerCtx), signFor('charlie', c.scriptHex, sellerCtx), 0n],
      ctx: sellerCtx,
    });
    const mixed = spendStateless(c, {
      stack: [signFor('bob', c.scriptHex, sellerCtx), signFor('charlie', c.scriptHex, arbCtx), 0n],
      ctx: sellerCtx,
    });
    console.log('A7 honest:', honest.ok, '| arbiter sig over other outputs:', mixed.ok, mixed.error?.split('\n')[0]);
  });

  it('A8 method-crossing: release sigs replayed with the refund selector', () => {
    const c = compiled();
    const sigs = [signFor('bob', c.scriptHex), signFor('charlie', c.scriptHex)];
    const r = spendStateless(c, { stack: [...sigs, 1n] });
    console.log('A8 release sigs w/ refund selector:', r.ok, r.error?.split('\n')[0]);
  });

  it('A9 pubkeys swapped: buyer+arbiter sigs on the release branch', () => {
    const c = compiled();
    const r = spendStateless(c, { stack: [signFor('alice', c.scriptHex), signFor('charlie', c.scriptHex), 0n] });
    console.log('A9:', r.ok, r.error?.split('\n')[0]);
  });
});
