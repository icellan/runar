/**
 * M-2 (round-three audit): `buildP2PKHScript` had no length or version gate
 * on its Base58Check branch — six peer tiers do.
 *
 * `Utils.fromBase58Check(addressOrPubKey).data` was concatenated straight
 * into `'76a914' + hash + '88ac'`. The checksum IS enforced by @bsv/sdk (a
 * typo'd address throws `Invalid checksum`), so what was missing is
 * specifically the payload-length and version-byte checks. Measured before
 * the fix:
 *
 *   WIF  Kx7ikhuW...  -> 38-byte script (the trailing push runs off the end;
 *                        unparseable, change permanently unspendable)
 *   xpub 04 88 B2 1E  -> 82-byte script, no error raised at all
 *   P2SH 3J98t1Wp...  -> 25-byte, syntactically perfect script that is a BURN
 *                        (that hash160 is a SCRIPT hash, not a pubkey hash)
 *
 * Reached from `contract.ts` deploy and call via `options.changeAddress`, a
 * public field on `DeployOptions` / `CallOptions` — so a caller-supplied
 * string lands here unvalidated.
 *
 * Peer state: Rust checks `!= 21`; Python / Ruby / Java check `!= 25`; Go and
 * Zig also check the version byte. Java's `Base58Check.decodeP2PKH`
 * (packages/runar-java/.../sdk/Base58Check.java) is the complete version —
 * length AND version (0x00 mainnet, 0x6f testnet/regtest) — and is what this
 * gate follows.
 */
import { describe, it, expect } from 'vitest';
import { Utils } from '@bsv/sdk';
import { buildP2PKHScript } from '../script-utils.js';

/** A compressed-key mainnet WIF (version 0x80, 33-byte payload). */
const WIF = 'Kx7ikhuWSiCD6FGisyKocw9vb4sw8b5kR9oBkJAvPSLeAWwhDvdM';
/** Mainnet P2SH (version 0x05): a 20-byte payload of the RIGHT length whose
 * hash160 is a script hash — only the version byte distinguishes it. */
const P2SH_MAINNET = '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy';
/** Testnet P2SH (version 0xc4) — the same trap on the other network, built
 * from the mainnet P2SH's own 20-byte payload so only the version differs. */
const P2SH_TESTNET = Utils.toBase58Check(
  Utils.toArray('b472a266d0bd89c13706a4132ccfb16f7c3b9fcb', 'hex'),
  [0xc4],
);
/** Version 0x00 (the P2PKH mainnet version) with a 32-byte payload: the ONE
 * fixture the version gate cannot catch, so it pins the length gate alone. */
const RIGHT_VERSION_WRONG_LENGTH = Utils.toBase58Check(new Array(32).fill(0x11), [0x00]);
/** Real mainnet / testnet P2PKH addresses — the controls that must keep working. */
const P2PKH_MAINNET = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2';
const P2PKH_TESTNET = 'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn';

/** A checksum-valid BIP-32 xpub shape (version 0x0488B21E, 78-byte payload),
 * built here so the fixture cannot rot on a mistyped constant. */
const XPUB = Utils.toBase58Check(new Array(74).fill(0), [0x04, 0x88, 0xb2, 0x1e]);

describe('M-2 — buildP2PKHScript must gate payload length and version byte', () => {
  it('RED: a WIF private key is rejected, not turned into a 38-byte unspendable script', () => {
    expect(() => buildP2PKHScript(WIF)).toThrow(/buildP2PKHScript/);
  });

  it('RED: an xpub is rejected, not turned into an 82-byte script', () => {
    expect(() => buildP2PKHScript(XPUB)).toThrow(/buildP2PKHScript/);
  });

  it('RED: a 0x00-versioned Base58Check string with a 32-byte payload is rejected — only the LENGTH gate sees this one', () => {
    expect(() => buildP2PKHScript(RIGHT_VERSION_WRONG_LENGTH)).toThrow(/32 bytes, expected 20/);
  });

  it('RED: a mainnet P2SH address is rejected — right length, wrong version, would BURN', () => {
    expect(() => buildP2PKHScript(P2SH_MAINNET)).toThrow(/version/i);
  });

  it('RED: a testnet P2SH address is rejected too', () => {
    expect(() => buildP2PKHScript(P2SH_TESTNET)).toThrow(/version/i);
  });

  it('RED: every rejection names the offending input class, not just "invalid"', () => {
    for (const bad of [WIF, XPUB, P2SH_MAINNET, P2SH_TESTNET, RIGHT_VERSION_WRONG_LENGTH]) {
      let msg = '';
      try { buildP2PKHScript(bad); } catch (e) { msg = (e as Error).message; }
      expect(msg).toMatch(/P2PKH/);
    }
  });

  it('CONTROL (teeth): a real MAINNET P2PKH address still builds the same 25-byte script', () => {
    const script = buildP2PKHScript(P2PKH_MAINNET);
    expect(script).toBe('76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac');
    expect(script.length / 2).toBe(25);
  });

  it('CONTROL (teeth): a real TESTNET P2PKH address still builds the same 25-byte script', () => {
    const script = buildP2PKHScript(P2PKH_TESTNET);
    expect(script).toBe('76a914243f1394f44554f4ce3fd68649c19adc483ce92488ac');
    expect(script.length / 2).toBe(25);
  });

  it('CONTROL (teeth): the raw-hash160 and pubkey branches are untouched', () => {
    const pkh = '77bff20c60e522dfaa3350c39b030a5d004e839a';
    expect(buildP2PKHScript(pkh)).toBe('76a914' + pkh + '88ac');
    const compressed = '02' + '11'.repeat(32);
    expect(buildP2PKHScript(compressed).length / 2).toBe(25);
    const uncompressed = '04' + '11'.repeat(64);
    expect(buildP2PKHScript(uncompressed).length / 2).toBe(25);
  });

  it('CONTROL: the pre-existing checksum enforcement still fires (and is a distinct failure)', () => {
    expect(() => buildP2PKHScript('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3')).toThrow(/checksum/i);
  });

  it('CONTROL: every script this function returns is a parseable 25-byte P2PKH', () => {
    for (const good of [P2PKH_MAINNET, P2PKH_TESTNET]) {
      expect(buildP2PKHScript(good)).toMatch(/^76a914[0-9a-f]{40}88ac$/);
    }
  });
});
