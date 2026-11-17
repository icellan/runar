/**
 * GK-DOC-009: runar-lang/tokens shipped FungibleToken / NonFungibleToken as
 * abstract stubs whose headers said "the compiler recognises classes
 * extending FungibleToken and emits the appropriate locking/unlocking script
 * structure". No compiler does: every tier accepts only SmartContract /
 * StatefulSmartContract / UnsafeSmartContract as a base class, so a class
 * extending FungibleToken is not a contract at all.
 *
 * User decision: no compiler changes. The two files are now real
 * StatefulSmartContract contracts with the logic of examples/ts/token-ft and
 * examples/ts/token-nft, compiled as-is.
 *
 * Proves: both files compile through the TS compiler to the same script as
 * the proven examples (so the merge path inherits the W8 real-Spend proof in
 * packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts),
 * the Python tier compiles them to the same bytes, TestContract runs
 * transfer / send / burn and rejects an over-spend, a class extending the
 * token is still rejected, and no file claims compiler recognition.
 * Does not prove: merge on TestContract (the W8 header forbids asserting that
 * family on the interpreter; it is covered by the byte equality above).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';
import { TestContract, ALICE, BOB, signTestMessage } from 'runar-testing';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p: string) => readFileSync(join(ROOT, p), 'utf8');

const FT = 'packages/runar-lang/src/tokens/fungible.ts';
const NFT = 'packages/runar-lang/src/tokens/nft.ts';
const FT_EXAMPLE = 'examples/ts/token-ft/FungibleTokenExample.runar.ts';
const NFT_EXAMPLE = 'examples/ts/token-nft/NFTExample.runar.ts';

function tsHex(path: string, fileName: string): string {
  const r = compile(read(path), { fileName, disableConstantFolding: true });
  expect(r.success, `${path}: ${JSON.stringify(r.diagnostics)}`).toBe(true);
  return (r.scriptHex as string).toLowerCase();
}

function pythonHex(path: string, name: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'gk-doc-009-'));
  try {
    const file = join(dir, `${name}.runar.ts`);
    writeFileSync(file, read(path));
    const r = spawnSync('python3', ['-m', 'runar_compiler', '--source', file, '--hex', '--disable-constant-folding'], {
      cwd: join(ROOT, 'compilers/python'),
      encoding: 'utf8',
      timeout: 120_000,
    });
    expect(r.status, `python tier failed on ${path}: ${r.stderr}`).toBe(0);
    return r.stdout.trim().toLowerCase();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('GK-DOC-009: runar-lang/tokens are compilable token contracts', () => {
  it('FungibleToken compiles to the token-ft example script (TS)', () => {
    expect(tsHex(FT, 'FungibleToken.runar.ts')).toBe(tsHex(FT_EXAMPLE, 'FungibleTokenExample.runar.ts'));
  });

  it('NonFungibleToken compiles to the token-nft example script (TS)', () => {
    expect(tsHex(NFT, 'NonFungibleToken.runar.ts')).toBe(tsHex(NFT_EXAMPLE, 'NFTExample.runar.ts'));
  });

  it('the Python tier compiles both files to the same bytes as TS', () => {
    expect(pythonHex(FT, 'FungibleToken')).toBe(tsHex(FT, 'FungibleToken.runar.ts'));
    expect(pythonHex(NFT, 'NonFungibleToken')).toBe(tsHex(NFT, 'NonFungibleToken.runar.ts'));
  }, 240_000);

  it('FungibleToken: transfer splits and send moves the full balance (TestContract)', () => {
    const make = () =>
      TestContract.fromSource(read(FT), { owner: ALICE.pubKey, balance: 100n, mergeBalance: 0n, tokenId: 'deadbeef' }, 'FungibleToken.runar.ts');
    const sig = signTestMessage(ALICE.privKey);

    const split = make().call('transfer', { sig, to: BOB.pubKey, amount: 30n, outputSatoshis: 1000n });
    expect(split.success, split.error).toBe(true);
    expect(split.outputs.map((o) => [o.owner, o.balance])).toEqual([[BOB.pubKey, 30n], [ALICE.pubKey, 70n]]);

    const send = make().call('send', { sig, to: BOB.pubKey, outputSatoshis: 1000n });
    expect(send.success, send.error).toBe(true);
    expect(send.outputs.map((o) => [o.owner, o.balance])).toEqual([[BOB.pubKey, 100n]]);
  });

  it('FungibleToken: transferring more than the balance is rejected by an assert', () => {
    const token = TestContract.fromSource(read(FT), { owner: ALICE.pubKey, balance: 100n, mergeBalance: 0n, tokenId: 'deadbeef' }, 'FungibleToken.runar.ts');
    const r = token.call('transfer', { sig: signTestMessage(ALICE.privKey), to: BOB.pubKey, amount: 101n, outputSatoshis: 1000n });
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/assert/i);
  });

  it('NonFungibleToken: transfer re-owns and burn leaves no output (TestContract)', () => {
    const make = () =>
      TestContract.fromSource(read(NFT), { owner: ALICE.pubKey, tokenId: 'deadbeef01', metadata: 'cafebabe' }, 'NonFungibleToken.runar.ts');
    const sig = signTestMessage(ALICE.privKey);

    const t = make().call('transfer', { sig, newOwner: BOB.pubKey, outputSatoshis: 1000n });
    expect(t.success, t.error).toBe(true);
    expect(t.outputs.map((o) => o.owner)).toEqual([BOB.pubKey]);

    const b = make().call('burn', { sig });
    expect(b.success, b.error).toBe(true);
    expect(b.outputs).toHaveLength(0);
  });

  it('a class extending FungibleToken is still not a contract (no base-class recognition)', () => {
    const r = compile(
      "import { FungibleToken } from 'runar-lang/tokens';\nclass MyToken extends FungibleToken {}\n",
      { fileName: 'MyToken.runar.ts' },
    );
    expect(r.success).toBe(false);
    expect(r.diagnostics.map((d) => d.message).join('\n')).toMatch(/SmartContract/);
  });

  it('no token file or README claims the compiler recognises a token base class', () => {
    for (const p of [FT, NFT, 'packages/runar-lang/src/tokens/index.ts', 'packages/runar-lang/README.md']) {
      const text = read(p);
      expect(text, p).not.toMatch(/compiler recogni[sz]es/i);
      expect(text, p).not.toMatch(/recogni[sz]ed by the compiler/i);
      expect(text, p).not.toMatch(/The compiler emits/);
      expect(text, p).not.toMatch(/Your contract extends the appropriate base/);
    }
  });
});
