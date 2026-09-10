// ---------------------------------------------------------------------------
// R-036 — `runar deploy` must splice REAL constructor args into the locking
// script, not a zero fill.
//
// The bug: deploy.ts built `new Array(params.length).fill(0n)` and there was
// no `--args` flag at all. For P2PKH that produced
// `76a90088ac` = OP_DUP OP_HASH160 OP_0 OP_EQUALVERIFY OP_CHECKSIG — an
// output no key can ever unlock, because hash160(pubKey) is a 20-byte push
// and can never equal the empty push OP_0. Any coins deployed there are gone.
//
// These tests assert on the ACTUAL emitted locking script bytes at the
// artifact's recorded `constructorSlots` byte offset, not merely that the CLI
// tolerated a new flag.
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';
import { RunarContract } from 'runar-sdk';
import type { RunarArtifact } from 'runar-sdk';

// Minimal real P2PKH — the canonical fund-losing case.
const P2PKH_SOURCE = `
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`;

function compileP2PKH(): RunarArtifact {
  const result = compile(P2PKH_SOURCE, { fileName: 'P2PKH.runar.ts' });
  const artifact = result.artifact;
  if (!artifact) {
    throw new Error(
      `P2PKH fixture failed to compile: ${result.diagnostics.map((d) => d.message).join('; ')}`,
    );
  }
  return artifact;
}

/** A hand-built stateless artifact whose single ctor param is a scriptnum. */
function counterLikeArtifact(): RunarArtifact {
  return {
    version: 'runar-v0.1.0',
    compilerVersion: '0.0.0-test',
    contractName: 'ScriptNumParam',
    abi: { constructor: { params: [{ name: 'limit', type: 'bigint' }] }, methods: [] },
    // OP_0 placeholder at byte 0, then OP_DROP.
    script: '0075',
    asm: 'OP_0 OP_DROP',
    constructorSlots: [
      {
        paramIndex: 0,
        byteOffset: 0,
        name: 'limit',
        type: 'bigint',
        valueEncoding: 'scriptnum',
      },
    ],
    buildTimestamp: '1970-01-01T00:00:00.000Z',
  };
}

const PKH = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678'; // 20 bytes

describe('R-036: deploy constructor args', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // Control — passes before AND after the fix. Documents the shape of the bug
  // and pins the compiler-emitted template so the RED test below is honest.
  // -------------------------------------------------------------------------
  it('CONTROL: the P2PKH template carries an OP_0 placeholder at the recorded slot', () => {
    const artifact = compileP2PKH();
    expect(artifact.script).toBe('76a90088ac');

    const slots = artifact.constructorSlots;
    expect(slots).toBeDefined();
    expect(slots).toHaveLength(1);
    const slot = slots![0]!;
    expect(slot.paramIndex).toBe(0);
    expect(slot.byteOffset).toBe(2);
    expect(slot.fixedValueByteLength).toBe(20);

    // The placeholder byte at the slot offset is OP_0.
    expect(artifact.script.slice(slot.byteOffset * 2, slot.byteOffset * 2 + 2)).toBe('00');

    // And the old zero-fill deploy path leaves it as OP_0 — unspendable.
    const zeroFilled = new RunarContract(artifact, [0n]);
    expect(zeroFilled.getLockingScript()).toBe('76a90088ac');
  });

  // -------------------------------------------------------------------------
  // RED — this is the assertion that closes R-036.
  // -------------------------------------------------------------------------
  it('parses --args by ABI type and splices the real value into the slot', async () => {
    const { parseConstructorArgs } = await import('../commands/deploy.js');
    const artifact = compileP2PKH();

    const args = parseConstructorArgs(artifact, [PKH]);
    const script = new RunarContract(artifact, args).getLockingScript();

    // Canonical P2PKH: OP_DUP OP_HASH160 <20-byte push> OP_EQUALVERIFY OP_CHECKSIG
    expect(script).toBe(`76a914${PKH}88ac`);

    // And specifically: the bytes at the recorded slot offset are the pkh push,
    // not a zero.
    const slot = artifact.constructorSlots![0]!;
    expect(script.slice(slot.byteOffset * 2)).toMatch(new RegExp(`^14${PKH}`));
    expect(script).not.toContain('76a90088ac');
  });

  it('accepts a 0x-prefixed hex value for a data-encoded slot', async () => {
    const { parseConstructorArgs } = await import('../commands/deploy.js');
    const artifact = compileP2PKH();
    const args = parseConstructorArgs(artifact, [`0x${PKH.toUpperCase()}`]);
    expect(new RunarContract(artifact, args).getLockingScript()).toBe(`76a914${PKH}88ac`);
  });

  // -------------------------------------------------------------------------
  // The zero case must still be reachable — but only when asked for.
  // -------------------------------------------------------------------------
  it('an explicitly requested zero still deploys as OP_0', async () => {
    const { parseConstructorArgs } = await import('../commands/deploy.js');
    const artifact = counterLikeArtifact();
    const args = parseConstructorArgs(artifact, ['0']);
    expect(args).toEqual([0n]);
    expect(new RunarContract(artifact, args).getLockingScript()).toBe('0075');
  });

  it('splices a non-zero scriptnum', async () => {
    const { parseConstructorArgs } = await import('../commands/deploy.js');
    const artifact = counterLikeArtifact();
    const args = parseConstructorArgs(artifact, ['1000']);
    expect(args).toEqual([1000n]);
    // 1000 = 0x03e8 -> LE sign-magnitude e803, pushed with a 2-byte header.
    expect(new RunarContract(artifact, args).getLockingScript()).toBe('02e80375');
  });

  // -------------------------------------------------------------------------
  // Loud rejection instead of coercion.
  // -------------------------------------------------------------------------
  it('rejects a decimal where a hex byte string is required', async () => {
    const { parseConstructorArgs } = await import('../commands/deploy.js');
    const artifact = compileP2PKH();
    expect(() => parseConstructorArgs(artifact, ['12345'])).toThrow(/pubKeyHash/);
  });

  it('rejects a hex value of the wrong fixed byte length', async () => {
    const { parseConstructorArgs } = await import('../commands/deploy.js');
    const artifact = compileP2PKH();
    expect(() => parseConstructorArgs(artifact, ['aabb'])).toThrow(/20 bytes/);
  });

  it('rejects a non-numeric value where a script number is required', async () => {
    const { parseConstructorArgs } = await import('../commands/deploy.js');
    const artifact = counterLikeArtifact();
    expect(() => parseConstructorArgs(artifact, ['deadbeef'])).toThrow(/limit/);
  });

  it('rejects an arity mismatch', async () => {
    const { parseConstructorArgs } = await import('../commands/deploy.js');
    const artifact = compileP2PKH();
    expect(() => parseConstructorArgs(artifact, [])).toThrow(/expects 1/);
    expect(() => parseConstructorArgs(artifact, [PKH, PKH])).toThrow(/expects 1/);
  });

  // -------------------------------------------------------------------------
  // Command level: omitting --args on a parameterised contract is a hard error,
  // NOT a silent zero-fill deploy.
  // -------------------------------------------------------------------------
  it('deployCommand refuses to deploy a parameterised contract with no --args', async () => {
    const { deployCommand } = await import('../commands/deploy.js');
    const artifact = compileP2PKH();

    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    const tmp = path.join(os.tmpdir(), `runar-r036-${process.pid}-${Date.now()}.json`);
    fs.writeFileSync(tmp, JSON.stringify(artifact));
    try {
      await deployCommand(tmp, {
        network: 'testnet',
        // A structurally valid WIF, so a failure here can only come from the
        // constructor-arg check and never from key decoding.
        key: 'cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA',
        satoshis: '1000',
      });
    } finally {
      fs.unlinkSync(tmp);
    }

    expect(process.exitCode).toBe(1);
    const msgs = errSpy.mock.calls.map((c) => String(c[0]));
    expect(msgs.some((m) => /--args/.test(m))).toBe(true);

    process.exitCode = prevExitCode;
  });

  it('deployCommand still accepts a contract with a zero-param constructor', async () => {
    const { deployCommand } = await import('../commands/deploy.js');

    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    const artifact = {
      version: 'runar-v0.1.0',
      compilerVersion: '0.0.0-test',
      contractName: 'NoOp',
      script: '51',
      asm: 'OP_1',
      abi: { constructor: { params: [] }, methods: [] },
      buildTimestamp: '1970-01-01T00:00:00.000Z',
    };
    const tmp = path.join(os.tmpdir(), `runar-r036-noop-${process.pid}-${Date.now()}.json`);
    fs.writeFileSync(tmp, JSON.stringify(artifact));
    try {
      await deployCommand(tmp, {
        network: 'testnet',
        key: 'not-a-wif',
        satoshis: '1000',
      });
    } finally {
      fs.unlinkSync(tmp);
    }

    // It must fail on the WIF, i.e. it got PAST the constructor-arg gate.
    const msgs = errSpy.mock.calls.map((c) => String(c[0]));
    expect(msgs.some((m) => /Invalid private key/.test(m))).toBe(true);
    expect(msgs.some((m) => /--args/.test(m))).toBe(false);

    process.exitCode = prevExitCode;
  });

  // -------------------------------------------------------------------------
  // Wiring: the flag must actually exist on the deploy command.
  // -------------------------------------------------------------------------
  it('bin.ts registers --args on the deploy command', () => {
    const binPath = path.resolve(fileURLToPath(new URL('../bin.ts', import.meta.url)));
    const src = fs.readFileSync(binPath, 'utf-8');
    const deployBlock = src.slice(src.indexOf(`.command('deploy')`));
    const end = deployBlock.indexOf('.action(');
    expect(end).toBeGreaterThan(0);
    expect(deployBlock.slice(0, end)).toContain('--args');
  });
});
