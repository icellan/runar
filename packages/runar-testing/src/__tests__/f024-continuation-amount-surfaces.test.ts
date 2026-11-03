/**
 * F-024 (R14) — `continuationAmount()` on all nine surfaces, in all seven tiers,
 * and on-chain.
 *
 * `continuationAmount()` is the read-only view of the compiler-injected
 * `_newAmount` witness (the satoshis of the default single-output state
 * continuation). It is an ordinary zero-argument builtin, so each surface
 * spells it the way that surface spells every other builtin
 * (`runar.ContinuationAmount()` in Go, `continuation_amount()` on the
 * snake_case surfaces, …) and no new grammar is involved.
 *
 * What this proves:
 *   1. The same `Pot` contract — `join(bet)` requires the continuation to hold
 *      exactly the input value plus the bet — written on each of the nine
 *      surfaces compiles in each of the seven tiers to ONE locking script
 *      (63 compiles, one hex).
 *   2. That script, under `@bsv/sdk` Spend on a real BIP-143 preimage:
 *      accepts an honest join (continuation = input + bet, paid by the
 *      joiner's funding input); rejects a join that does not pay the bet
 *      (continuation = input — the author's stricter rule, which the
 *      compiler's `>= input` check alone would accept); and rejects the drain
 *      (continuation = 1 sat) that F-024 is about.
 *   3. A write to it is refused on every surface by every tier.
 * What this does NOT prove: that authors who do not write such a rule get
 * anything beyond the compiler's `>= input` floor (f024-stateful-value-drain
 * covers that floor), or anything about addOutput / terminal methods, where
 * `continuationAmount()` is refused (per-tier unit tests cover the refusal).
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
const TMP = mkdtempSync(join(tmpdir(), 'runar-f024-surfaces-'));

// `@WRITE@` is replaced by nothing (the valid contract) or by a write to the
// accessor in that surface's own spelling (the refusal case).
const SURFACES: Record<string, { src: string; write: string }> = {
  ts: {
    src: `import { StatefulSmartContract, assert, extractAmount, continuationAmount } from 'runar-lang';

class Pot extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public join(bet: bigint) {
    assert(bet > 0n);@WRITE@
    assert(continuationAmount() == extractAmount(this.txPreimage) + bet);
    this.count = this.count + 1n;
  }
}
`,
    write: '\n    continuationAmount() = 5n;',
  },
  sol: {
    src: `pragma runar ^0.1.0;

contract Pot is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    function join(bigint bet) public {
        require(bet > 0);@WRITE@
        require(continuationAmount() == extractAmount(this.txPreimage) + bet);
        this.count = this.count + 1;
    }
}
`,
    write: '\n        continuationAmount() = 5;',
  },
  move: {
    src: `module Pot {
    use runar::crypto::{extract_amount};

    resource struct Pot {
        count: &mut bigint,
    }

    public fun join(contract: &mut Pot, bet: bigint) {
        assert!(bet > 0, 0);@WRITE@
        assert!(continuation_amount() == extract_amount(contract.tx_preimage) + bet, 0);
        contract.count = contract.count + 1;
    }
}
`,
    write: '\n        continuation_amount() = 5;',
  },
  go: {
    src: `package x

import runar "github.com/icellan/runar/packages/runar-go"

type Pot struct {
	runar.StatefulSmartContract

	Count runar.Bigint
}

func (c *Pot) Join(bet runar.Bigint) {
	runar.Assert(bet > 0)@WRITE@
	runar.Assert(runar.ContinuationAmount() == runar.ExtractAmount(c.TxPreimage)+bet)
	c.Count = c.Count + 1
}
`,
    write: '\n\trunar.ContinuationAmount() = 5',
  },
  rs: {
    src: `use runar::prelude::*;

#[runar::contract]
pub struct Pot {
    pub count: Bigint,
}

impl Pot {
    pub fn join(&mut self, bet: Bigint) {
        assert!(bet > 0);@WRITE@
        assert!(continuation_amount() == extract_amount(&self.tx_preimage) + bet);
        self.count = self.count + 1;
    }
}
`,
    write: '\n        continuation_amount() = 5;',
  },
  py: {
    src: `from runar import (
    StatefulSmartContract, Bigint, public, assert_, extract_amount, continuation_amount,
)


class Pot(StatefulSmartContract):
    count: Bigint

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    @public
    def join(self, bet: Bigint):
        assert_(bet > 0)@WRITE@
        assert_(continuation_amount() == extract_amount(self.tx_preimage) + bet)
        self.count = self.count + 1
`,
    write: '\n        continuation_amount() = 5',
  },
  zig: {
    src: `const runar = @import("runar");

pub const Pot = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) Pot {
        return .{ .count = count };
    }

    pub fn join(self: *Pot, ctx: runar.StatefulContext, bet: i64) void {
        runar.assert(bet > 0);@WRITE@
        runar.assert(runar.continuationAmount() == runar.extractAmount(ctx.txPreimage) + bet);
        self.count = self.count + 1;
    }
};
`,
    write: '\n        runar.continuationAmount() = 5;',
  },
  rb: {
    src: `require 'runar'

class Pot < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  runar_public bet: Bigint
  def join(bet)
    assert bet > 0@WRITE@
    assert continuation_amount() == extract_amount(@tx_preimage) + bet
    @count = @count + 1
  end
end
`,
    write: '\n    continuation_amount() = 5',
  },
  java: {
    src: `package runar.examples.pot;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.continuationAmount;
import static runar.lang.Builtins.extractAmount;

class Pot extends StatefulSmartContract {

    Bigint count;

    Pot(Bigint count) {
        super(count);
        this.count = count;
    }

    @Public
    void join(Bigint bet) {
        assertThat(bet.gt(Bigint.ZERO));@WRITE@
        assertThat(Bigint.of(continuationAmount()).eq(Bigint.of(extractAmount(this.txPreimage)).plus(bet)));
        this.count = this.count.plus(Bigint.ONE);
    }
}
`,
    write: '\n        continuationAmount() = 5;',
  },
};

function render(ext: string, withWrite: boolean): string {
  const s = SURFACES[ext]!;
  return s.src.replace('@WRITE@', withWrite ? s.write : '');
}

let seq = 0;
function writeTmp(fileName: string, src: string): string {
  const dir = join(TMP, String(seq++));
  mkdirSync(dir);
  const p = join(dir, fileName);
  writeFileSync(p, src);
  return p;
}

function javaJar(): string {
  const libs = join(REPO, 'compilers', 'java', 'build', 'libs');
  const jar = existsSync(libs) ? readdirSync(libs).find((f) => f.endsWith('.jar')) : undefined;
  if (!jar) throw new Error('Java jar missing — run `gradle jar` in compilers/java');
  return join(libs, jar);
}

function requireBin(p: string, how: string): string {
  if (!existsSync(p)) throw new Error(`missing compiler binary ${p} — build it with: ${how}`);
  return p;
}

type Outcome = { ok: true; script: string } | { ok: false; error: string };

function spawn(cmd: string, args: string[], cwd?: string): Outcome & { stdout?: string } {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 180_000, maxBuffer: 64 * 1024 * 1024 });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  if (r.signal) throw new Error(`${cmd} killed by ${r.signal}`);
  if (r.status !== 0) {
    const error = `${r.stderr}${r.stdout}`.trim();
    // A refusal needs a verdict, not silence (conformance/negatives R-100).
    if (!error) throw new Error(`${cmd} exited ${r.status} with no diagnostic`);
    return { ok: false, error };
  }
  return { ok: true, script: '', stdout: r.stdout };
}

function fromArtifact(o: Outcome & { stdout?: string }): Outcome {
  if (!o.ok) return o;
  return { ok: true, script: (JSON.parse(o.stdout!) as { script: string }).script };
}

const TIERS: Record<string, (fileName: string, src: string) => Outcome> = {
  ts: (fileName, src) => {
    const r = compile(src, { fileName });
    return r.success && r.artifact
      ? { ok: true, script: r.artifact.script }
      : { ok: false, error: r.diagnostics.map((d) => d.message).join(' | ') };
  },
  go: (fileName, src) => fromArtifact(spawn(
    requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
    ['--source', writeTmp(fileName, src)],
  )),
  rust: (fileName, src) => fromArtifact(spawn(
    requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'),
    ['--source', writeTmp(fileName, src)],
  )),
  python: (fileName, src) => fromArtifact(spawn(
    'python3', ['-m', 'runar_compiler', '--source', writeTmp(fileName, src)], join(REPO, 'compilers', 'python'),
  )),
  zig: (fileName, src) => fromArtifact(spawn(
    requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
    ['--source', writeTmp(fileName, src)],
  )),
  ruby: (fileName, src) => fromArtifact(spawn('ruby', [
    '-I', join(REPO, 'compilers', 'ruby', 'lib'),
    join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'),
    '--source', writeTmp(fileName, src),
  ])),
  java: (fileName, src) => {
    const out = writeTmp('artifact.json', '');
    const o = spawn('java', ['-jar', javaJar(), '--source', writeTmp(fileName, src), '--emit-artifact', out]);
    if (!o.ok) return o;
    return { ok: true, script: (JSON.parse(readFileSync(out, 'utf8')) as { script: string }).script };
  },
};

const REFERENCE = TIERS.ts!('Pot.runar.ts', render('ts', false));
if (!REFERENCE.ok) throw new Error(`reference compile failed: ${REFERENCE.error}`);

describe('F-024 continuationAmount() — nine surfaces x seven tiers, one script', () => {
  for (const ext of Object.keys(SURFACES)) {
    for (const [tier, run] of Object.entries(TIERS)) {
      it(`.runar.${ext} in ${tier} compiles to the reference script`, () => {
        const o = run(`Pot.runar.${ext}`, render(ext, false));
        expect(o.ok ? '' : o.error).toBe('');
        expect((o as { script: string }).script).toBe((REFERENCE as { script: string }).script);
      });
      it(`.runar.${ext} in ${tier} refuses a write to continuationAmount()`, () => {
        const o = run(`Pot.runar.${ext}`, render(ext, true));
        expect(o.ok, 'a write to continuationAmount() compiled').toBe(false);
      });
    }
  }
});

const CONTRACT_SATS = 10_000;
const BET = 500;

/**
 * Deploy Pot(count = 0) with CONTRACT_SATS, then call `join(BET)` with the
 * continuation holding `newSatoshis`. `funded`: the caller brings a UTXO, so
 * the continuation can grow. The verdict is `@bsv/sdk` Spend on the bytes the
 * SDK built; MockProvider's own validation stays on, so a refused broadcast is
 * recorded and replayed rather than hidden.
 */
async function joinPot(newSatoshis: number, funded: boolean): Promise<{ accepted: boolean; tx: Transaction }> {
  const artifact = compile(render('ts', false), { fileName: 'Pot.runar.ts' }).artifact as unknown as RunarArtifact;
  const owner = testKey('alice');
  const joiner = testKey('eve');
  let last: Transaction | undefined;
  class Recording extends MockProvider {
    override async broadcast(tx: Transaction): Promise<string> {
      last = tx;
      return super.broadcast(tx);
    }
  }
  const provider = new Recording();
  provider.addUtxo(await new LocalSigner(owner.privKey).getAddress(), {
    txid: owner.privKey.slice(0, 64), outputIndex: 0, satoshis: 500_000, script: buildP2PKHScript(owner.pubKey),
  });
  const contract = new RunarContract(artifact, [0n]);
  await contract.deploy(provider, new LocalSigner(owner.privKey), { satoshis: CONTRACT_SATS });
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  const signer = new LocalSigner(joiner.privKey);
  if (funded) {
    provider.addUtxo(await signer.getAddress(), {
      txid: joiner.privKey.slice(0, 64), outputIndex: 0, satoshis: 50_000, script: buildP2PKHScript(joiner.pubKey),
    });
  }
  try {
    await contract.call('join', [BigInt(BET)], provider, signer, { satoshis: newSatoshis, changeAddress: joiner.pubKeyHash });
  } catch {
    // replayed below
  }
  if (!last || last === deployTx) throw new Error('no call tx was built');
  const tx = Transaction.fromHex(last.toHex());
  expect(tx.outputs[0]!.satoshis).toBe(newSatoshis);
  let accepted: boolean;
  try {
    accepted = validateContractInput(tx, 0, deployTx, 0);
  } catch {
    accepted = false;
  }
  return { accepted, tx };
}

describe('F-024 continuationAmount() — the author rule holds on-chain (@bsv/sdk Spend)', () => {
  it('honest join: continuation = input + bet, paid by the joiner, is ACCEPTED', async () => {
    expect((await joinPot(CONTRACT_SATS + BET, true)).accepted).toBe(true);
  });

  it('join without paying the bet (continuation = input) is REJECTED by the author rule', async () => {
    expect((await joinPot(CONTRACT_SATS, true)).accepted).toBe(false);
  });

  it('the drain (continuation = 1 sat) is REJECTED', async () => {
    expect((await joinPot(1, false)).accepted).toBe(false);
  });
});
