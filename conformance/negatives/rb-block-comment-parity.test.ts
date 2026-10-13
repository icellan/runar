import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { REPO, Tier, buildSourceTiers } from './tier-harness.js';
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

/**
 * N-021 (user decision R11) — seven-tier POSITIVE parity for Ruby's
 * `=begin` / `=end` embedded documents on the .runar.rb surface.
 *
 * rejection-parity.test.ts only proves every tier REFUSES N65 (an
 * unterminated `=begin`). The fund-critical half of the defect was an
 * ACCEPTED program: a P2PKH whose "commented-out" `drain(sig, pk) { assert
 * true }` compiled as the only spend path (517777, anyone-can-spend) in the
 * TS reference, Rust, Python, Zig and Java, while Ruby (F-018) and Go (F-012)
 * compiled the P2PKH. This test pins the accepted side in all seven tiers.
 *
 * Why a test here rather than a conformance fixture: a new fixture must also
 * be stamped into conformance/script-size-baseline.json, which the
 * golden-provenance gate guards and which only a route-B allowlist entry
 * signed by a human reviewer can justify. Every other assertion a fixture
 * would make (this source, all seven tiers, byte-identical to a golden) is
 * made below against the existing basic-p2pkh golden, which is not modified.
 *
 * What this proves: every available tier's CLI compiles the backdoor shape
 * (LF, CRLF, text or a tab after the markers, and a notes-only block) to the
 * basic-p2pkh golden bytes; every tier refuses an unterminated `=begin` with
 * the shared text naming the opener's line; and the boundary controls (an
 * indented `=begin`, `=beginx`) produce one identical script in all tiers.
 * What it does NOT prove: spend behaviour of those bytes (the golden's own
 * real-crypto witness and packages/runar-testing's N-021 spend test cover
 * that), fold-OFF output (the CLIs run in their fold-ON default here; the
 * per-tier suites pin fold OFF), or the silent skip of unknown class-body
 * tokens (N-004), which the boundary controls deliberately do not judge.
 */

const GOLDEN = readFileSync(join(REPO, 'conformance/tests/basic-p2pkh/expected-script.hex'), 'utf8').trim();

const ATTACK = [
  "require 'runar'",
  '',
  'class P2PKH < Runar::SmartContract',
  '  prop :pub_key_hash, Addr',
  '',
  '  def initialize(pub_key_hash)',
  '    super(pub_key_hash)',
  '    @pub_key_hash = pub_key_hash',
  '  end',
  '',
  '=begin',
  '  Old debugging entry point, disabled:',
  '  runar_public sig: Sig, pk: PubKey',
  '  def drain(sig, pk)',
  '    assert true',
  '  end',
  'end',
  '=end',
  '',
  '  runar_public sig: Sig, pub_key: PubKey',
  '  def unlock(sig, pub_key)',
  '    assert hash160(pub_key) == @pub_key_hash',
  '    assert check_sig(sig, pub_key)',
  '  end',
  'end',
  '',
].join('\n');

const COMMENT_SHAPES: Record<string, string> = {
  attack: ATTACK,
  crlf: ATTACK.replace(/\n/g, '\r\n'),
  trailing: ATTACK.replace('\n=begin\n', '\n=begin some text\n').replace('\n=end\n', '\n=end trailing words\n'),
  tab: ATTACK.replace('\n=begin\n', '\n=begin\tx\n').replace('\n=end\n', '\n=end\tx\n'),
  notes: ATTACK.replace(/\n=begin\n[\s\S]*?\n=end\n/, '\n=begin\n  Legacy notes\n=end\n'),
};

const CONTROL_SHAPES: Record<string, string> = {
  indented: ATTACK.replace('\n=begin\n', '\n  =begin\n').replace('\n=end\n', '\n  =end\n'),
  beginx: ATTACK.replace('\n=begin\n', '\n=beginx\n'),
};

const UNTERMINATED = ATTACK.replace('\n=end\n', '\n');
const UNTERMINATED_MSG = "unterminated '=begin' block comment starting at line 11: missing '=end'";

interface Run {
  status: number | null;
  hex: string | null;
  out: string;
}

function run(tier: Tier, file: string): Run {
  const r = spawnSync(tier.cmd!, [...tier.prefix, ...tier.argsFor(file)], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) throw new Error(`${tier.id} could not run: ${r.error.message}`);
  const stdout = r.stdout ?? '';
  const hexLines = stdout.split(/\r?\n/).map((l) => l.trim()).filter((l) => /^[0-9a-f]+$/i.test(l));
  return {
    status: r.status,
    hex: r.status === 0 && hexLines.length > 0 ? hexLines[hexLines.length - 1]!.toLowerCase() : null,
    out: `${stdout}\n${r.stderr ?? ''}`,
  };
}

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
let dir = '';

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n021-rb-'));
});

function write(name: string, src: string): string {
  const p = join(dir, `${name}.runar.rb`);
  writeFileSync(p, src);
  return p;
}

describe('N-021 .runar.rb =begin/=end — seven-tier positive parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [name, src] of Object.entries(COMMENT_SHAPES)) {
    for (const tier of TIERS) {
      it(`${tier.id} compiles the ${name} shape to the basic-p2pkh golden`, () => {
        const r = run(tier, write(name, src));
        expect(r.hex, `${tier.id} ${name}: exit ${r.status}\n${r.out.slice(0, 800)}`).toBe(GOLDEN);
      });
    }
  }

  for (const tier of TIERS) {
    it(`${tier.id} refuses an unterminated =begin with the shared text`, () => {
      const r = run(tier, write('unterminated', UNTERMINATED));
      expect(r.status, r.out.slice(0, 800)).not.toBe(0);
      expect(r.out).toContain(UNTERMINATED_MSG);
    });
  }

  for (const [name, src] of Object.entries(CONTROL_SHAPES)) {
    it(`the ${name} control (not a comment) gives one result in every tier`, () => {
      const file = write(name, src);
      const results = TIERS.map((t) => `${t.id}=${run(t, file).hex ?? 'ERR'}`);
      const distinct = new Set(results.map((r) => r.split('=')[1]));
      expect(distinct.size, results.join(' ')).toBe(1);
    });
  }
});
