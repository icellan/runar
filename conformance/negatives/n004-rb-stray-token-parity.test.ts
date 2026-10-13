import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import {
  CONSENSUS_SPEND_CONTEXT,
  newConsensusSpend,
} from '../../packages/runar-testing/src/consensus-spend.js';
import { REPO, Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

/**
 * N-004 (CL-BUG-257) — stray class-level tokens on the .runar.rb surface,
 * seven-tier parity.
 *
 * N-021 made a column-0 `=begin` ... `=end` a comment in every tier. But every
 * tier's .runar.rb parser, the TS reference included, still skipped any
 * class-body token it did not recognise and ignored everything after the
 * class's `end`. An INDENTED `=begin` is not a comment in Ruby: it lexes as
 * `=` then `begin`; both were skipped, the "commented-out" `drain` became a
 * method, the block's `end` closed the class, and the guarded `unlock` after
 * it was dropped with no diagnostic. All seven tiers compiled the backdoor to
 * 517777 (OP_TRUE OP_NIP OP_NIP), which any unlocking script spends.
 *
 * The TS reference was fail-open too, so it was fixed first (ESCALATION
 * RULE) and the fix ported: a class-body token other than `prop`,
 * `runar_public`, `params`, `def` or a bare `private` / `public` marker
 * (examples/ruby uses them; they stay no-ops) is refused with
 * "Unexpected token in class body: '<tok>'", and the first token after the
 * class's `end` with "Unexpected token after class end: '<tok>'".
 *
 * What this proves:
 *   - every available tier refuses each shape below, and (all seven changed)
 *     prints the TS diagnostic for it;
 *   - every available tier still compiles the plain P2PKH, one with bare
 *     `private` / `public` markers, and one with blank lines and a comment
 *     after the class to the basic-p2pkh golden, in both fold modes;
 *   - under @bsv/sdk Spend (consensus rules) the pre-fix backdoor bytes
 *     (517777) accept a keyless spend, while the golden refuses it.
 * What it does NOT prove: characters a tier's LEXER drops before the parser
 *   sees them (Go and Zig skip unknown characters; the `42 + ?` shape is
 *   refused on `42` in every tier regardless), a class with no closing `end`,
 *   or any surface other than .runar.rb.
 */

const GOLDEN = readFileSync(join(REPO, 'conformance/tests/basic-p2pkh/expected-script.hex'), 'utf8').trim();

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

const BODY = (tok: string): string => `Unexpected token in class body: '${tok}'`;
const AFTER = (tok: string): string => `Unexpected token after class end: '${tok}'`;

const p2pkh = (body: string, tail: string): string =>
  [
    "require 'runar'",
    '',
    'class P2PKH < Runar::SmartContract',
    '  prop :pub_key_hash, Addr',
    '',
    '  def initialize(pub_key_hash)',
    '    super(pub_key_hash)',
    '    @pub_key_hash = pub_key_hash',
    '  end',
    body,
    '  runar_public sig: Sig, pub_key: PubKey',
    '  def unlock(sig, pub_key)',
    '    assert hash160(pub_key) == @pub_key_hash',
    '    assert check_sig(sig, pub_key)',
    '  end',
    'end',
    tail,
  ].join('\n');

/** The F-018 backdoor with its markers indented: code, not a comment. */
const INDENTED = p2pkh(
  [
    '',
    '  =begin',
    '  Old debugging entry point, disabled:',
    '  runar_public sig: Sig, pk: PubKey',
    '  def drain(sig, pk)',
    '    assert true',
    '  end',
    'end',
    '  =end',
    '',
  ].join('\n'),
  '',
);

/** [case name, source, TS diagnostic]. */
const REFUSED: Array<[string, string, string]> = [
  ['the indented =begin backdoor', INDENTED, BODY('=')],
  ['a stray `42 + ?` in the class body', p2pkh('\n  42 + ?\n', ''), BODY('42')],
  ['a stray `= end` in the class body', p2pkh('\n  = end\n', ''), BODY('=')],
  ['a bare identifier in the class body', p2pkh('\n  foo\n', ''), BODY('foo')],
  ['an identifier after the class end', p2pkh('', 'foo\n'), AFTER('foo')],
  ['a second `end` after the class end', p2pkh('', 'end\n'), AFTER('end')],
  ['a method after the class end', p2pkh('', 'def drain(sig)\n  assert true\nend\n'), AFTER('def')],
  ['a second class after the class end', p2pkh('', 'class Other < Runar::SmartContract\nend\n'), AFTER('class')],
];

const ACCEPTED: Array<[string, string]> = [
  ['the plain P2PKH', p2pkh('', '')],
  ['bare `private` / `public` markers', p2pkh('\n  private\n\n  public\n', '')],
  ['blank lines and a comment after the class end', p2pkh('', '\n# trailing note\n\n')],
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n004-rb-stray-'));
});

let seq = 0;
function write(src: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, 'P2PKH.runar.rb');
  writeFileSync(p, src);
  return p;
}

/** Run a tier and return its refusal diagnostic; fail if it compiled. */
function refusal(tier: Tier, file: string): string {
  const r = spawnSync(tier.cmd!, [...tier.prefix, ...tier.argsFor(file)], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) throw new Error(`${tier.id} could not run: ${r.error.message}`);
  if (r.status === 0) throw new Error(`${tier.id} ${file}: compiled (${r.stdout.trim().slice(-40)}), expected a refusal`);
  return `${r.stderr ?? ''}\n${r.stdout ?? ''}`;
}

function spends(lockingHex: string, unlockingHex: string): boolean {
  try {
    return newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
      otherInputs: [],
      outputs: [],
    }).validate();
  } catch {
    return false; // a thrown validation error is a failed spend
  }
}

describe('N-004 the indented backdoor (@bsv/sdk Spend)', () => {
  // `drain(sig, pk)` takes two pushes; OP_0 OP_0 is no signature at all.
  it('control: the pre-fix bytes of the backdoor (517777) accept a keyless spend', () => {
    expect(spends('517777', '0000')).toBe(true);
  });

  it('the basic-p2pkh golden refuses the same keyless spend', () => {
    expect(spends(GOLDEN, '0000')).toBe(false);
  });
});

describe('N-004 .runar.rb stray class-level tokens — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [name, src, diag] of REFUSED) {
    for (const tier of TIERS) {
      it(`${tier.id} refuses ${name} with the TS diagnostic`, () => {
        expect(refusal(tier, write(src))).toContain(diag);
      });
    }
  }

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    for (const [name, src] of ACCEPTED) {
      for (const tier of tiers) {
        it(`${tier.id} (${mode}) compiles ${name} to the basic-p2pkh golden`, () => {
          expect(compileHex(tier, write(src))).toBe(GOLDEN);
        });
      }
    }
  }
});
