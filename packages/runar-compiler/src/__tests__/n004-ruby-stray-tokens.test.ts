import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile } from '../index.js';
import { parseRubySource } from '../passes/01-parse-ruby.js';

/**
 * N-004 (CL-BUG-257) — the .runar.rb class body and the text after the class.
 *
 * N-021 made a column-0 `=begin` ... `=end` a comment, but the parser still
 * skipped any class-body token it did not recognise and ignored everything
 * after the class's `end`. An INDENTED `=begin` is not a comment in Ruby: it
 * lexes as `=` then `begin`, both were skipped, the "commented-out" `drain`
 * was parsed as a method, the `end` closing the block closed the class, and
 * the real guarded `unlock` after it was silently dropped. The contract
 * compiled with `drain` (assert true) as its only spend path.
 *
 * The rule: a class-body token that is not `prop`, `runar_public`, `params`,
 * `def`, or one of Ruby's bare `private` / `public` visibility markers (used
 * by examples/ruby, and a no-op here: visibility comes from `runar_public`)
 * is refused with "Unexpected token in class body: '<tok>'"; the first token
 * after the class's `end` is refused with "Unexpected token after class end:
 * '<tok>'". Every tier refuses with the same text.
 *
 * What this proves: in the reference tier the indented-`=begin` backdoor, a
 * stray class-body token (`42 + ?`, `= end`, a bare identifier) and trailing
 * code after the class (an identifier, `end`, `def`, a second class) are
 * parse errors with the shared text at the offending token, and none of them
 * compiles; the bare `private` / `public` markers and the plain P2PKH still
 * compile to the basic-p2pkh golden.
 * What it does NOT prove: the other six tiers (their own suites and
 * conformance/negatives/n004-rb-stray-token-parity.test.ts cover those);
 * unknown characters dropped by a tier's LEXER (they never reach the parser);
 * a class with no closing `end`.
 */

const GOLDEN = readFileSync(
  resolve(__dirname, '../../../../conformance/tests/basic-p2pkh/expected-script.hex'),
  'utf8',
).trim();

const FILE = 'P2PKH.runar.rb';

const P2PKH = (body: string, tail: string): string =>
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

/** The F-018 backdoor with its markers indented: not a comment in Ruby. */
const INDENTED = P2PKH(
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

const BODY = (tok: string): string => `Unexpected token in class body: '${tok}'`;
const AFTER = (tok: string): string => `Unexpected token after class end: '${tok}'`;

function errors(src: string): Array<{ message: string; line?: number }> {
  return parseRubySource(src, FILE).errors.map((e) => ({ message: e.message, line: e.loc?.line }));
}

/** [name, source, expected first diagnostic, its line]. */
const REFUSED: Array<[string, string, string, number]> = [
  ['the indented =begin backdoor', INDENTED, BODY('='), 11],
  ['a stray `42 + ?` in the class body', P2PKH('\n  42 + ?\n', ''), BODY('42'), 11],
  ['a stray `= end` in the class body', P2PKH('\n  = end\n', ''), BODY('='), 11],
  ['a bare identifier in the class body', P2PKH('\n  foo\n', ''), BODY('foo'), 11],
  ['an identifier after the class end', P2PKH('', 'foo\n'), AFTER('foo'), 17],
  ['a second `end` after the class end', P2PKH('', 'end\n'), AFTER('end'), 17],
  ['a method after the class end', P2PKH('', 'def drain(sig)\n  assert true\nend\n'), AFTER('def'), 17],
  ['a second class after the class end', P2PKH('', 'class Other < Runar::SmartContract\nend\n'), AFTER('class'), 17],
];

describe('N-004 .runar.rb stray class-level tokens are refused (reference tier)', () => {
  for (const [name, src, msg, line] of REFUSED) {
    it(`${name}: refused with the shared text at the token`, () => {
      const errs = errors(src);
      expect(errs[0], JSON.stringify(errs)).toEqual({ message: msg, line });
      expect(compile(src, { fileName: FILE }).success).toBe(false);
    });
  }

  it('the indented backdoor no longer compiles to a drain-only contract', () => {
    const c = compile(INDENTED, { fileName: FILE, disableConstantFolding: true });
    expect(c.success).toBe(false);
    expect(c.artifact).toBeUndefined();
  });

  const ACCEPTED: Record<string, string> = {
    'the plain P2PKH': P2PKH('', ''),
    'bare `private` / `public` markers': P2PKH('\n  private\n\n  public\n', ''),
    'blank lines and comments after the class end': P2PKH('', '\n# trailing note\n\n'),
  };
  for (const [name, src] of Object.entries(ACCEPTED)) {
    it(`${name} still compiles to the basic-p2pkh golden`, () => {
      expect(errors(src)).toEqual([]);
      const c = compile(src, { fileName: FILE, disableConstantFolding: true });
      expect(c.success).toBe(true);
      expect(c.artifact!.script.toLowerCase()).toBe(GOLDEN);
    });
  }
});
