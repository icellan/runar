import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile } from '../index.js';
import { parseRubySource } from '../passes/01-parse-ruby.js';

/**
 * N-021 (CL-BUG-197) — `=begin` ... `=end` embedded documents in .runar.rb.
 *
 * The reference tier's Ruby-surface tokenizer knew only `#` comments. In a
 * column-0 `=begin` ... `=end` block every line was lexed as live code: a
 * method "commented out" there became a real spending entry point, the `=` of
 * `=end` was skipped as an unknown class-body token and its `end` closed the
 * class early, so the real guarded method after the block was dropped. The
 * crafted P2PKH below (with a disabled `drain` backdoor) compiled to 517777
 * (OP_TRUE OP_NIP OP_NIP, anyone-can-spend) with ABI [drain], and @bsv/sdk
 * Spend.validate accepted a keyless spend (see
 * packages/runar-testing/src/__tests__/n021-ruby-block-comment-spend.test.ts).
 *
 * The rule (user decision R11) is the Ruby tier's F-018 rule, already ported
 * to Go by F-012, which is Ruby's own: `=begin` / `=end` open and close a block
 * comment only at column 0 and only as a whole word (followed by whitespace or
 * end of line). Every line from `=begin` through `=end` is a comment,
 * including any text after either marker. An unterminated `=begin` is refused
 * with "unterminated '=begin' block comment starting at line N: missing
 * '=end'", located at the opener's line (column 0 = no column, as in Go).
 *
 * What this proves: in the reference tier the crafted contract parses to
 * exactly `unlock` (LF, CRLF, text or a tab after the markers) and compiles
 * (fold OFF) to the basic-p2pkh golden with ABI [unlock]; an unterminated
 * `=begin` (including one closed only by `=endx`) is refused with the shared
 * text at its line; an indented `=begin` and `=beginx` do not open a comment.
 * What it does NOT prove: the other six tiers (their own suites and
 * conformance/negatives cover those); the parser's separate silent skip of
 * unknown class-body tokens (N-004); `__END__` or other Ruby lexical forms.
 */

const GOLDEN = readFileSync(
  resolve(__dirname, '../../../../conformance/tests/basic-p2pkh/expected-script.hex'),
  'utf8',
).trim();

const FILE = 'P2PKH.runar.rb';

// Joined, not a template literal with indentation: `=begin` / `=end` must sit
// at column 0 exactly as an attacker would place them.
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

/** 1-based line of `=begin` in ATTACK. */
const BEGIN_LINE = 11;

const unterminatedMsg = (line: number) =>
  `unterminated '=begin' block comment starting at line ${line}: missing '=end'`;

function methods(source: string): string[] {
  return parseRubySource(source, FILE).contract?.methods.map((m) => m.name) ?? [];
}

const VARIANTS: Record<string, string> = {
  lf: ATTACK,
  crlf: ATTACK.replace(/\n/g, '\r\n'),
  'text after markers': ATTACK.replace('\n=begin\n', '\n=begin legacy notes\n').replace(
    '\n=end\n',
    '\n=end trailing words\n',
  ),
  'tab after markers': ATTACK.replace('\n=begin\n', '\n=begin\tx\n').replace('\n=end\n', '\n=end\tx\n'),
};

describe('N-021 .runar.rb =begin/=end is a comment (reference tier)', () => {
  for (const [name, src] of Object.entries(VARIANTS)) {
    it(`${name}: the commented-out backdoor is not a spend path; unlock survives`, () => {
      const r = parseRubySource(src, FILE);
      expect(r.errors.map((e) => e.message)).toEqual([]);
      expect(r.contract!.methods.map((m) => m.name)).toEqual(['unlock']);
      expect(r.contract!.properties.map((p) => p.name)).toEqual(['pubKeyHash']);
    });

    it(`${name}: compiles to the basic-p2pkh golden with ABI [unlock]`, () => {
      const c = compile(src, { fileName: FILE, disableConstantFolding: true });
      expect(c.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message)).toEqual([]);
      expect(c.success).toBe(true);
      expect(c.artifact!.abi.methods.filter((m) => m.isPublic).map((m) => m.name)).toEqual(['unlock']);
      expect(c.artifact!.script.toLowerCase()).toBe(GOLDEN);
    });
  }

  it('a notes-only block between methods leaves the contract intact', () => {
    const src = ATTACK.replace(
      /\n=begin\n[\s\S]*?\n=end\n/,
      '\n=begin\n  Legacy notes\n=end\n',
    );
    expect(methods(src)).toEqual(['unlock']);
  });

  it('an unterminated =begin is refused at its line with the shared text', () => {
    const src = ATTACK.replace('\n=end\n', '\n');
    const errs = parseRubySource(src, FILE).errors;
    const d = errs.find((e) => e.message === unterminatedMsg(BEGIN_LINE));
    expect(d, JSON.stringify(errs)).toBeDefined();
    expect(d!.loc?.line).toBe(BEGIN_LINE);
    expect(d!.loc?.column).toBe(0);
    expect(compile(src, { fileName: FILE }).success).toBe(false);
  });

  it('`=endx` does not close a block (whole word only), so the block is unterminated', () => {
    const src = ATTACK.replace('\n=end\n', '\n=endx\n');
    const msgs = parseRubySource(src, FILE).errors.map((e) => e.message);
    expect(msgs).toContain(unterminatedMsg(BEGIN_LINE));
  });

  it('a =begin on the last line (no trailing newline) is unterminated', () => {
    const src = "require 'runar'\n=begin";
    expect(parseRubySource(src, FILE).errors.map((e) => e.message)).toContain(unterminatedMsg(2));
  });

  // Boundary controls: only a column-0 whole-word `=begin` opens a comment, so
  // the lines after these are still lexed as code (`drain` is parsed). They
  // assert nothing else about the parse; the parser's tolerance of stray
  // class-body tokens is N-004.
  it('an indented =begin is not a comment opener', () => {
    const src = ATTACK.replace('\n=begin\n', '\n  =begin\n').replace('\n=end\n', '\n  =end\n');
    expect(methods(src)).toContain('drain');
  });

  it('`=beginx` is not a comment opener', () => {
    expect(methods(ATTACK.replace('\n=begin\n', '\n=beginx\n'))).toContain('drain');
  });
});
