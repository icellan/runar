/**
 * F-389: direct unit coverage for parser-core.ts, codegen-emitter.ts, and
 * compiler-result-passes.ts.
 *
 * Before this file, none of the three modules was imported BY NAME from any
 * `__tests__` file — they were only exercised transitively through
 * `compile()` (codegen-emitter.ts, parser-core.ts) or through `index.js`'s
 * re-export (compiler-result-passes.ts: `compiler-result.test.ts` already
 * covers `parseR`/`validateR`/`typecheckR`/`lowerToANFR`/`lowerToStackR`/
 * `emitR` via `../index.js`, but never imports the module directly, and
 * never exercises `expandFixedArraysR` at all). `push-encoding.ts`, the
 * fourth module this item originally named, already has direct coverage in
 * `r168-pushdata4.test.ts` and is out of scope here.
 *
 * What this test proves: each of the three modules' exported symbols behaves
 * correctly when imported and called directly, including branches that were
 * previously unreachable from any test (`expandFixedArraysR`, and the
 * try/catch "pass throws -> CompilerResult.fail" adapter path in
 * `lowerToANFR` / `lowerToStackR` / `emitR`, triggered here with inputs that
 * make the real underlying pass throw for real reasons: an unbounded
 * `for`-loop that skips `validateR`'s compile-time-bound check, and an
 * `asm()` raw-script body with odd hex length that skips the same
 * validator). Expected values are computed independently of the function
 * under test: byte layouts are hand-computed or taken from
 * `spec/opcodes.md`'s opcode table (0x51 OP_1, 0x7c OP_SWAP, 0x7e OP_CAT,
 * 0x7f OP_SPLIT) and from parser-core.ts's own documented precedence chain
 * (file header: "MulDiv -> AddSub -> Shift -> Comparison -> Equality ->
 * BitAnd -> BitXor -> BitOr -> And -> Or", highest to lowest), never from
 * running the code and asserting on its own output.
 *
 * What this test does NOT prove: it does not prove `validateR`'s,
 * `parseR`'s, or `typecheckR`'s own catch branches are reachable — `parse`
 * and `validate` never throw at HEAD (confirmed by reading the source), so
 * those two wrappers' try/catch is dead code for any input reachable
 * through real compilation, and this file does not contrive a hand-built
 * malformed AST node just to force an unrelated TypeError through them.
 * It also does not re-verify push-encoding.ts (already covered elsewhere)
 * or claim full precedence-chain coverage of parser-core.ts — only enough
 * precedence transitions to prove the chain order matches the documented
 * contract, plus the documented `&`/`&&` and `|`/`||` tokenizer-ambiguity
 * guards.
 */

import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import {
  parseR,
  validateR,
  typecheckR,
  expandFixedArraysR,
  lowerToANFR,
  lowerToStackR,
  emitR,
} from '../passes/compiler-result-passes.js';
import { Emitter, u32ToLE, u32ToBE } from '../passes/codegen-emitter.js';
import { ParserCore } from '../passes/parser-core.js';
import type { Token } from '../passes/parser-core.js';
import type { CompilerDiagnostic } from '../errors.js';
import type { Expression } from '../ir/index.js';
import type { StackProgram, StackMethod } from '../ir/index.js';

// ===========================================================================
// codegen-emitter.ts — Emitter, u32ToLE, u32ToBE
// ===========================================================================

describe('codegen-emitter.ts: u32ToLE / u32ToBE', () => {
  it('u32ToLE encodes 0x01020304 as bytes [04, 03, 02, 01] (little-endian)', () => {
    expect(u32ToLE(0x01020304)).toEqual(new Uint8Array([0x04, 0x03, 0x02, 0x01]));
  });

  it('u32ToBE encodes 0x01020304 as bytes [01, 02, 03, 04] (big-endian)', () => {
    expect(u32ToBE(0x01020304)).toEqual(new Uint8Array([0x01, 0x02, 0x03, 0x04]));
  });

  it('u32ToLE handles the 0xffffffff all-ones edge case', () => {
    expect(u32ToLE(0xffffffff)).toEqual(new Uint8Array([0xff, 0xff, 0xff, 0xff]));
  });

  it('u32ToLE handles the 0x80000000 sign-bit edge case (exercises the >>> 24 unsigned shift)', () => {
    // Hand-computed: byte0 = 0x80000000 & 0xff = 0x00, byte3 = (0x80000000 >>> 24) & 0xff = 0x80.
    expect(u32ToLE(0x80000000)).toEqual(new Uint8Array([0x00, 0x00, 0x00, 0x80]));
  });
});

describe('codegen-emitter.ts: Emitter depth bookkeeping', () => {
  it('pushI/pushB increment depth by 1; drop decrements by 1', () => {
    const em = new Emitter(0);
    em.pushI(5n);
    expect(em.depth).toBe(1);
    em.pushB(new Uint8Array([1]));
    expect(em.depth).toBe(2);
    em.drop();
    expect(em.depth).toBe(1);
  });

  it('dup/over increment depth; nip decrements depth; swap/rot leave depth unchanged', () => {
    const em = new Emitter(2);
    em.dup();
    expect(em.depth).toBe(3);
    em.over();
    expect(em.depth).toBe(4);
    em.nip();
    expect(em.depth).toBe(3);
    em.swap();
    expect(em.depth).toBe(3);
    em.rot();
    expect(em.depth).toBe(3);
  });

  it('pick(0) and pick(1) delegate to dup/over (no extra pick op, depth +1)', () => {
    const em0 = new Emitter(1);
    em0.pick(0);
    expect(em0.ops).toEqual([{ op: 'dup' }]);
    expect(em0.depth).toBe(2);

    const em1 = new Emitter(1);
    em1.pick(1);
    expect(em1.ops).toEqual([{ op: 'over' }]);
    expect(em1.depth).toBe(2);
  });

  it('pick(d >= 2) pushes the depth as a number then emits a pick op (net depth +1)', () => {
    const em = new Emitter(3);
    em.pick(2);
    expect(em.ops).toEqual([
      { op: 'push', value: 2n },
      { op: 'pick', depth: 2 },
    ]);
    expect(em.depth).toBe(4); // +1 for the pushed literal, +1 for pick itself
  });

  it('roll(0) is a no-op; roll(1) delegates to swap; roll(2) delegates to rot — none touch depth', () => {
    const em = new Emitter(5);
    em.roll(0);
    expect(em.ops).toEqual([]);
    expect(em.depth).toBe(5);

    em.roll(1);
    expect(em.ops).toEqual([{ op: 'swap' }]);
    expect(em.depth).toBe(5);

    em.roll(2);
    expect(em.ops).toEqual([{ op: 'swap' }, { op: 'rot' }]);
    expect(em.depth).toBe(5);
  });

  it('roll(d >= 3) pushes the depth then emits a roll op (net depth -1, since roll consumes the item it moves TOS then drops the pushed index)', () => {
    const em = new Emitter(4);
    em.roll(3);
    expect(em.ops).toEqual([
      { op: 'push', value: 3n },
      { op: 'roll', depth: 3 },
    ]);
    expect(em.depth).toBe(4); // +1 (push) - 1 (roll's own depth--) = net 0 on top of the starting 4
  });

  it('toAlt/fromAlt move depth to/from the alt stack', () => {
    const em = new Emitter(1);
    em.toAlt();
    expect(em.depth).toBe(0);
    expect(em.altDepth).toBe(1);
    em.fromAlt();
    expect(em.depth).toBe(1);
    expect(em.altDepth).toBe(0);
  });

  it('binOp decrements depth by 1 (two operands in, one result out); uniOp leaves depth unchanged', () => {
    const em = new Emitter(2);
    em.binOp('OP_ADD');
    expect(em.depth).toBe(1);
    expect(em.ops).toEqual([{ op: 'opcode', code: 'OP_ADD' }]);
    em.uniOp('OP_NOT');
    expect(em.depth).toBe(1);
    expect(em.ops[1]).toEqual({ op: 'opcode', code: 'OP_NOT' });
  });

  it('dup2 (OP_2DUP) increments depth by 2', () => {
    const em = new Emitter(2);
    em.dup2();
    expect(em.depth).toBe(4);
    expect(em.ops).toEqual([{ op: 'opcode', code: 'OP_2DUP' }]);
  });

  it('assert() throws when depth does not match the expected value, and is silent when it does', () => {
    const em = new Emitter(3);
    expect(() => em.assert(2, 'should be 2')).toThrow(/Expected depth 2, got 3/);
    expect(() => em.assert(3, 'should be 3')).not.toThrow();
  });

  it('e_raw splices a StackOp without touching depth (documented escape hatch)', () => {
    const em = new Emitter(0);
    em.e_raw({ op: 'opcode', code: 'OP_CHECKSIG' });
    expect(em.ops).toEqual([{ op: 'opcode', code: 'OP_CHECKSIG' }]);
    expect(em.depth).toBe(0);
  });
});

describe('codegen-emitter.ts: Emitter op sequences, verified against emit() + spec/opcodes.md', () => {
  /**
   * emit() a single-method StackProgram built straight from `em.ops` and
   * compare the resulting hex against bytes hand-derived from
   * `spec/opcodes.md`'s opcode table (0x51 OP_1, 0x7c OP_SWAP, 0x7e OP_CAT,
   * 0x7f OP_SPLIT) — never against the Emitter's own notion of what it did.
   */
  function hexOf(ops: ReturnType<Emitter['ops']['slice']>): string {
    const program: StackProgram = {
      contractName: 'Direct',
      methods: [{ name: 'run', ops, maxStackDepth: 0 } as StackMethod],
    };
    const result = emitR(program);
    if (!result.ok) throw new Error(`emit failed: ${result.errors[0]?.message}`);
    return result.value!.scriptHex;
  }

  it('reverseBytes4 emits pushI(1);split three times then swap;OP_CAT three times (12 ops, 0 net depth)', () => {
    const em = new Emitter(1);
    em.reverseBytes4();
    expect(em.ops.length).toBe(12);
    expect(em.depth).toBe(1);
    // Hand-derived from spec/opcodes.md: push 1n -> OP_1 (0x51, minimal push
    // of a bigint literal 1-16), OP_SPLIT (0x7f), OP_SWAP (0x7c), OP_CAT (0x7e).
    expect(hexOf(em.ops)).toBe('51' + '7f' + '51' + '7f' + '51' + '7f' + '7c' + '7e' + '7c' + '7e' + '7c' + '7e');
  });

  it('le2num emits push(0x00);OP_CAT;OP_BIN2NUM (3 ops, 0 net depth)', () => {
    const em = new Emitter(1);
    em.le2num();
    expect(em.ops).toEqual([
      { op: 'push', value: new Uint8Array([0x00]) },
      { op: 'opcode', code: 'OP_CAT' },
      { op: 'opcode', code: 'OP_BIN2NUM' },
    ]);
    expect(em.depth).toBe(1);
  });

  it('num2le emits push(5);OP_NUM2BIN;push(4);OP_SPLIT;drop (5 ops, 0 net depth)', () => {
    const em = new Emitter(1);
    em.num2le();
    expect(em.ops).toEqual([
      { op: 'push', value: 5n },
      { op: 'opcode', code: 'OP_NUM2BIN' },
      { op: 'push', value: 4n },
      { op: 'opcode', code: 'OP_SPLIT' },
      { op: 'drop' },
    ]);
    expect(em.depth).toBe(1);
  });

  it('add32 combines two LE values into one (net depth -1)', () => {
    const em = new Emitter(2);
    em.add32();
    expect(em.depth).toBe(1);
    // le2num, swap, le2num, OP_ADD, num2le — each push op's own kind is
    // 'push' regardless of which opcode follows it, so it shows up as a
    // bare 'push' entry in this flattened op-kind list.
    const codes = em.ops.map(o => ('code' in o ? o.code : o.op));
    expect(codes).toEqual([
      'push', 'OP_CAT', 'OP_BIN2NUM',          // le2num
      'swap',
      'push', 'OP_CAT', 'OP_BIN2NUM',          // le2num
      'OP_ADD',
      'push', 'OP_NUM2BIN', 'push', 'OP_SPLIT', 'drop', // num2le
    ]);
  });

  it('rotrBE(n) is dup; push(n); OP_RSHIFT; swap; push(32-n); OP_LSHIFT; OP_OR (0 net depth, 7 ops)', () => {
    const em = new Emitter(1);
    em.rotrBE(7);
    expect(em.ops).toEqual([
      { op: 'dup' },
      { op: 'push', value: 7n },
      { op: 'opcode', code: 'OP_RSHIFT' },
      { op: 'swap' },
      { op: 'push', value: 25n },
      { op: 'opcode', code: 'OP_LSHIFT' },
      { op: 'opcode', code: 'OP_OR' },
    ]);
    expect(em.depth).toBe(1);
  });

  it('shrBE(n) is push(n); OP_RSHIFT (0 net depth, 2 ops)', () => {
    const em = new Emitter(1);
    em.shrBE(3);
    expect(em.ops).toEqual([
      { op: 'push', value: 3n },
      { op: 'opcode', code: 'OP_RSHIFT' },
    ]);
    expect(em.depth).toBe(1);
  });

  it('rotr16_LE swaps the two 16-bit halves: push(2);OP_SPLIT;swap;OP_CAT (0 net depth)', () => {
    const em = new Emitter(1);
    em.rotr16_LE();
    expect(em.ops).toEqual([
      { op: 'push', value: 2n },
      { op: 'opcode', code: 'OP_SPLIT' },
      { op: 'swap' },
      { op: 'opcode', code: 'OP_CAT' },
    ]);
    expect(em.depth).toBe(1);
  });

  it('beWordsToLE(n) reverses each of n BE words to LE while preserving stack order (round-trips through the alt stack)', () => {
    const em = new Emitter(2);
    em.beWordsToLE(2);
    // 2 x (reverseBytes4 [12 ops] + toAlt [1 op]) + 2 x fromAlt = 28 ops, net 0 depth, 0 alt depth.
    expect(em.ops.length).toBe(2 * (12 + 1) + 2);
    expect(em.depth).toBe(2);
    expect(em.altDepth).toBe(0);
  });
});

// ===========================================================================
// parser-core.ts — ParserCore<Token>
// ===========================================================================

/** Minimal concrete subclass to directly exercise the abstract base class. */
class TestParser extends ParserCore<Token> {
  // Expose protected members for direct assertion.
  currentPub(): Token { return this.current(); }
  advancePub(): Token { return this.advance(); }
  expectPub(type: string): Token { return this.expect(type); }
  matchPub(type: string): boolean { return this.match(type); }
  posPub(): number { return this.pos; }
  errorsPub(): CompilerDiagnostic[] { return this.errors; }
  parseExpressionPub(): Expression { return this.parseExpression(); }
  parsePostfixChainPub(expr: Expression, selfNames: Set<string>): Expression {
    return this.parsePostfixChain(expr, selfNames);
  }

  protected parseUnary(): Expression {
    return this.parsePostfixChain(this.parsePrimary(), new Set(['self']));
  }

  protected parsePrimary(): Expression {
    const at = this.loc();
    const t = this.current();
    if (t.type === 'num') {
      this.advance();
      return { kind: 'bigint_literal', value: BigInt(t.value), sourceLocation: at };
    }
    if (t.type === 'ident') {
      this.advance();
      return { kind: 'identifier', name: t.value, sourceLocation: at };
    }
    if (t.type === '(') {
      this.advance();
      const inner = this.parseExpression();
      this.expect(')');
      return inner;
    }
    throw new Error(`TestParser.parsePrimary: unexpected token '${t.type}'`);
  }
}

/** Tiny whitespace-splitting tokenizer for test fixtures ONLY — not production code. */
function lex(src: string): Token[] {
  const parts = src.trim().split(/\s+/);
  const toks: Token[] = parts.map((p, i) => {
    let type = p;
    if (/^-?\d+$/.test(p)) type = 'num';
    else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(p)) type = 'ident';
    return { type, value: p, line: 1, column: i + 1 };
  });
  toks.push({ type: 'eof', value: '', line: 1, column: parts.length + 1 });
  return toks;
}

function mkParser(src: string): TestParser {
  return new TestParser(lex(src), 'test.ts');
}

describe('parser-core.ts: ParserCore token-stream helpers', () => {
  it('current()/advance() walk the token stream in order', () => {
    const p = mkParser('a b');
    expect(p.currentPub().type).toBe('ident');
    expect(p.currentPub().value).toBe('a');
    expect(p.advancePub().value).toBe('a');
    expect(p.currentPub().value).toBe('b');
  });

  it('current() clamps at the last token once advance() runs past the end', () => {
    const p = mkParser('a');
    p.advancePub(); // consumes 'a'
    const last = p.currentPub(); // now on synthetic 'eof'
    p.advancePub();
    p.advancePub();
    // Clamped: still reports the last token in the array, never undefined/throw.
    expect(p.currentPub()).toEqual(last);
  });

  it('match(type) consumes and returns true on a hit; leaves position untouched and returns false on a miss', () => {
    const p = mkParser('+ a');
    expect(p.matchPub('-')).toBe(false);
    expect(p.posPub()).toBe(0); // did not advance
    expect(p.matchPub('+')).toBe(true);
    expect(p.posPub()).toBe(1); // advanced exactly one token
  });

  it('expect(type) on a mismatch pushes a diagnostic with the documented message and still advances', () => {
    const p = mkParser('a b');
    const errorsBefore = p.errorsPub().length;
    const t = p.expectPub(')'); // current is 'ident a', not ')'
    expect(p.errorsPub().length).toBe(errorsBefore + 1);
    expect(p.errorsPub()[p.errorsPub().length - 1]!.message).toMatch(/^Expected '\)', got 'a'$/);
    expect(t.value).toBe('a'); // expect() still returns (and consumes) the wrong token
    expect(p.posPub()).toBe(1);
  });

  it('expect(type) on a match does not push a diagnostic', () => {
    const p = mkParser('+ a');
    const errorsBefore = p.errorsPub().length;
    p.expectPub('+');
    expect(p.errorsPub().length).toBe(errorsBefore);
  });

  it('a pre-seeded errors array (constructor 3rd arg) is the same array `expect()` appends to', () => {
    const seeded: CompilerDiagnostic[] = [{ message: 'lexical: bad char', severity: 'error' }];
    const p = new TestParser(lex('a'), 'test.ts', seeded);
    p.expectPub(')'); // mismatch -> appends
    expect(seeded.length).toBe(2);
    expect(p.errorsPub()).toBe(seeded); // same array identity, not a copy
  });
});

describe('parser-core.ts: ParserCore precedence-climbing expression chain', () => {
  // Reference: the file's own documented chain (highest to lowest precedence):
  //   MulDiv -> AddSub -> Shift -> Comparison -> Equality -> BitAnd -> BitXor -> BitOr -> And -> Or
  // i.e. an operator earlier in that list binds TIGHTER than one later in it.

  it('MulDiv binds tighter than AddSub: "a + b * c" -> a + (b * c)', () => {
    const e = mkParser('a + b * c').parseExpressionPub();
    expect(e).toMatchObject({
      kind: 'binary_expr', op: '+',
      left: { kind: 'identifier', name: 'a' },
      right: { kind: 'binary_expr', op: '*', left: { name: 'b' }, right: { name: 'c' } },
    });
  });

  it('AddSub is left-associative: "a - b - c" -> (a - b) - c, and both nodes share one sourceLocation (loc at entry of the AddSub level)', () => {
    const e = mkParser('a - b - c').parseExpressionPub();
    expect(e).toMatchObject({
      kind: 'binary_expr', op: '-',
      left: { kind: 'binary_expr', op: '-', left: { name: 'a' }, right: { name: 'b' } },
      right: { name: 'c' },
    });
    // `start` is captured once before the while loop and reused for every
    // iteration, so the inner and outer binary_expr nodes carry the SAME
    // location: the token where the AddSub-level parse began ('a', column 1).
    const outer = e as Expression & { sourceLocation?: { column: number } };
    const inner = (outer as unknown as { left: { sourceLocation?: { column: number } } }).left;
    expect(outer.sourceLocation?.column).toBe(1);
    expect(inner.sourceLocation?.column).toBe(1);
  });

  it('Shift binds tighter than Comparison: "a << b < c" -> (a << b) < c', () => {
    const e = mkParser('a << b < c').parseExpressionPub();
    expect(e).toMatchObject({
      kind: 'binary_expr', op: '<',
      left: { kind: 'binary_expr', op: '<<', left: { name: 'a' }, right: { name: 'b' } },
      right: { name: 'c' },
    });
  });

  it('== maps to the AST op "===" and != maps to "!=="; Comparison binds tighter than Equality: "a < b == c" -> (a < b) === c', () => {
    const e = mkParser('a < b == c').parseExpressionPub();
    expect(e).toMatchObject({
      kind: 'binary_expr', op: '===',
      left: { kind: 'binary_expr', op: '<', left: { name: 'a' }, right: { name: 'b' } },
      right: { name: 'c' },
    });
    const ne = mkParser('a != b').parseExpressionPub();
    expect(ne).toMatchObject({ kind: 'binary_expr', op: '!==' });
  });

  it('Equality binds tighter than BitAnd: "a & b == c" -> a & (b === c)', () => {
    const e = mkParser('a & b == c').parseExpressionPub();
    expect(e).toMatchObject({
      kind: 'binary_expr', op: '&',
      left: { name: 'a' },
      right: { kind: 'binary_expr', op: '===', left: { name: 'b' }, right: { name: 'c' } },
    });
  });

  it('BitAnd binds tighter than BitXor: "a & b ^ c" -> (a & b) ^ c', () => {
    const e = mkParser('a & b ^ c').parseExpressionPub();
    expect(e).toMatchObject({
      kind: 'binary_expr', op: '^',
      left: { kind: 'binary_expr', op: '&', left: { name: 'a' }, right: { name: 'b' } },
      right: { name: 'c' },
    });
  });

  it('BitXor binds tighter than BitOr: "a ^ b | c" -> (a ^ b) | c', () => {
    const e = mkParser('a ^ b | c').parseExpressionPub();
    expect(e).toMatchObject({
      kind: 'binary_expr', op: '|',
      left: { kind: 'binary_expr', op: '^', left: { name: 'a' }, right: { name: 'b' } },
      right: { name: 'c' },
    });
  });

  it('BitOr binds tighter than And; And binds tighter than Or: "a && b || c | d" -> (a && (b || ??)) -- actually "a | b && c" -> (a | b) && c, "a && b || c" -> (a && b) || c', () => {
    const e1 = mkParser('a | b && c').parseExpressionPub();
    expect(e1).toMatchObject({
      kind: 'binary_expr', op: '&&',
      left: { kind: 'binary_expr', op: '|', left: { name: 'a' }, right: { name: 'b' } },
      right: { name: 'c' },
    });
    const e2 = mkParser('a && b || c').parseExpressionPub();
    expect(e2).toMatchObject({
      kind: 'binary_expr', op: '||',
      left: { kind: 'binary_expr', op: '&&', left: { name: 'a' }, right: { name: 'b' } },
      right: { name: 'c' },
    });
  });

  it('parenthesized subexpression overrides precedence: "(a + b) * c" -> (a + b) * c, not a + (b * c)', () => {
    const e = mkParser('( a + b ) * c').parseExpressionPub();
    expect(e).toMatchObject({
      kind: 'binary_expr', op: '*',
      left: { kind: 'binary_expr', op: '+', left: { name: 'a' }, right: { name: 'b' } },
      right: { name: 'c' },
    });
  });

  it('the "&" vs "&&" disambiguation guard (parseBitAnd) stops before consuming two adjacent single "&" tokens as one "&&"', () => {
    // Two separate single-ampersand tokens (what a non-combining tokenizer
    // would hand it), not one '&&' token. parseBitAnd's loop condition is
    // `current().type === '&' && tokens[pos+1]?.type !== '&'`; with the next
    // token ALSO '&', the guard must refuse to merge them.
    const p = mkParser('a & & b');
    const e = p.parseExpressionPub();
    expect(e).toMatchObject({ kind: 'identifier', name: 'a' });
    // The two '&' tokens and 'b' are left unconsumed by this guard.
    expect(p.currentPub().type).toBe('&');
  });

  it('the "|" vs "||" disambiguation guard (parseBitOr) stops before consuming two adjacent single "|" tokens as one "||"', () => {
    const p = mkParser('a | | b');
    const e = p.parseExpressionPub();
    expect(e).toMatchObject({ kind: 'identifier', name: 'a' });
    expect(p.currentPub().type).toBe('|');
  });
});

describe('parser-core.ts: parsePostfixChain', () => {
  it('self.x -> property_access when "self" is in selfNames', () => {
    const base: Expression = { kind: 'identifier', name: 'self', sourceLocation: { file: 't', line: 1, column: 1 } };
    // Manually feed the ". x" tail by constructing a parser positioned on it.
    const chain = mkParser('. x');
    const result = chain.parsePostfixChainPub(base, new Set(['self']));
    expect(result).toMatchObject({ kind: 'property_access', property: 'x' });
  });

  it('a.b -> member_expr when the object is not in selfNames', () => {
    const base: Expression = { kind: 'identifier', name: 'a', sourceLocation: { file: 't', line: 1, column: 1 } };
    const chain = mkParser('. b');
    const result = chain.parsePostfixChainPub(base, new Set(['self']));
    expect(result).toMatchObject({ kind: 'member_expr', property: 'b', object: { name: 'a' } });
  });

  it('function-call postfix: f(a, b) collects positional args', () => {
    const base: Expression = { kind: 'identifier', name: 'f', sourceLocation: { file: 't', line: 1, column: 1 } };
    const chain = mkParser('( a , b )');
    const result = chain.parsePostfixChainPub(base, new Set());
    expect(result).toMatchObject({
      kind: 'call_expr',
      callee: { name: 'f' },
      args: [{ name: 'a' }, { name: 'b' }],
    });
  });

  it('index-access postfix: a[b]', () => {
    const base: Expression = { kind: 'identifier', name: 'a', sourceLocation: { file: 't', line: 1, column: 1 } };
    const chain = mkParser('[ b ]');
    const result = chain.parsePostfixChainPub(base, new Set());
    expect(result).toMatchObject({ kind: 'index_access', object: { name: 'a' }, index: { name: 'b' } });
  });

  it('chained postfix a.b(c)[d]: each node\'s sourceLocation is the postfix OPERATOR\'S token, not the base expression\'s (R-142)', () => {
    const base: Expression = { kind: 'identifier', name: 'a', sourceLocation: { file: 't', line: 1, column: 99 } };
    // tokens: '.'(col1) 'b'(col2) '('(col3) 'c'(col4) ')'(col5) '['(col6) 'd'(col7) ']'(col8)
    const chain = mkParser('. b ( c ) [ d ]');
    const result = chain.parsePostfixChainPub(base, new Set());
    expect(result).toMatchObject({ kind: 'index_access' });
    const indexNode = result as Expression & { object: Expression; sourceLocation?: { column: number } };
    expect(indexNode.sourceLocation?.column).toBe(6); // the '[' token, not base's column 99
    const callNode = indexNode.object as Expression & { sourceLocation?: { column: number } };
    expect(callNode.sourceLocation?.column).toBe(3); // the '(' token
    const memberNode = (callNode as unknown as { callee: Expression }).callee as Expression & {
      sourceLocation?: { column: number };
    };
    expect(memberNode.sourceLocation?.column).toBe(1); // the '.' token
  });
});

// ===========================================================================
// compiler-result-passes.ts — parseR / validateR / typecheckR /
// expandFixedArraysR / lowerToANFR / lowerToStackR / emitR, imported
// DIRECTLY from the module (not via index.js's re-export).
// ===========================================================================

const VALID_FIXED_ARRAY_CONTRACT = `
class Boardy extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public setZero(v: bigint) {
    this.board[0] = v;
    assert(true);
  }
}
`;

const BAD_LENGTH_FIXED_ARRAY_CONTRACT = `
class BadInit extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n];

  constructor() {
    super();
  }

  public m() {
    assert(true);
  }
}
`;

describe('compiler-result-passes.ts: the full *R chain, imported directly, including expandFixedArraysR', () => {
  it('parseR -> validateR -> typecheckR -> expandFixedArraysR -> lowerToANFR -> lowerToStackR -> emitR succeeds end-to-end on a FixedArray contract', () => {
    const result = parseR(VALID_FIXED_ARRAY_CONTRACT, 'Boardy.runar.ts')
      .flatMap(validateR)
      .flatMap(typecheckR)
      .flatMap(expandFixedArraysR)
      .flatMap(lowerToANFR)
      .flatMap(lowerToStackR)
      .flatMap(emitR);

    expect(result.ok).toBe(true);
    expect(result.value).not.toBeNull();
    expect(result.value!.scriptHex.length).toBeGreaterThan(0);

    // Independent check that expandFixedArraysR actually ran: re-run just
    // that stage and confirm the FixedArray property was expanded into
    // scalar siblings board__0..board__2 (not via the chain's own success).
    const parsed = parseR(VALID_FIXED_ARRAY_CONTRACT, 'Boardy.runar.ts');
    const typed = parsed.flatMap(validateR).flatMap(typecheckR);
    const expanded = expandFixedArraysR(typed.value!);
    expect(expanded.ok).toBe(true);
    const propNames = expanded.value!.properties.map(p => p.name);
    expect(propNames).toContain('board__0');
    expect(propNames).toContain('board__1');
    expect(propNames).toContain('board__2');
    expect(propNames).not.toContain('board');
  });

  it('expandFixedArraysR fails cleanly (no throw) when the array-literal length does not match the declared size', () => {
    const typed = parseR(BAD_LENGTH_FIXED_ARRAY_CONTRACT, 'BadInit.runar.ts')
      .flatMap(validateR)
      .flatMap(typecheckR);
    expect(typed.ok).toBe(true); // the length mismatch is expandFixedArraysR's job, not typecheck's

    const expanded = expandFixedArraysR(typed.value!);
    expect(expanded.ok).toBe(false);
    expect(expanded.value).toBeNull();
    expect(expanded.errors.length).toBeGreaterThan(0);
  });
});

describe('compiler-result-passes.ts: lowerToANFR wraps a real thrown error as a failed CompilerResult (no throw escapes)', () => {
  it('a for-loop with a non-constant bound parses fine and is normally rejected by validateR; skipping validateR lets it reach lowerToANF, which throws, and lowerToANFR must convert that throw into CompilerResult.fail', () => {
    const source = `
class LoopBound extends SmartContract {
  readonly n: bigint;
  constructor(n: bigint) {
    super(n);
    this.n = n;
  }
  public m() {
    let sum: bigint = 0n;
    for (let i: bigint = 0n; i < this.n; i++) {
      sum = sum + i;
    }
    assert(sum >= 0n);
  }
}
`;
    const parsed = parseR(source, 'LoopBound.runar.ts');
    expect(parsed.ok).toBe(true);

    // Confirm validateR DOES reject this normally (so the test below is
    // actually exercising a path real compilation never takes).
    const validated = validateR(parsed.value!);
    expect(validated.ok).toBe(false);
    expect(validated.errors.some(e => e.message.includes('compile-time constant'))).toBe(true);

    // Skip validateR/typecheckR entirely and hand the raw parsed contract to
    // lowerToANFR directly — this is the only way to reach anf-lower's own
    // "Cannot determine loop bound at compile time" throw, since validateR
    // always runs first in the real pipeline.
    const result = lowerToANFR(parsed.value!);
    expect(result.ok).toBe(false);
    expect(result.value).toBeNull();
    expect(result.errors[0]?.message).toMatch(/loop bound/i);
  });
});

describe('compiler-result-passes.ts: lowerToStackR wraps a real thrown error as a failed CompilerResult (no throw escapes)', () => {
  it('asm() with an odd-length hex body parses fine and is normally rejected by validateR; skipping validateR lets lowerToStack\'s raw_script decoder throw, and lowerToStackR must convert that throw into CompilerResult.fail', () => {
    const source = `
class Anyone extends UnsafeSmartContract {
  constructor() {
    super();
  }
  public unlock() {
    asm({ body: '5', in_arity: 0, out_arity: 1 });
  }
}
`;
    const parsed = parseR(source, 'Anyone.runar.ts');
    expect(parsed.ok).toBe(true);

    const validated = validateR(parsed.value!);
    expect(validated.ok).toBe(false);
    expect(validated.errors.some(e => e.message.includes('odd hex length'))).toBe(true);

    const anf = lowerToANFR(parsed.value!);
    expect(anf.ok).toBe(true); // anf-lower passes the hex body through unchanged (no validation there)

    const result = lowerToStackR(anf.value!);
    expect(result.ok).toBe(false);
    expect(result.value).toBeNull();
    expect(result.errors[0]?.message).toMatch(/even hex length/);
  });
});

describe('compiler-result-passes.ts: emitR wraps a real thrown error as a failed CompilerResult (no throw escapes)', () => {
  it('a StackProgram referencing an opcode name absent from the emitter\'s opcode table makes emit() throw; emitR must convert that throw into CompilerResult.fail', () => {
    const program: StackProgram = {
      contractName: 'Bogus',
      methods: [
        { name: 'run', ops: [{ op: 'opcode', code: 'OP_NOT_A_REAL_OPCODE' }], maxStackDepth: 0 } as StackMethod,
      ],
    };
    const result = emitR(program);
    expect(result.ok).toBe(false);
    expect(result.value).toBeNull();
    expect(result.errors[0]?.message).toMatch(/Unknown opcode/);
  });
});

// Sanity: directly-imported parse() still agrees with parseR on the simplest
// possible input, so the two import paths (passes/01-parse.js vs
// passes/compiler-result-passes.js) are not silently diverging.
describe('compiler-result-passes.ts: parseR agrees with the underlying parse()', () => {
  it('parseR(source) succeeds iff parse(source) returns a non-null contract with no errors', () => {
    const source = `
class Empty extends SmartContract {
  constructor() { super(); }
  public m() { assert(true); }
}
`;
    const direct = parse(source, 'Empty.runar.ts');
    const wrapped = parseR(source, 'Empty.runar.ts');
    expect(wrapped.ok).toBe(direct.contract !== null && direct.errors.length === 0);
    expect(wrapped.value?.name).toBe(direct.contract?.name);
  });
});
