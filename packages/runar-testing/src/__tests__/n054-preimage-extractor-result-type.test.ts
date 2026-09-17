/**
 * N-054 — the preimage extractors' RESULT TYPE was decided by a per-tier
 * heuristic that disagreed with the type checker, with itself, and across
 * tiers.
 *
 * `03-typecheck.ts` (and its six peers) already carry the authoritative
 * answer for all thirteen `extract*` builtins:
 *
 *     bigint      extractVersion  extractInputIndex  extractAmount
 *                 extractSequence extractLocktime    extractSigHashType
 *     ByteString  extractOutpoint extractScriptCode  extractPrevOutputScript
 *     Sha256      extractHashPrevouts extractHashSequence
 *                 extractOutputHash   extractOutputs
 *
 * and the stack lowerer agrees with it: every one of the six `bigint`
 * extractors ends its split sequence with OP_BIN2NUM, so what sits on the
 * stack is a SCRIPT NUMBER; none of the seven byte extractors do, so what
 * sits on the stack is a BYTE STRING.
 *
 * `04-anf-lower` then threw that away. It re-derives "is this expression
 * byte-typed?" from a hand-maintained list (`isByteTypedExpr`), and that
 * annotation is what picks OP_EQUAL vs OP_NUMEQUAL for `===`/`!==` and
 * OP_CAT vs OP_ADD for `+`. Three different wrong answers shipped:
 *
 *   Go, Python, Zig, Ruby, Java  `name.startsWith("extract")` — ALL thirteen
 *                                treated as bytes, the six numeric ones
 *                                included.
 *   TypeScript                   an explicit list holding extractVersion,
 *                                extractLocktime and extractSigHashType
 *                                (numeric — wrong) and missing
 *                                extractScriptCode, extractOutputs and
 *                                extractPrevOutputScript (bytes — wrong).
 *   Rust                         no extractor entry at all — ALL thirteen
 *                                treated as numeric, the seven byte ones
 *                                included.
 *
 * MEASURED BEFORE THE FIX (`--source X --hex --disable-constant-folding`):
 *
 *   assert(extractVersion(p) === 1n)      ts,go,py,zig,rb,java 88   rust 9d
 *   assert(extractAmount(p) === 3n)       go,py,zig,rb,java    88   ts,rust 9d
 *   assert(extractScriptCode(p) === …)    go,py,zig,rb,java    87   ts,rust 9c
 *   assert(extractLocktime(p) + 1n > 0n)  ts,go,py,zig,rb,java 51 7e (OP_CAT!)
 *                                         rust 8b (OP_1ADD)
 *
 * The three defects do NOT have the same severity, and the difference is
 * worth stating rather than blurring:
 *
 *   `+` lowered to OP_CAT   — a plain CORRECTNESS bug, independent of any
 *     node policy. Both operands are compiler-generated, and the script
 *     computes a concatenation where the source says addition:
 *     `extractLocktime(p) + 1n` over nLocktime 65280 evaluates to 0x00ff0001,
 *     not 65281. Six of seven tiers made contracts of that shape unspendable.
 *     Executed below.
 *
 *   numeric extractor + OP_EQUAL   — OVER-STRICT. OP_EQUAL compares the bytes
 *     of a value OP_BIN2NUM just minimised, so an operand encoding the same
 *     number differently is rejected. Executed below against `@bsv/sdk`'s
 *     interpreter, which is this repo's execution oracle. Note the honest
 *     bound: a node applying SCRIPT_VERIFY_MINIMALDATA would abort an
 *     OP_NUMEQUAL over that same non-minimal operand instead of accepting it,
 *     so on a standard relay path both opcodes end in "spend fails" and the
 *     defect is a semantic and cross-tier one rather than a live fund loss.
 *
 *   byte extractor + OP_NUMEQUAL   — UNDER-STRICT. OP_NUMEQUAL reads both
 *     operands as little-endian script numbers, so a trailing high-order zero
 *     byte and a `80` negative zero compare equal to values they are not
 *     byte-equal to: a hash or scriptCode comparison that accepts a padded
 *     variant is a covenant bypass. Executed below. Same bound as above —
 *     under MINIMALDATA the padded operand aborts the script instead of
 *     passing; the bypass needs consensus-only evaluation.
 *
 * What is unconditional in all three is the cross-tier divergence itself,
 * which conformance invariant 2 does not permit at any severity.
 *
 * THE RULE this suite pins: the comparison opcode follows the builtin's
 * declared return type, in every tier, byte for byte.
 *
 * A missing toolchain FAILS this suite rather than skipping it.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { ScriptVM } from '../index.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-n054-'));

// ---------------------------------------------------------------------------
// Contracts under test
// ---------------------------------------------------------------------------

/** The six extractors the type checker declares `bigint`. */
const NUMERIC_SRC = `import {
  SmartContract, assert, SigHashPreimage,
  extractVersion, extractLocktime, extractSigHashType,
  extractAmount, extractSequence, extractInputIndex,
} from 'runar-lang';

export class N054Numeric extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public go(p: SigHashPreimage) {
    assert(extractVersion(p) === 1n);
    assert(extractLocktime(p) === 2n);
    assert(extractSigHashType(p) === 65n);
    assert(extractAmount(p) === 3n);
    assert(extractSequence(p) === 4n);
    assert(extractInputIndex(p) === 5n);
  }
}
`;

/**
 * The seven extractors the type checker declares `ByteString` / `Sha256`.
 *
 * Both operands of every comparison are extractor calls on purpose: that is
 * the shape in which the classification is load-bearing. When one side is a
 * declared `ByteString` parameter or property the `||` in `isByteTypedExpr`
 * rescues the wrong classification, which is exactly why this defect survived.
 */
const BYTES_SRC = `import {
  SmartContract, assert, SigHashPreimage, ByteString,
  extractHashPrevouts, extractHashSequence, extractOutpoint,
  extractOutputHash, extractOutputs, extractScriptCode, extractPrevOutputScript,
} from 'runar-lang';

export class N054Bytes extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public go(p: SigHashPreimage, q: SigHashPreimage, h: ByteString) {
    assert(extractHashPrevouts(p) === extractHashPrevouts(q));
    assert(extractHashSequence(p) === extractHashSequence(q));
    assert(extractOutpoint(p) === extractOutpoint(q));
    assert(extractOutputHash(p) === extractOutputHash(q));
    assert(extractOutputs(p) === extractOutputs(q));
    assert(extractScriptCode(p) === extractScriptCode(q));
    assert(extractPrevOutputScript(0n, h) === extractScriptCode(q));
  }
}
`;

/** `+` reads the same annotation: OP_ADD for a number, OP_CAT for bytes. */
const PLUS_SRC = `import { SmartContract, assert, SigHashPreimage, extractLocktime, extractAmount } from 'runar-lang';

export class N054Plus extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public go(p: SigHashPreimage) {
    assert(extractLocktime(p) + 1n > 0n);
    assert(extractAmount(p) + 1n > 0n);
  }
}
`;

/** Single numeric comparison, small enough to execute end-to-end. */
const SEQ_SRC = `import { SmartContract, assert, SigHashPreimage, extractSequence } from 'runar-lang';

export class N054Seq extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public go(p: SigHashPreimage, n: bigint) { assert(extractSequence(p) === n); }
}
`;

/** Single byte comparison, small enough to execute end-to-end. */
const CODE_SRC = `import { SmartContract, assert, SigHashPreimage, extractScriptCode } from 'runar-lang';

export class N054Code extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public go(p: SigHashPreimage, q: SigHashPreimage) {
    assert(extractScriptCode(p) === extractScriptCode(q));
  }
}
`;

// ---------------------------------------------------------------------------
// Seven-tier compile harness
// ---------------------------------------------------------------------------

function write(name: string, src: string): string {
  const p = join(TMP, name);
  writeFileSync(p, src);
  return p;
}

function run(cmd: string, args: string[], cwd?: string): string {
  try {
    return execFileSync(cmd, args, {
      cwd, timeout: 120_000, stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 32 * 1024 * 1024,
    }).toString().trim();
  } catch (e: unknown) {
    const err = e as { stdout?: Buffer; stderr?: Buffer };
    throw new Error(`${cmd} failed:\n${err.stdout?.toString() ?? ''}${err.stderr?.toString() ?? ''}`);
  }
}

function javaJar(): string {
  const libs = join(REPO, 'compilers', 'java', 'build', 'libs');
  if (!existsSync(libs)) throw new Error('Java jar missing — run `./gradlew jar` in compilers/java');
  const jar = readdirSync(libs).find((f) => f.endsWith('.jar'));
  if (!jar) throw new Error('Java jar missing — run `./gradlew jar` in compilers/java');
  return join(libs, jar);
}

function requireBin(p: string, how: string): string {
  if (!existsSync(p)) throw new Error(`missing compiler binary ${p} — build it with: ${how}`);
  return p;
}

const FOLD_OFF = '--disable-constant-folding';

const TIERS: { name: string; hex: (src: string, file: string) => string }[] = [
  {
    name: 'ts',
    hex: (src, file) => {
      const r = compile(src, { fileName: file, disableConstantFolding: true });
      const errs = r.diagnostics.filter((d) => d.severity === 'error');
      expect(errs.map((d) => d.message).join(' | ')).toBe('');
      return (r.artifact as unknown as { script: string }).script;
    },
  },
  {
    name: 'go',
    hex: (src, file) => run(
      requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
      ['--source', write(`go-${file}`, src), '--hex', FOLD_OFF],
    ),
  },
  {
    name: 'rust',
    hex: (src, file) => run(
      requireBin(
        join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'),
        'cd compilers/rust && cargo build --release',
      ),
      ['--source', write(`rust-${file}`, src), '--hex', FOLD_OFF],
    ),
  },
  {
    name: 'python',
    hex: (src, file) => run('python3',
      ['-m', 'runar_compiler', '--source', write(`py-${file}`, src), '--hex', FOLD_OFF],
      join(REPO, 'compilers', 'python')),
  },
  {
    name: 'zig',
    hex: (src, file) => run(
      requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
      ['--source', write(`zig-${file}`, src), '--hex', FOLD_OFF],
    ),
  },
  {
    name: 'ruby',
    hex: (src, file) => run('ruby',
      ['-I', join(REPO, 'compilers', 'ruby', 'lib'),
        join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'),
        '--source', write(`rb-${file}`, src), '--hex', FOLD_OFF],
    ),
  },
  {
    name: 'java',
    hex: (src, file) => run('java',
      ['-jar', javaJar(), '--source', write(`java-${file}`, src), '--hex', FOLD_OFF]),
  },
];

/** Compile with all seven tiers; fail on any disagreement, return the hex. */
function compileEverywhere(src: string, file: string): string {
  const out = TIERS.map((t) => [t.name, t.hex(src, file)] as const);
  const first = out[0]![1];
  for (const [name, hex] of out) {
    expect(hex, `${name} diverges from ts:\n  ts   ${first}\n  ${name} ${hex}`).toBe(first);
  }
  return first;
}

// ---------------------------------------------------------------------------
// Opcode extraction
// ---------------------------------------------------------------------------

/**
 * Split a script into its OPCODE bytes, skipping push payloads.
 *
 * Substring-matching the hex would count a `9c` that happens to sit inside a
 * pushed constant, which is precisely the false signal a comparison-opcode
 * assertion must not have.
 */
function opcodes(hex: string): number[] {
  const b: number[] = [];
  for (let i = 0; i < hex.length; i += 2) b.push(parseInt(hex.slice(i, i + 2), 16));
  const ops: number[] = [];
  for (let i = 0; i < b.length;) {
    const op = b[i]!;
    ops.push(op);
    i += 1;
    if (op >= 0x01 && op <= 0x4b) i += op;
    else if (op === 0x4c) { i += 1 + (b[i] ?? 0); }
    else if (op === 0x4d) { i += 2 + ((b[i] ?? 0) | ((b[i + 1] ?? 0) << 8)); }
    else if (op === 0x4e) { i += 4 + ((b[i] ?? 0) | ((b[i + 1] ?? 0) << 8) | ((b[i + 2] ?? 0) << 16) | ((b[i + 3] ?? 0) << 24)); }
  }
  return ops;
}

const OP_CAT = 0x7e;
const OP_1ADD = 0x8b;
const OP_EQUAL = 0x87;
const OP_EQUALVERIFY = 0x88;
const OP_NUMEQUAL = 0x9c;
const OP_NUMEQUALVERIFY = 0x9d;

const count = (ops: number[], want: number[]): number => ops.filter((o) => want.includes(o)).length;

// ---------------------------------------------------------------------------
// Script-level primitives for the executed legs
// ---------------------------------------------------------------------------

function push(hex: string): string {
  const n = hex.length / 2;
  if (n <= 75) return n.toString(16).padStart(2, '0') + hex;
  if (n <= 255) return `4c${n.toString(16).padStart(2, '0')}${hex}`;
  return `4d${(n & 0xff).toString(16).padStart(2, '0')}${((n >> 8) & 0xff).toString(16).padStart(2, '0')}${hex}`;
}

/**
 * A BIP-143-shaped preimage. The extractors are pure OP_SPLIT / OP_SIZE
 * arithmetic, so only the field WIDTHS have to be right.
 */
function preimage(opts: { scriptCode: string; sequence: string }): string {
  return 'aa'.repeat(4)          // nVersion
    + 'bb'.repeat(32)            // hashPrevouts
    + 'cc'.repeat(32)            // hashSequence
    + 'dd'.repeat(36)            // outpoint
    + opts.scriptCode            // scriptCode (varint prefix folded in by the caller)
    + '1122334455667788'         // amount
    + opts.sequence              // nSequence
    + 'ee'.repeat(32)            // hashOutputs
    + '00000000'                 // nLocktime
    + '41000000';                // sighashType
}

const vm = new ScriptVM();

function exec(scriptHex: string): boolean {
  return vm.executeHex(scriptHex).success;
}

// ---------------------------------------------------------------------------

describe('N-054 preimage extractor result typing', () => {
  // -------------------------------------------------------------------------
  // The interpreter bracket. Every executed claim below is only worth what
  // these two lines are worth.
  // -------------------------------------------------------------------------
  it('ScriptVM sanity bracket', () => {
    expect(exec('51'), 'OP_1 must succeed').toBe(true);
    expect(exec('00'), 'OP_0 must fail').toBe(false);
  });

  // -------------------------------------------------------------------------
  // The two opcodes genuinely disagree — executed, not asserted from the spec.
  // -------------------------------------------------------------------------
  it('OP_EQUAL and OP_NUMEQUAL disagree on two encodings of the same number', () => {
    // `0400` is the number 4 pushed as two bytes. The PUSH is minimal (0x02
    // is the shortest opcode for a two-byte payload), so this is a witness a
    // node relays.
    expect(exec(`${push('0400')}54${'87'}`), '<0400> OP_4 OP_EQUAL').toBe(false);
    expect(exec(`${push('0400')}54${'9c'}`), '<0400> OP_4 OP_NUMEQUAL').toBe(true);

    // Negative zero — the same disagreement from the other side.
    expect(exec(`${push('80')}00${'87'}`), '<80> OP_0 OP_EQUAL').toBe(false);
    expect(exec(`${push('80')}00${'9c'}`), '<80> OP_0 OP_NUMEQUAL').toBe(true);

    // …and they agree once BOTH operands are minimal script numbers, which is
    // why a wrong opcode here survives every literal-vs-literal test.
    expect(exec(`${push('0400')}${'81'}54${'87'}`), 'BIN2NUM then OP_EQUAL').toBe(true);
    expect(exec(`${push('0400')}${'81'}54${'9c'}`), 'BIN2NUM then OP_NUMEQUAL').toBe(true);
  });

  it('OP_NUMEQUAL accepts operands wider than four bytes', () => {
    // extractAmount reads an eight-byte field, so its OP_BIN2NUM result can be
    // up to eight bytes wide. Pin that OP_NUMEQUAL handles that, so moving the
    // amount comparison onto it cannot break large-value contracts.
    const fiveByte = '00f2052a01'; // 5_000_000_000
    expect(exec(`${push(fiveByte)}${push(fiveByte)}9c`)).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Cross-tier parity + per-extractor correctness
  // -------------------------------------------------------------------------
  it('the six bigint extractors compare NUMERICALLY in all seven tiers', () => {
    const hex = compileEverywhere(NUMERIC_SRC, 'N054Numeric.runar.ts');
    const ops = opcodes(hex);
    expect(count(ops, [OP_NUMEQUAL, OP_NUMEQUALVERIFY]),
      `expected six numeric comparisons, got ${hex}`).toBe(6);
    expect(count(ops, [OP_EQUAL, OP_EQUALVERIFY]),
      `a bigint extractor is being compared BYTEWISE: ${hex}`).toBe(0);
    // Every one of the six ends in OP_BIN2NUM — the reason numeric is right.
    expect(ops.filter((o) => o === 0x81).length).toBe(6);
  });

  it('the seven byte extractors compare BYTEWISE in all seven tiers', () => {
    const hex = compileEverywhere(BYTES_SRC, 'N054Bytes.runar.ts');
    const ops = opcodes(hex);
    expect(count(ops, [OP_NUMEQUAL, OP_NUMEQUALVERIFY]),
      `a ByteString/Sha256 extractor is being compared NUMERICALLY: ${hex}`).toBe(0);
    // 7 comparisons + the OP_EQUALVERIFY inside extractPrevOutputScript's
    // own hash assertion.
    expect(count(ops, [OP_EQUAL, OP_EQUALVERIFY])).toBe(8);
    // No OP_BIN2NUM anywhere: none of these fields is a number.
    expect(ops.filter((o) => o === 0x81).length).toBe(0);
  });

  it('`+` on a bigint extractor is arithmetic, not concatenation', () => {
    const hex = compileEverywhere(PLUS_SRC, 'N054Plus.runar.ts');
    const ops = opcodes(hex);
    // Exactly ONE OP_CAT, and it is not the `+`: it is W1's zero-pad in
    // `extractLocktime` (`push [0x00] OP_CAT OP_BIN2NUM`, so the unsigned
    // 32-bit field is not read as a negative script number). `extractAmount`
    // is an 8-byte field and is not padded, so it contributes none. A `+`
    // that regressed to concatenation would make this 2 and drop OP_1ADD to
    // 0 — both halves still have to hold.
    expect(count(ops, [OP_CAT]),
      `a bigint extractor is being CONCATENATED instead of added: ${hex}`).toBe(1);
    expect(count(ops, [OP_1ADD])).toBe(2);
  });

  it('the OP_CAT lowering of `+` computed a different number', () => {
    // `assert(extractLocktime(p) + 1n === 65281n)` against nLocktime = 65280.
    const locktimeField = '00ff0000';   // 65280, 4-byte LE, as it sits in the preimage
    const expected = '01ff00';          // 65281, minimal script number

    const field = push(locktimeField);
    const rhs = push(expected);

    // What the fixed compiler emits: OP_BIN2NUM, OP_1ADD, OP_NUMEQUAL.
    expect(exec(`${field}818b${rhs}9c`),
      'the arithmetic lowering evaluates the source').toBe(true);

    // What six tiers emitted: the extractor was byte-typed, so `+` became
    // OP_1 OP_CAT and `===` became OP_EQUAL. 0x00ff00 concatenated with 0x01
    // is 0x00ff0001, not 65281 — the assert fails and the contract is
    // unspendable. No minimal-encoding policy rescues this one: both operands
    // are compiler-generated.
    expect(exec(`${field}81517e${rhs}87`),
      'the concatenation lowering rejects a spend the source accepts').toBe(false);
    // …and it is not merely a wrong OPCODE over a right value: read the
    // concatenation back as a number and it still is not 65281.
    expect(exec(`${field}81517e${rhs}9c`)).toBe(false);
  });

  // -------------------------------------------------------------------------
  // Executed semantics: the numeric side rejects valid spends
  // -------------------------------------------------------------------------
  it('a numeric extractor accepts a witness that encodes the right number differently', () => {
    const hex = compileEverywhere(SEQ_SRC, 'N054Seq.runar.ts');
    const p = preimage({ scriptCode: '19' + '76a914' + '99'.repeat(20) + '88ac', sequence: '04000000' });

    // A spender that pushes the number 4 as `0400` — legal, minimally pushed,
    // decoded as 4 by every script-number reader.
    const nonMinimal = `${push(p)}${push('0400')}${hex}`;
    // …and one that pushes it minimally.
    const minimal = `${push(p)}${push('04')}${hex}`;

    expect(exec(minimal), 'minimal witness must spend').toBe(true);
    expect(exec(nonMinimal),
      'a witness encoding the SAME number differently must still spend').toBe(true);

    // Control: the byte-comparison variant of the very same script rejects it.
    // This is what the five OP_EQUAL tiers shipped.
    const bytewise = `${hex.slice(0, -2)}87`;
    expect(exec(`${push(p)}${push('04')}${bytewise}`)).toBe(true);
    expect(exec(`${push(p)}${push('0400')}${bytewise}`),
      'the byte-comparison variant is the over-strict one').toBe(false);
  });

  // -------------------------------------------------------------------------
  // Executed semantics: the byte side accepts forgeries
  // -------------------------------------------------------------------------
  it('a byte extractor rejects a numerically-equal but byte-different scriptCode', () => {
    const hex = compileEverywhere(CODE_SRC, 'N054Code.runar.ts');
    // `extractScriptCode` returns preimage[104 .. len-52], i.e. the varint
    // length prefix AND the script — it is a pure OP_SPLIT, it never parses
    // the varint. So the two blobs differ only in a trailing byte.
    //
    // The final byte is 0x51, below 0x80, ON PURPOSE: a script number is
    // little-endian sign-magnitude, so appending 0x00 is a high-order zero
    // that preserves the value only when the previous top byte's sign bit is
    // clear. End the blob in 0xac instead and the padding flips the sign and
    // the two stop being numerically equal — which is how this control was
    // wrong the first time.
    const code = '76a914' + '99'.repeat(20) + '8851';
    const p = preimage({ scriptCode: '19' + code, sequence: '04000000' });
    // The same bytes with one trailing 0x00: the SAME script number, a
    // DIFFERENT script.
    const q = preimage({ scriptCode: '19' + code + '00', sequence: '04000000' });

    expect(exec(`${push(p)}${push(p)}${hex}`), 'identical scriptCodes must match').toBe(true);
    expect(exec(`${push(p)}${push(q)}${hex}`),
      'a zero-padded scriptCode must NOT match').toBe(false);

    // Control: the numeric variant of the same script — what Rust shipped for
    // every byte extractor, and TypeScript for extractScriptCode — accepts it.
    const numeric = `${hex.slice(0, -2)}9c`;
    expect(exec(`${push(p)}${push(q)}${numeric}`),
      'the numeric variant is the forgeable one').toBe(true);
  });
});
