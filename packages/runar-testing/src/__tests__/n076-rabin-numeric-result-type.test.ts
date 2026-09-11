/**
 * N-076 — `RabinSig` / `RabinPubKey` are BIGINT aliases, and six of seven ANF
 * lowerers classified them as BYTE strings.
 *
 * All seven `03-typecheck` tables already carry the authoritative answer, and
 * they do not disagree with each other by a single character:
 *
 *     BYTESTRING_SUBTYPES  ByteString PubKey Sig Sha256 Ripemd160 Addr
 *                          SigHashPreimage Point P256Point P384Point
 *     BIGINT_SUBTYPES      bigint RabinSig RabinPubKey
 *
 * (`typecheck.go:228/241`, `typecheck.rs:224/232`, `typecheck.py:229/242`,
 * `typecheck.zig:229/238`, `typecheck.rb:177/181`, `Typecheck.java:98/103`,
 * `03-typecheck.ts:242/250`.)
 *
 * The rest of the pipeline agrees. `emitVerifyRabinSig` consumes the modulus
 * with OP_MOD — a SCRIPT NUMBER opcode. `isVariableLengthStateType` excludes
 * the Rabin types on purpose, and `b7e91a19` made all seven tiers write a
 * mutable Rabin state field as a bare 8-byte OP_NUM2BIN word, byte-identical
 * to the `bigint` control it aliases.
 *
 * `04-anf-lower` then threw that away. It re-derives "is this expression
 * byte-typed?" from a SECOND, hand-maintained list (`BYTE_TYPES` /
 * `byteTypes` / `isByteType`), and six copies of that list carried
 * `RabinSig` and `RabinPubKey`. That annotation picks OP_EQUAL vs OP_NUMEQUAL
 * for `===`/`!==` and OP_CAT vs OP_ADD for `+`.
 *
 * MEASURED BEFORE THE FIX (`--source X --hex --disable-constant-folding`):
 *
 *   assert(s === t)              ts 9c            go,rust,py,zig,rb,java 87
 *   assert(s + t === sum)        ts 7b7b93 7c9c   rust 7b7b93 7c87
 *                                go,py,zig,rb,java 7b7b7e 7c87   <- OP_CAT
 *
 * The `+` row is the severe one and it is NOT the row the item was reported
 * as. `93` is OP_ADD; `7e` is OP_CAT. Five tiers compile the ADDITION of two
 * Rabin numbers into a CONCATENATION. Executed below: a contract whose source
 * says `1 + 2 === 3` evaluates FALSE in those five tiers and TRUE in
 * TypeScript. Both operands are witness data, both encodings are minimal,
 * nothing about node policy enters into it — the contract is simply
 * unspendable. That is a miscompile, not a parity question.
 *
 * The comparison row is the milder one: OP_EQUAL over a value the script
 * treats as a number is OVER-STRICT, so a witness that encodes the same
 * number with different bytes is rejected. Executed below. Honest bound, same
 * as N-054's: a node applying SCRIPT_VERIFY_MINIMALDATA would abort the
 * OP_NUMEQUAL over that same non-minimal operand rather than accept it, so on
 * a standard relay path both opcodes end in "spend fails" — the defect is
 * semantic and cross-tier rather than a live fund loss.
 *
 * TypeScript is the MINORITY and TypeScript is RIGHT. The fix moves six tiers,
 * not one, and the argument is the type system, not the headcount.
 *
 * ---------------------------------------------------------------------------
 * SECOND DEFECT, found by the ByteString control of this same sweep.
 *
 * `anf_lower.rs` never annotated `+` at all. Its dispatch handles `===`/`!==`
 * and `&`/`|`/`^` and drops straight to `None` for everything else, with a
 * doc comment three lines above claiming it covers `+`. So in Rust, `+` on
 * two `ByteString`s — the ordinary concatenation every other tier compiles to
 * OP_CAT — compiled to OP_ADD:
 *
 *   assert(s + t === sum)  ByteString   ts,go,py,zig,rb,java 7e   rust 93
 *
 * Executed below: `"aa" + "bb" === "aabb"` is TRUE in six tiers and FALSE in
 * Rust. Pre-existing, unrelated to the Rabin types, and the exact mirror of
 * the Rabin `+` bug in the other direction.
 *
 * ---------------------------------------------------------------------------
 * THE RULE this suite pins: the byte-ness annotation follows the type
 * checker's own type families, in every tier, byte for byte — and `+` is
 * annotated in every tier.
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
const TMP = mkdtempSync(join(tmpdir(), 'runar-n076-'));

// ---------------------------------------------------------------------------
// Contracts under test
// ---------------------------------------------------------------------------

/** `===` / `!==` on both Rabin types, as plain method parameters. */
const RABIN_CMP_SRC = `import { SmartContract, assert, RabinSig, RabinPubKey } from 'runar-lang';

export class N076RabinCmp extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public go(s: RabinSig, t: RabinSig, u: RabinPubKey, v: RabinPubKey) {
    assert(s === t);
    assert(u !== v);
  }
}
`;

/**
 * `+` on two Rabin values. OP_ADD for a number, OP_CAT for bytes — the same
 * annotation, and by far the worse consequence.
 */
const RABIN_PLUS_SRC = `import { SmartContract, assert, RabinSig } from 'runar-lang';

export class N076RabinPlus extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public go(s: RabinSig, t: RabinSig, sum: RabinSig) {
    assert(s + t === sum);
  }
}
`;

/**
 * `&`, `|`, `^`, `~` on Rabin values.
 *
 * The bitwise opcodes themselves do NOT depend on the annotation — OP_AND is
 * `84` for bytes and for numbers alike. What the annotation leaks into is the
 * comparison that consumes the result, which is why this probe asserts on the
 * whole script rather than on the bitwise byte.
 */
const RABIN_BITS_SRC = `import { SmartContract, assert, RabinSig } from 'runar-lang';

export class N076RabinBits extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public go(s: RabinSig, t: RabinSig) {
    assert((s & t) === t);
    assert((s | t) === t);
    assert((s ^ t) === t);
    assert((~s) === t);
  }
}
`;

/**
 * The shape the item was reported as: a Rabin PROPERTY compared against a
 * local aliasing a parameter. `isByteTypedExpr` reaches the same table by
 * three different routes (parameter type, property type, local byte-var set)
 * and all three have to agree.
 */
const RABIN_PROP_SRC = `import { SmartContract, assert, RabinSig } from 'runar-lang';

export class N076RabinProp extends SmartContract {
  readonly tag: RabinSig;
  constructor(tag: RabinSig) { super(tag); this.tag = tag; }
  public go(expected: RabinSig) {
    const v = expected;
    assert(this.tag === v);
  }
}
`;

/** `+` on two ByteStrings. OP_CAT everywhere — the Rust `+` defect. */
const BYTES_PLUS_SRC = `import { SmartContract, assert, ByteString } from 'runar-lang';

export class N076BytesPlus extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public go(s: ByteString, t: ByteString, sum: ByteString) {
    assert(s + t === sum);
  }
}
`;

/** Full operator battery over one type — used for the three controls. */
function batterySrc(cls: string, type: string, extraImport: string): string {
  return `import { SmartContract, assert${extraImport} } from 'runar-lang';

export class ${cls} extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public go(s: ${type}, t: ${type}, sum: ${type}) {
    assert(s === t);
    assert(s !== sum);
    assert(s + t === sum);
    assert((s & t) === t);
    assert((s | t) === t);
    assert((s ^ t) === t);
    assert((~s) === t);
  }
}
`;
}

const CTRL_BIGINT_SRC = batterySrc('N076CtrlBigint', 'bigint', '');
const CTRL_BYTES_SRC = batterySrc('N076CtrlBytes', 'ByteString', ', ByteString');
const CTRL_SIG_SRC = batterySrc('N076CtrlSig', 'Sig', ', Sig');

// ---------------------------------------------------------------------------
// Seven-tier compile harness
//
// A TypeScript-only structural test CANNOT carry this RED: TypeScript is the
// tier that is already correct. Every cross-tier assertion below drives the
// six native binaries.
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
//
// Substring-matching the hex would count a `93` or a `9c` that happens to sit
// inside a pushed constant, which is exactly the false signal an opcode
// assertion must not have.
// ---------------------------------------------------------------------------

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
const OP_ADD = 0x93;
const OP_EQUAL = 0x87;
const OP_EQUALVERIFY = 0x88;
const OP_NUMEQUAL = 0x9c;
const OP_NUMEQUALVERIFY = 0x9d;

const count = (ops: number[], want: number[]): number => ops.filter((o) => want.includes(o)).length;

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

const vm = new ScriptVM();

function exec(scriptHex: string): boolean {
  return vm.executeHex(scriptHex).success;
}

/** Minimal single-byte-length push of a hex payload. */
function push(hex: string): string {
  const n = hex.length / 2;
  if (n > 75) throw new Error('push helper is for small operands only');
  return n.toString(16).padStart(2, '0') + hex;
}

// ---------------------------------------------------------------------------

describe('N-076 Rabin types are numeric in the ANF byte-ness annotation', () => {
  // -------------------------------------------------------------------------
  // The interpreter bracket. Every executed claim below is only worth what
  // these two lines are worth.
  // -------------------------------------------------------------------------
  it('ScriptVM sanity bracket', () => {
    expect(exec('51'), 'OP_1 must succeed').toBe(true);
    expect(exec('00'), 'OP_0 must fail').toBe(false);
  });

  // -------------------------------------------------------------------------
  // The severe half: `+`.
  // -------------------------------------------------------------------------
  describe('`+` on Rabin values is ADDITION in all seven tiers', () => {
    it('compiles to OP_ADD and never OP_CAT, byte-identically', () => {
      const hex = compileEverywhere(RABIN_PLUS_SRC, 'N076RabinPlus.runar.ts');
      expect(hex).toBe('7b7b937c9c');
      const ops = opcodes(hex);
      expect(count(ops, [OP_ADD]), `expected OP_ADD in ${hex}`).toBe(1);
      expect(count(ops, [OP_CAT]), `OP_CAT must not appear in ${hex}`).toBe(0);
    });

    it('EXECUTED: a contract whose source says 1 + 2 === 3 must unlock', () => {
      // Argument order is s, t, sum pushed left to right.
      const witness = push('01') + push('02') + push('03');
      const correct = '7b7b937c9c';   // OP_ROT OP_ROT OP_ADD OP_SWAP OP_NUMEQUAL
      const catBug = '7b7b7e7c87';    // go/python/zig/ruby/java before the fix
      const eqBug = '7b7b937c87';     // rust before the fix

      expect(exec(witness + correct), '1 + 2 === 3 must be spendable').toBe(true);
      // The two pre-fix lowerings, pinned so the severity claim stays honest.
      expect(exec(witness + catBug), 'OP_CAT lowering: 0x01||0x02 != 0x03').toBe(false);
      expect(exec(witness + eqBug), 'OP_ADD + OP_EQUAL agrees when both sides are minimal').toBe(true);

      // …and disagrees the moment the witness is not minimally encoded.
      const nonMinimalSum = push('01') + push('02') + push('0300');
      expect(exec(nonMinimalSum + correct), 'OP_NUMEQUAL accepts 0x0300 as 3').toBe(true);
      expect(exec(nonMinimalSum + eqBug), 'OP_EQUAL rejects 0x0300 against 0x03').toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // The reported half: `===` / `!==`.
  // -------------------------------------------------------------------------
  describe('`===` / `!==` on Rabin values compare as NUMBERS in all seven tiers', () => {
    it('compiles to the OP_NUMEQUAL family, byte-identically', () => {
      const hex = compileEverywhere(RABIN_CMP_SRC, 'N076RabinCmp.runar.ts');
      expect(hex).toBe('537a537a9d9c91');
      const ops = opcodes(hex);
      expect(count(ops, [OP_NUMEQUAL, OP_NUMEQUALVERIFY]), `in ${hex}`).toBe(2);
      expect(count(ops, [OP_EQUAL, OP_EQUALVERIFY]), `OP_EQUAL must not appear in ${hex}`).toBe(0);
    });

    it('a Rabin PROPERTY compared against a local behaves the same', () => {
      const hex = compileEverywhere(RABIN_PROP_SRC, 'N076RabinProp.runar.ts');
      expect(hex).toBe('007c9c');
      const ops = opcodes(hex);
      expect(count(ops, [OP_NUMEQUAL, OP_NUMEQUALVERIFY]), `in ${hex}`).toBe(1);
      expect(count(ops, [OP_EQUAL, OP_EQUALVERIFY]), `in ${hex}`).toBe(0);
    });

    it('`&` `|` `^` `~` feed a NUMERIC comparison in all seven tiers', () => {
      const hex = compileEverywhere(RABIN_BITS_SRC, 'N076RabinBits.runar.ts');
      expect(hex).toBe('6e84789d6e85789d6e86789d7c837c9c');
      const ops = opcodes(hex);
      expect(count(ops, [OP_NUMEQUAL, OP_NUMEQUALVERIFY]), `in ${hex}`).toBe(4);
      expect(count(ops, [OP_EQUAL, OP_EQUALVERIFY]), `in ${hex}`).toBe(0);
    });

    it('EXECUTED: OP_EQUAL is over-strict on a non-minimally-encoded witness', () => {
      // `assert(s === t)` with s = 0x0100 (a non-minimal 1) and t = 0x01.
      const witness = push('0100') + push('01');
      expect(exec(witness + '9c'), 'OP_NUMEQUAL: both operands read as 1').toBe(true);
      expect(exec(witness + '87'), 'OP_EQUAL: 0x0100 != 0x01 byte-wise').toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // The second defect: Rust never annotated `+` at all.
  // -------------------------------------------------------------------------
  describe('`+` on ByteStrings is CONCATENATION in all seven tiers', () => {
    it('compiles to OP_CAT and never OP_ADD, byte-identically', () => {
      const hex = compileEverywhere(BYTES_PLUS_SRC, 'N076BytesPlus.runar.ts');
      expect(hex).toBe('7b7b7e7c87');
      const ops = opcodes(hex);
      expect(count(ops, [OP_CAT]), `expected OP_CAT in ${hex}`).toBe(1);
      expect(count(ops, [OP_ADD]), `OP_ADD must not appear in ${hex}`).toBe(0);
    });

    it('EXECUTED: a contract whose source says "aa" + "bb" === "aabb" must unlock', () => {
      const witness = push('aa') + push('bb') + push('aabb');
      expect(exec(witness + '7b7b7e7c87'), 'OP_CAT lowering').toBe(true);
      expect(exec(witness + '7b7b937c87'), 'rust OP_ADD lowering before the fix').toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Controls. These pin the bytes the fix must NOT move.
  //
  // `bigint` is the type the Rabin aliases resolve to, so it is the shape the
  // Rabin probes must converge ON; `ByteString` and `Sig` are the byte family
  // the six tiers wrongly filed them under, so they must stay put.
  //
  // The one deliberate exception is Rust's `+`, which was wrong in the
  // ByteString and Sig batteries too — see the block above.
  // -------------------------------------------------------------------------
  describe('controls', () => {
    it('bigint battery is unchanged in all seven tiers', () => {
      expect(compileEverywhere(CTRL_BIGINT_SRC, 'N076CtrlBigint.runar.ts')).toBe(
        '527952799d5279789c916952795279937c9d6e84789d6e85789d6e86789d7c837c9c',
      );
    });

    it('ByteString battery is unchanged in all seven tiers', () => {
      expect(compileEverywhere(CTRL_BYTES_SRC, 'N076CtrlBytes.runar.ts')).toBe(
        '5279527988527978879169527952797e7c886e8478886e8578886e8678887c837c87',
      );
    });

    it('Sig battery is unchanged in all seven tiers', () => {
      expect(compileEverywhere(CTRL_SIG_SRC, 'N076CtrlSig.runar.ts')).toBe(
        '5279527988527978879169527952797e7c886e8478886e8578886e8678887c837c87',
      );
    });

    it('the Rabin probes land exactly on their bigint equivalents', () => {
      // Same source, `RabinSig` swapped for `bigint`: identical bytes, which
      // is what "alias" has to mean.
      const rabin = compileEverywhere(RABIN_PLUS_SRC, 'N076RabinPlusAlias.runar.ts');
      const asBigint = compileEverywhere(
        RABIN_PLUS_SRC.replace(/RabinSig/g, 'bigint').replace(", bigint }", " }"),
        'N076BigintPlusAlias.runar.ts',
      );
      expect(rabin).toBe(asBigint);
    });
  });
});
