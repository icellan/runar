import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile } from '../index.js';
import { parse } from '../passes/01-parse.js';
import { UNTERMINATED_STRING_LITERAL } from '../errors.js';

/**
 * F-011 (CL-BUG-196) — an unterminated string or byte-string literal is
 * refused, never scanned onward into the lines that follow it.
 *
 * Several tokenizers scanned a quoted literal up to the next matching quote,
 * wherever that was. `tag: ByteString = b"cafe` with no closing quote therefore
 * swallowed the guard `assert_(y < 5)` on the next line as literal DATA and
 * closed on a quote in a later comment. b-strings hex-encode arbitrary bytes,
 * so no hex validator fired, and the Go / Python / Zig / Java tiers emitted a
 * script WITHOUT the guard (@bsv/sdk Spend.validate accepted y = 100). Other
 * tokenizers ended the literal at the line break silently, and the reference
 * tier's Python tokenizer skipped every line after an unclosed docstring,
 * dropping a guard the same way.
 *
 * The rule (user decision R10), defined here and ported verbatim to all seven
 * tiers:
 *   - a quoted literal that reaches a line break or end of file before its
 *     closing quote is refused with exactly `unterminated string literal`,
 *     located at its opening quote. That covers .runar.py '..' ".." b'..' b"..",
 *     .runar.sol, .runar.move, .runar.zig, .runar.java, .runar.rb, .runar.go
 *     and .runar.ts (whose host languages do not allow a raw line break in
 *     those literals);
 *   - on .runar.rs (Rust strings may span lines), for Python triple-quoted
 *     strings and for .runar.go backtick raw strings only end of file makes a
 *     literal unterminated;
 *   - a Java char literal is refused with
 *     `char literals are unsupported in Rúnar Java contracts`.
 *
 * What this proves: the reference tier refuses every negative fixture
 * N52-N64 with the shared diagnostic at the opening quote's line; it refuses
 * each literal shape on each surface both at a line break and at end of file;
 * and it still accepts the same programs with the literal closed, plus the
 * legitimate multi-line forms (Python triple-quoted docstrings, a Rust string
 * that spans lines) and escaped quotes.
 * What it does NOT prove: anything about the other six tiers (their own suites
 * and conformance/negatives/rejection-parity.test.ts cover that), and nothing
 * about literal forms the reference tokenizers do not scan at all (Rust raw
 * strings, Ruby heredocs / %-literals, Zig `\\` lines, Java text blocks are
 * refused or mis-tokenized as they were before).
 */

const NEGATIVES = resolve(__dirname, '../../../../conformance/negatives');
const CHAR_MSG = 'char literals are unsupported in Rúnar Java contracts';

function errorsWithLoc(source: string, fileName: string): Array<{ message: string; line?: number }> {
  return parse(source, fileName).errors.map((e) => ({ message: e.message, line: e.loc?.line }));
}

function expectUnterminated(source: string, fileName: string, line: number): void {
  const errs = errorsWithLoc(source, fileName);
  expect(errs.map((e) => e.message), `${fileName}: ${JSON.stringify(errs)}`).toContain(UNTERMINATED_STRING_LITERAL);
  expect(errs.find((e) => e.message === UNTERMINATED_STRING_LITERAL)!.line).toBe(line);
  expect(compile(source, { fileName }).success).toBe(false);
}

function expectNoUnterminated(source: string, fileName: string): string[] {
  const msgs = errorsWithLoc(source, fileName).map((e) => e.message);
  expect(msgs).not.toContain(UNTERMINATED_STRING_LITERAL);
  return msgs;
}

function expectCompiles(source: string, fileName: string): void {
  const r = compile(source, { fileName });
  const errs = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
  expect(errs, fileName).toEqual([]);
  expect(r.success).toBe(true);
}

describe('F-011 the shared diagnostic', () => {
  it('has one fixed text', () => {
    expect(UNTERMINATED_STRING_LITERAL).toBe('unterminated string literal');
  });
});

// ---------------------------------------------------------------------------
// The conformance negatives: refused here, with the closed-literal control
// still compiling (or, on .sol/.move, still refused for its own reason, since
// the reference tier accepts no quoted literal on those two surfaces).
// ---------------------------------------------------------------------------

interface Fixture {
  file: string;
  line: number; // line of the opening quote
  open: string; // the unterminated text on that line
  closed: string; // the same text with the literal closed
  controlCompiles: boolean;
}

const FIXTURES: Fixture[] = [
  { file: 'N52-py-bytes-unterminated-swallow.runar.py', line: 22, open: 'b"cafe\n', closed: 'b"cafe"\n', controlCompiles: true },
  { file: 'N53-py-string-unterminated.runar.py', line: 13, open: "'cafe\n", closed: "'cafe'\n", controlCompiles: true },
  { file: 'N54-py-docstring-unterminated.runar.py', line: 19, open: 'follows.\n', closed: 'follows."""\n', controlCompiles: true },
  { file: 'N55-sol-string-unterminated.runar.sol', line: 13, open: '"cafe\n', closed: '"cafe";\n', controlCompiles: false },
  { file: 'N56-move-string-unterminated.runar.move', line: 12, open: '"cafe\n', closed: '"cafe";\n', controlCompiles: false },
  { file: 'N57-zig-string-unterminated.runar.zig', line: 12, open: '"cafe\n', closed: 'runar.hexToBytes("cafe");\n', controlCompiles: true }, // N-448: a bare "cafe" is refused
  { file: 'N58-rs-string-unterminated.runar.rs', line: 13, open: '"cafe;\n', closed: '"cafe";\n', controlCompiles: true },
  { file: 'N59-java-string-unterminated.runar.java', line: 22, open: '"cafe\n', closed: '"cafe");\n', controlCompiles: true },
  { file: 'N61-rb-single-quote-unterminated.runar.rb', line: 10, open: "'cafe\n", closed: "'cafe'\n", controlCompiles: true },
  { file: 'N62-rb-double-quote-unterminated.runar.rb', line: 9, open: '"cafe\n', closed: '"cafe"\n', controlCompiles: true },
  { file: 'N63-go-string-unterminated.runar.go', line: 18, open: '"cafe\n', closed: 'runar.HexToBytes("cafe")\n', controlCompiles: true }, // N-448: a bare "cafe" is refused
  { file: 'N64-ts-string-unterminated.runar.ts', line: 14, open: '"cafe;\n', closed: '"cafe";\n', controlCompiles: true },
];

describe('F-011 conformance negatives (reference tier)', () => {
  for (const f of FIXTURES) {
    const src = readFileSync(resolve(NEGATIVES, f.file), 'utf8');

    it(`${f.file}: refused with the shared diagnostic at line ${f.line}`, () => {
      expect(src.split('\n')[f.line - 1]! + '\n').toContain(f.open);
      expectUnterminated(src, f.file, f.line);
    });

    it(`${f.file}: the closed-literal control is not refused for it`, () => {
      // Close the literal and neutralise the later comment quote that the
      // swallow shape relied on (it is inside a comment either way).
      const control = src.replace(f.open, f.closed);
      expect(control).not.toBe(src);
      expectNoUnterminated(control, f.file);
      if (f.controlCompiles) expectCompiles(control, f.file);
    });
  }

  it('N60-java-char-literal.runar.java: refused as a char literal', () => {
    const file = 'N60-java-char-literal.runar.java';
    const errs = errorsWithLoc(readFileSync(resolve(NEGATIVES, file), 'utf8'), file);
    expect(errs.map((e) => e.message)).toContain(CHAR_MSG);
    expect(errs.find((e) => e.message === CHAR_MSG)!.line).toBe(21);
  });
});

// ---------------------------------------------------------------------------
// Every literal shape, at a line break and at end of file.
// ---------------------------------------------------------------------------

const PY = (body: string) => `from runar import SmartContract, Bigint, ByteString, public, assert_


class G(SmartContract):
    def __init__(self):
        super().__init__()

    @public
    def unlock(self, y: Bigint):
${body}`;

describe('F-011 .runar.py shapes', () => {
  const F = 'G.runar.py';
  for (const lit of [`b"ca`, `b'ca`, `"ca`, `'ca`]) {
    it(`${lit} reaching a line break is refused`, () => {
      expectUnterminated(PY(`        t: ByteString = ${lit}\n        assert_(y < 5)\n`), F, 10);
    });
    it(`${lit} reaching end of file is refused`, () => {
      expectUnterminated(PY(`        assert_(y < 5)\n        t: ByteString = ${lit}`), F, 11);
    });
  }
  it('a backslash before the line break does not continue the literal', () => {
    expectUnterminated(PY(`        t: ByteString = b"ca\\\n        assert_(y < 5)\n`), F, 10);
  });
  it('an unclosed triple-quoted string at end of file is refused', () => {
    expectUnterminated(PY(`        assert_(y < 5)\n        '''note\n        more\n`), F, 11);
    expectUnterminated(PY(`        assert_(y < 5)\n        x = """note\n`), F, 11);
  });
  it('still accepts multi-line and one-line docstrings, and escaped quotes', () => {
    const doc = `from runar import SmartContract, Bigint, ByteString, public, assert_


class G(SmartContract):
    """A contract.

    Spanning lines, with a 'quote' and a "quote".
    """

    def __init__(self):
        super().__init__()

    @public
    def unlock(self, y: Bigint):
        '''Method docstring
        on two lines.'''
        """one line"""
        t: ByteString = b'\\x0a'
        assert_(y < 5)
`;
    expectCompiles(doc, F);
  });
});

describe('F-011 C-like surfaces: a line break ends the literal', () => {
  const SOL = (decl: string) => `pragma runar ^0.1.0;

contract G is SmartContract {
    function unlock(bigint y) public {
${decl}
        require(y < 5);
    }
}
`;
  it('.runar.sol: both quote characters', () => {
    expectUnterminated(SOL(`        ByteString t = "ca`), 'G.runar.sol', 5);
    expectUnterminated(SOL(`        ByteString t = 'ca`), 'G.runar.sol', 5);
    expectUnterminated(`pragma runar ^0.1.0;\ncontract G is SmartContract {\n  function f() public { "ca`, 'G.runar.sol', 3);
  });

  const MOVE = (decl: string) => `module G {
    struct G {
    }
    public fun unlock(contract: &G, y: Int) {
${decl}
        assert!(y < 5, 0);
    }
}
`;
  it('.runar.move: both quote characters', () => {
    expectUnterminated(MOVE(`        let t: ByteString = "ca`), 'G.runar.move', 5);
    expectUnterminated(MOVE(`        let t: ByteString = b'ca`), 'G.runar.move', 5);
  });

  const ZIG = (decl: string) => `const runar = @import("runar");

pub const G = struct {
    pub const Contract = runar.SmartContract;

    pub fn unlock(self: *const G, y: runar.Bigint) void {
        _ = self;
${decl}
        runar.assert(y < 5);
    }
};
`;
  it('.runar.zig', () => {
    expectUnterminated(ZIG(`        const t: runar.ByteString = "ca`), 'G.runar.zig', 8);
    expectUnterminated(ZIG(`        const t: runar.ByteString = "ca\\`), 'G.runar.zig', 8);
    expectUnterminated(`const runar = @import("runar`, 'G.runar.zig', 1);
  });

  const JAVA = (decl: string) => `package g;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;

class G extends SmartContract {
    G() {
        super();
    }

    @Public
    void unlock(Bigint y) {
${decl}
        assertThat(y.lt(Bigint.of(5)));
    }
}
`;
  it('.runar.java', () => {
    expectUnterminated(JAVA(`        ByteString t = ByteString.fromHex("ca`), 'G.runar.java', 17);
    expectUnterminated(JAVA(`        ByteString t = ByteString.fromHex("ca\\"`), 'G.runar.java', 17);
  });
  it('.runar.java: escaped quotes stay inside a terminated literal', () => {
    expectNoUnterminated(JAVA(`        ByteString t = ByteString.fromHex("ca\\"fe");`), 'G.runar.java');
  });
  it('.runar.java: a char literal is always refused, terminated or not', () => {
    for (const lit of [`'c';`, `'c`, `'\\''`]) {
      const msgs = errorsWithLoc(JAVA(`        Bigint z = y; ${lit}`), 'G.runar.java').map((e) => e.message);
      expect(msgs, lit).toContain(CHAR_MSG);
    }
  });

  const GO = (decl: string) => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type G struct {
\trunar.SmartContract
}

func (c *G) Unlock(y runar.Bigint) {
${decl}
\trunar.Assert(y < 5)
}
`;
  it('.runar.go', () => {
    expectUnterminated(GO(`\tvar t runar.ByteString = "ca`), 'G.runar.go', 10);
    expectUnterminated(GO(`\tvar t runar.ByteString = "ca\\`), 'G.runar.go', 10);
    expectNoUnterminated(GO(`\tvar t runar.ByteString = "ca\\"fe"`), 'G.runar.go');
  });
  it('.runar.go: a backtick raw string may span lines; only end of file is unterminated', () => {
    const tagged = (tag: string) => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type G struct {
\trunar.SmartContract
\tK runar.Bigint ${tag}
}

func (c *G) Unlock(y runar.Bigint) {
\trunar.Assert(y < c.K)
}
`;
    expectCompiles(tagged('`runar:"readonly"`'), 'G.runar.go');
    expectNoUnterminated(tagged('`runar:\n"readonly"`'), 'G.runar.go');
    expectUnterminated(tagged('`runar:"readonly"'), 'G.runar.go', 7);
  });

  const TS = (decl: string) => `import { SmartContract, ByteString, assert } from 'runar-lang';

export class G extends SmartContract {
  constructor() {
    super();
  }

  public unlock(y: bigint): void {
${decl}
    assert(y < 5n);
  }
}
`;
  it('.runar.ts (ts-morph path)', () => {
    expectUnterminated(TS(`    const t: ByteString = "ca`), 'G.runar.ts', 9);
    expectUnterminated(TS(`    const t: ByteString = 'ca`), 'G.runar.ts', 9);
    expectUnterminated(`import { SmartContract } from 'runar-lang`, 'G.runar.ts', 1);
  });
  it('.runar.ts: a backslash before the line break continues the literal (as in TS)', () => {
    expectNoUnterminated(TS(`    const t: ByteString = "ca\\\nfe";`), 'G.runar.ts');
  });
});

describe('F-011 .runar.rb: line-based, both quote characters', () => {
  const RB = (decl: string) => `require 'runar'

class G < Runar::SmartContract
  runar_public y: Bigint
  def unlock(y)
${decl}
    assert y < 5
  end
end
`;
  it('refuses at the line break', () => {
    expectUnterminated(RB(`    t = 'ca`), 'G.runar.rb', 6);
    expectUnterminated(RB(`    t = "ca`), 'G.runar.rb', 6);
    expectUnterminated(RB(`    t = "ca\\`), 'G.runar.rb', 6);
  });
  it('accepts escaped quotes inside a terminated literal', () => {
    expectNoUnterminated(RB(`    t = "ca\\"fe"`), 'G.runar.rb');
  });
});

describe('F-011 .runar.rs: Rust strings may span lines, so only end of file is unterminated', () => {
  const RS = (decl: string) => `use runar::prelude::*;

#[runar::contract]
pub struct G {
}

impl G {
    pub fn unlock(&self, y: Bigint) {
${decl}
        assert!(y < 5);
    }
}
`;
  it('refuses a literal that reaches end of file', () => {
    expectUnterminated(RS(`        let t: ByteString = "ca;`), 'G.runar.rs', 9);
    expectUnterminated(RS(`        let t: ByteString = "ca\\"`), 'G.runar.rs', 9);
  });
  it('does not call a literal that spans lines unterminated', () => {
    expectNoUnterminated(RS(`        let t: ByteString = "ca\nfe";`), 'G.runar.rs');
  });
});
