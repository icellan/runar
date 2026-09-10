/**
 * R-041 — a parser must never turn a syntax error into a wrong program.
 *
 * Two silent-mis-parse paths existed in the TypeScript tier's eight format
 * parsers:
 *
 *   1. All eight tokenizers silently dropped any character they did not
 *      recognise, so a stray character vanished instead of erroring.
 *   2. Five of the eight (`go`, `rust`, `sol`, `move`, `zig`) invented an
 *      `identifier` node named after whatever token they met at primary
 *      (expression) position, with no diagnostic. `python`, `ruby` and `java`
 *      already emitted "Unexpected token in expression".
 *
 * Both turn a syntax error into a silently different program. These tests
 * pin the diagnostic — including its line and column — for every one of the
 * eight TypeScript-tier format parsers.
 *
 * Scope: TypeScript tier only. The Go / Rust / Python / Zig / Ruby / Java
 * compiler tiers carry the same defect and are tracked separately.
 */

import { describe, it, expect } from 'vitest';
import { parseGoSource } from '../passes/01-parse-go.js';
import { parseRustSource } from '../passes/01-parse-rust.js';
import { parseSolSource } from '../passes/01-parse-sol.js';
import { parseMoveSource } from '../passes/01-parse-move.js';
import { parseZigSource } from '../passes/01-parse-zig.js';
import { parsePythonSource } from '../passes/01-parse-python.js';
import { parseRubySource } from '../passes/01-parse-ruby.js';
import { parseJavaSource } from '../passes/01-parse-java.js';
import type { ParseResult } from '../passes/01-parse.js';

// ---------------------------------------------------------------------------
// Minimal, known-good P2PKH in each of the eight non-TypeScript surfaces.
// ---------------------------------------------------------------------------

const GO = `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type P2PKH struct {
\trunar.SmartContract
\tPubKeyHash runar.Addr
}

func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
\trunar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
\trunar.Assert(runar.CheckSig(sig, pubKey))
}
`;

const RS = `use runar::prelude::*;

#[runar::contract]
pub struct P2PKH {
    #[readonly]
    pub pub_key_hash: Addr,
}

impl P2PKH {
    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}
`;

const SOL = `pragma runar ^0.1.0;

contract P2PKH is SmartContract {
    Addr immutable pubKeyHash;

    constructor(Addr _pubKeyHash) {
        pubKeyHash = _pubKeyHash;
    }

    function unlock(Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}
`;

const MOVE = `module P2PKH {
    use runar::types::{Addr, PubKey, Sig};
    use runar::crypto::{hash160, check_sig};

    struct P2PKH {
        pub_key_hash: Addr,
    }

    public fun unlock(contract: &P2PKH, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);
    }
}
`;

const ZIG = `const runar = @import("runar");

pub const P2PKH = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr,

    pub fn init(pubKeyHash: runar.Addr) P2PKH {
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
`;

const PY = `from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig

class P2PKH(SmartContract):
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
`;

const RB = `require 'runar'

class P2PKH < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end
`;

const JAVA = `package runar.examples.p2pkh;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;

class P2PKH extends SmartContract {

    @Readonly Addr pubKeyHash;

    P2PKH(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    void unlock(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
`;

// ---------------------------------------------------------------------------
// Per-format case table
// ---------------------------------------------------------------------------

type ParseFn = (source: string, fileName: string) => ParseResult;

interface FormatCase {
  /** Display name. */
  readonly name: string;
  readonly parse: ParseFn;
  readonly file: string;
  readonly source: string;
  /**
   * A character no token of this surface syntax can start.
   *
   * `@` is NOT universally safe: it is load-bearing in four of the eight
   * surfaces — Zig `@builtin`s, Python decorators (`@public`), Ruby instance
   * variables (`@pub_key_hash`) and Java annotations (`@Public`). Those four
   * get a character that really is unrecognised by their lexer instead.
   */
  readonly strayChar: string;
  /** Substring the stray character is inserted immediately before. */
  readonly strayAnchor: string;
  /**
   * A source in which a real, lexable token (`:`) appears where an expression
   * must start. `:` tokenizes in all eight lexers, so this exercises the
   * parser's primary-position fallback rather than the tokenizer's.
   */
  readonly badPrimarySource: string;
}

const CASES: readonly FormatCase[] = [
  {
    name: 'go',
    parse: parseGoSource,
    file: 'P2PKH.runar.go',
    source: GO,
    strayChar: '@',
    strayAnchor: 'runar.CheckSig(sig, pubKey)',
    badPrimarySource: GO.replace('runar.CheckSig(sig, pubKey)', ':'),
  },
  {
    name: 'rust',
    parse: parseRustSource,
    file: 'P2PKH.runar.rs',
    source: RS,
    strayChar: '@',
    strayAnchor: 'check_sig(sig, pub_key)',
    badPrimarySource: RS.replace('check_sig(sig, pub_key)', ':'),
  },
  {
    name: 'sol',
    parse: parseSolSource,
    file: 'P2PKH.runar.sol',
    source: SOL,
    strayChar: '@',
    strayAnchor: 'checkSig(sig, pubKey)',
    badPrimarySource: SOL.replace('checkSig(sig, pubKey)', ':'),
  },
  {
    name: 'move',
    parse: parseMoveSource,
    file: 'P2PKH.runar.move',
    source: MOVE,
    strayChar: '@',
    strayAnchor: 'check_sig(sig, pub_key)',
    badPrimarySource: MOVE.replace('check_sig(sig, pub_key)', ':'),
  },
  {
    name: 'zig',
    parse: parseZigSource,
    file: 'P2PKH.runar.zig',
    source: ZIG,
    // `@` starts every Zig builtin (`@import`, `@divTrunc`) — not a stray char.
    strayChar: '$',
    strayAnchor: 'runar.checkSig(sig, pubKey)',
    badPrimarySource: ZIG.replace('runar.checkSig(sig, pubKey)', ':'),
  },
  {
    name: 'python',
    parse: parsePythonSource,
    file: 'P2PKH.runar.py',
    source: PY,
    // `@` is the decorator sigil (`@public`) — not a stray char.
    strayChar: '$',
    strayAnchor: 'check_sig(sig, pub_key)',
    badPrimarySource: PY.replace('check_sig(sig, pub_key)', ':'),
  },
  {
    name: 'ruby',
    parse: parseRubySource,
    file: 'P2PKH.runar.rb',
    source: RB,
    // `@` is the instance-variable sigil (`@pub_key_hash`) — not a stray char.
    strayChar: '$',
    strayAnchor: 'check_sig(sig, pub_key)',
    badPrimarySource: RB.replace('check_sig(sig, pub_key)', ':'),
  },
  {
    name: 'java',
    parse: parseJavaSource,
    file: 'P2PKH.runar.java',
    source: JAVA,
    // `@` is the annotation sigil (`@Public`); `$` is a legal Java identifier
    // character. `#` is neither.
    strayChar: '#',
    strayAnchor: 'checkSig(sig, pubKey)',
    badPrimarySource: JAVA.replace('checkSig(sig, pubKey)', ':'),
  },
];

/** 1-based line/column of a character offset within `source`. */
function lineColumnOf(source: string, offset: number): { line: number; column: number } {
  const before = source.slice(0, offset);
  const lines = before.split('\n');
  const lastLine = lines[lines.length - 1] ?? '';
  return { line: lines.length, column: lastLine.length + 1 };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('R-041: TS-tier format parsers reject unrecognized input', () => {
  describe.each(CASES.map(c => [c.name, c] as const))('%s', (_name, c) => {
    it('parses the known-good contract with no diagnostics (control)', () => {
      const result = c.parse(c.source, c.file);
      expect(result.errors).toEqual([]);
      expect(result.contract).not.toBeNull();
    });

    it('rejects a stray character with a diagnostic carrying line and column', () => {
      const offset = c.source.indexOf(c.strayAnchor);
      expect(offset).toBeGreaterThan(-1);
      const mutated = c.source.slice(0, offset) + c.strayChar + c.source.slice(offset);
      const expectedPos = lineColumnOf(mutated, offset);

      const result = c.parse(mutated, c.file);

      expect(result.errors.length).toBeGreaterThan(0);
      const positioned = result.errors.filter(
        e => e.severity === 'error' && e.loc !== undefined,
      );
      expect(positioned.length).toBeGreaterThan(0);

      // At least one diagnostic must point exactly at the stray character.
      const atStray = positioned.filter(
        e => e.loc?.line === expectedPos.line && e.loc?.column === expectedPos.column,
      );
      expect(
        atStray.length,
        `expected a diagnostic at ${c.file}:${expectedPos.line}:${expectedPos.column} for stray '${c.strayChar}', got ${JSON.stringify(result.errors)}`,
      ).toBeGreaterThan(0);
      expect(atStray[0]?.loc?.file).toBe(c.file);
      expect(atStray[0]?.message).toContain(c.strayChar);
    });

    it('rejects an unrecognized token at expression position instead of fabricating an identifier', () => {
      const result = c.parse(c.badPrimarySource, c.file);

      expect(
        result.errors.length,
        `expected a diagnostic for ':' at expression position, got none`,
      ).toBeGreaterThan(0);

      const positioned = result.errors.filter(
        e => e.severity === 'error' && typeof e.loc?.line === 'number' && typeof e.loc?.column === 'number',
      );
      expect(positioned.length).toBeGreaterThan(0);
      expect(positioned[0]?.loc?.file).toBe(c.file);
      expect(positioned[0]?.loc?.line).toBeGreaterThan(0);
      expect(positioned[0]?.loc?.column).toBeGreaterThan(0);
    });
  });
});
