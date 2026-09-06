/**
 * Rust parser: verify all example contracts and conformance tests parse correctly.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { validate } from '../passes/02-validate.js';
import { typecheck } from '../passes/03-typecheck.js';
import { parseRustSource } from '../passes/01-parse-rust.js';
import { readFileSync, existsSync, readdirSync } from 'fs';
import { basename, join, resolve } from 'path';

// ---------------------------------------------------------------------------
// Vacuity guard
// ---------------------------------------------------------------------------

// Every test in this file must assert. The two conformance suites below used
// to `return` early when a fixture path was missing, so all 18 of their cases
// reported PASSED while executing zero `expect()` calls — an early `return` is
// invisible to `scripts/lint-no-silent-skips.sh` because it is not a skip.
// `expect.hasAssertions()` makes a re-introduction of that pattern fail loudly.
beforeEach(() => {
  expect.hasAssertions();
});

// ---------------------------------------------------------------------------
// Conformance tests
// ---------------------------------------------------------------------------

const CONFORMANCE_DIR = join(__dirname, '..', '..', '..', '..', 'conformance', 'tests');

interface SourceConfig {
  sources?: Record<string, string>;
}

/**
 * Resolve a conformance fixture's source for `ext` through its `source.json`,
 * the same indirection `conformance/runner/` and `multi-format.test.ts` use.
 * Contract sources live under `examples/<lang>/<dir>/<Contract>.runar.<ext>`;
 * only the fixture metadata lives in `conformance/tests/<dir>/`.
 *
 * Throws on a missing `source.json`, an undeclared extension, or a declared
 * path that is absent on disk. None of those are legitimate skips — they mean
 * the fixture wiring is broken and the test must not silently pass.
 */
function readFixtureSource(testName: string, ext: string): { content: string; fileName: string } {
  const configFile = join(CONFORMANCE_DIR, testName, 'source.json');
  if (!existsSync(configFile)) {
    throw new Error(`source.json not found for conformance fixture '${testName}': ${configFile}`);
  }
  const config = JSON.parse(readFileSync(configFile, 'utf-8')) as SourceConfig;
  const rel = config.sources?.[ext];
  if (rel === undefined) {
    throw new Error(`source.json for '${testName}' does not declare a ${ext} source`);
  }
  const absPath = resolve(CONFORMANCE_DIR, testName, rel);
  if (!existsSync(absPath)) {
    throw new Error(
      `source.json for '${testName}' declares ${ext} -> ${rel}, but resolved path does not exist: ${absPath}`,
    );
  }
  return { content: readFileSync(absPath, 'utf-8'), fileName: basename(absPath) };
}

/** Format a parse result's errors for an assertion message. */
function errorText(errors: { message: string; loc?: { line: number } }[]): string {
  return errors.map(e => `  line ${e.loc?.line ?? '?'}: ${e.message}`).join('\n');
}

const CONFORMANCE_TESTS = [
  { dir: 'arithmetic', contract: 'Arithmetic', parent: 'SmartContract' },
  { dir: 'basic-p2pkh', contract: 'P2PKH', parent: 'SmartContract' },
  { dir: 'boolean-logic', contract: 'BooleanLogic', parent: 'SmartContract' },
  { dir: 'bounded-loop', contract: 'BoundedLoop', parent: 'SmartContract' },
  { dir: 'if-else', contract: 'IfElse', parent: 'SmartContract' },
  { dir: 'if-without-else', contract: 'IfWithoutElse', parent: 'SmartContract' },
  { dir: 'multi-method', contract: 'MultiMethod', parent: 'SmartContract' },
  { dir: 'property-initializers', contract: 'PropertyInitializers', parent: 'StatefulSmartContract' },
  { dir: 'stateful', contract: 'Stateful', parent: 'StatefulSmartContract' },
];

describe('Rust parser: conformance test parsing', () => {
  for (const { dir, contract: contractName, parent } of CONFORMANCE_TESTS) {
    it(`parses the ${dir} .runar.rs conformance source`, () => {
      const { content, fileName } = readFixtureSource(dir, '.runar.rs');
      const result = parse(content, fileName);
      const errors = result.errors.filter(e => e.severity === 'error');
      expect(errors, `parse errors in ${fileName}:\n${errorText(errors)}`).toEqual([]);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.name).toBe(contractName);
      expect(result.contract!.parentClass).toBe(parent);
      expect(result.contract!.properties.length).toBeGreaterThan(0);
      expect(result.contract!.methods.length).toBeGreaterThan(0);
    });
  }
});

// ---------------------------------------------------------------------------
// Cross-format structural consistency (Rust vs TS)
// ---------------------------------------------------------------------------

describe('Rust parser: cross-format structural consistency', () => {
  for (const { dir } of CONFORMANCE_TESTS) {
    it(`${dir}: Rust and TS formats produce matching contract structure`, () => {
      const rs = readFixtureSource(dir, '.runar.rs');
      const ts = readFixtureSource(dir, '.runar.ts');

      const rsResult = parse(rs.content, rs.fileName);
      const tsResult = parse(ts.content, ts.fileName);

      // A parse failure on either side is a real defect, not a reason to skip
      // the comparison: returning early here would make the whole suite green
      // the moment one parser regressed.
      const rsErrors = rsResult.errors.filter(e => e.severity === 'error');
      const tsErrors = tsResult.errors.filter(e => e.severity === 'error');
      expect(rsErrors, `parse errors in ${rs.fileName}:\n${errorText(rsErrors)}`).toEqual([]);
      expect(tsErrors, `parse errors in ${ts.fileName}:\n${errorText(tsErrors)}`).toEqual([]);
      expect(rsResult.contract).not.toBeNull();
      expect(tsResult.contract).not.toBeNull();
      const rsContract = rsResult.contract!;
      const tsContract = tsResult.contract!;

      // Contract name
      expect(rsContract.name).toBe(tsContract.name);

      // Same base class
      expect(rsContract.parentClass).toBe(tsContract.parentClass);

      // Same number of properties
      expect(rsContract.properties.length).toBe(tsContract.properties.length);

      // Property names and readonly flags
      for (let j = 0; j < tsContract.properties.length; j++) {
        expect(rsContract.properties[j]!.name).toBe(tsContract.properties[j]!.name);
        expect(rsContract.properties[j]!.readonly).toBe(tsContract.properties[j]!.readonly);
      }

      // Same number of methods
      expect(rsContract.methods.length).toBe(tsContract.methods.length);

      // Method names, visibility, and param counts
      for (let j = 0; j < tsContract.methods.length; j++) {
        expect(rsContract.methods[j]!.name).toBe(tsContract.methods[j]!.name);
        expect(rsContract.methods[j]!.visibility).toBe(tsContract.methods[j]!.visibility);
        expect(rsContract.methods[j]!.params.length).toBe(tsContract.methods[j]!.params.length);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Example contracts (examples/rust/)
// ---------------------------------------------------------------------------

const EXAMPLES_DIR = join(__dirname, '..', '..', '..', '..', 'examples', 'rust');

function findRustExamples(): { name: string; path: string }[] {
  if (!existsSync(EXAMPLES_DIR)) return [];
  const examples: { name: string; path: string }[] = [];
  for (const subdir of readdirSync(EXAMPLES_DIR)) {
    const subdirPath = join(EXAMPLES_DIR, subdir);
    try {
      const files = readdirSync(subdirPath);
      for (const f of files) {
        if (f.endsWith('.runar.rs')) {
          examples.push({ name: f, path: join(subdirPath, f) });
        }
      }
    } catch {
      // skip non-directories
    }
  }
  return examples;
}

const RUST_EXAMPLES = findRustExamples();

describe('Rust parser: example contracts', () => {
  // Non-vacuity sentinel: an empty discovery would generate zero `it()` cases
  // and the describe would still report green. Assert the corpus is non-empty
  // so a broken EXAMPLES_DIR fails instead of silently covering nothing.
  it('discovers the examples/rust corpus', () => {
    expect(existsSync(EXAMPLES_DIR), `examples dir missing: ${EXAMPLES_DIR}`).toBe(true);
    expect(RUST_EXAMPLES.length).toBeGreaterThan(0);
  });

  for (const { name, path } of RUST_EXAMPLES) {
    it(`parses ${name} without errors`, () => {
      const source = readFileSync(path, 'utf-8');
      const result = parseRustSource(source, name);
      const errors = result.errors.filter(e => e.severity === 'error');
      if (errors.length > 0) {
        console.error(`Parse errors in ${name}:`);
        for (const e of errors) {
          console.error(`  Line ${e.loc?.line ?? '?'}: ${e.message}`);
        }
      }
      expect(errors).toEqual([]);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.properties.length).toBeGreaterThanOrEqual(0);
      expect(result.contract!.methods.length).toBeGreaterThanOrEqual(1);
    });
  }
});

// ---------------------------------------------------------------------------
// Specific feature tests
// ---------------------------------------------------------------------------

describe('Rust parser: specific features', () => {
  it('converts snake_case identifiers to camelCase', () => {
    const source = `
use runar::prelude::*;

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
    const result = parseRustSource(source, 'P2PKH.runar.rs');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.properties[0]!.name).toBe('pubKeyHash');
    expect(result.contract!.methods[0]!.name).toBe('unlock');
    expect(result.contract!.methods[0]!.params[0]!.name).toBe('sig');
    expect(result.contract!.methods[0]!.params[1]!.name).toBe('pubKey');
  });

  it('strips .clone() calls', () => {
    const source = `
use runar::prelude::*;

#[runar::contract]
pub struct Test {
    pub owner: PubKey,
}

impl Test {
    pub fn do_it(&mut self, player: PubKey) {
        self.owner = player.clone();
    }
}
`;
    const result = parseRustSource(source, 'Test.runar.rs');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    // The assignment value should be an identifier, not a call_expr
    const method = result.contract!.methods[0]!;
    const assign = method.body[0]!;
    expect(assign.kind).toBe('assignment');
    if (assign.kind === 'assignment') {
      expect(assign.value.kind).toBe('identifier');
    }
  });

  it('strips & reference operators from arguments', () => {
    const source = `
use runar::prelude::*;

#[runar::contract]
pub struct Test {
    #[readonly]
    pub owner: PubKey,
}

impl Test {
    pub fn check(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.owner));
    }
}
`;
    const result = parseRustSource(source, 'Test.runar.rs');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    const method = result.contract!.methods[0]!;
    // The assert!(check_sig(sig, &self.owner)) should produce an expression_statement
    expect(method.body.length).toBe(1);
  });

  it('handles property initializers via init()', () => {
    const source = `
use runar::prelude::*;

#[runar::contract]
pub struct Counter {
    pub count: Bigint,
    #[readonly]
    pub active: bool,
}

impl Counter {
    pub fn init(&mut self) {
        self.count = 0;
        self.active = true;
    }

    pub fn increment(&mut self) {
        self.count += 1;
    }
}
`;
    const result = parseRustSource(source, 'Counter.runar.rs');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);

    // count and active should have initializers
    const countProp = result.contract!.properties.find(p => p.name === 'count');
    expect(countProp!.initializer).toBeDefined();
    expect(countProp!.initializer!.kind).toBe('bigint_literal');

    const activeProp = result.contract!.properties.find(p => p.name === 'active');
    expect(activeProp!.initializer).toBeDefined();
    expect(activeProp!.initializer!.kind).toBe('bool_literal');

    // init() should not appear in methods
    expect(result.contract!.methods.find(m => m.name === 'init')).toBeUndefined();

    // Constructor should only have uninit props (none after init())
    // Both count and active are initialized, so constructor has 0 params
    expect(result.contract!.constructor.params.length).toBe(0);
  });

  it('handles for..range loops', () => {
    const source = `
use runar::prelude::*;

#[runar::contract]
pub struct Loop {
    #[readonly]
    pub expected: Bigint,
}

impl Loop {
    pub fn verify(&self, start: Bigint) {
        let mut sum: Bigint = 0;
        for i in 0..5 {
            sum = sum + start + i;
        }
        assert!(sum == self.expected);
    }
}
`;
    const result = parseRustSource(source, 'Loop.runar.rs');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    const method = result.contract!.methods[0]!;
    // Should have: variable_decl, for_statement, expression_statement(assert)
    const forStmt = method.body.find(s => s.kind === 'for_statement');
    expect(forStmt).toBeDefined();
  });

  it('detects stateful vs stateless contracts', () => {
    // Stateless: all fields readonly
    const stateless = parseRustSource(`
use runar::prelude::*;
#[runar::contract]
struct Test { #[readonly] x: Bigint, }
impl Test { pub fn verify(&self) { assert!(self.x > 0); } }
`, 'Test.runar.rs');
    expect(stateless.contract!.parentClass).toBe('SmartContract');

    // Stateful: at least one mutable field
    const stateful = parseRustSource(`
use runar::prelude::*;
#[runar::contract]
struct Test { x: Bigint, }
impl Test { pub fn set(&mut self) { self.x = 1; } }
`, 'Test.runar.rs');
    expect(stateful.contract!.parentClass).toBe('StatefulSmartContract');
  });

  it('converts trailing expression without semicolon to return_statement', () => {
    const source = `
use runar::prelude::*;

#[runar::contract]
pub struct Test {
    #[readonly]
    pub x: Bigint,
}

impl Test {
    fn helper(&self, a: Bigint, b: Bigint) -> Bigint {
        a + b
    }

    pub fn check(&self, v: Bigint) {
        assert!(self.helper(v, 1) > 0);
    }
}
`;
    const result = parseRustSource(source, 'Test.runar.rs');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    const helper = result.contract!.methods.find(m => m.name === 'helper');
    expect(helper).toBeDefined();
    // The trailing expression should be a return_statement, not an expression_statement
    const lastStmt = helper!.body[helper!.body.length - 1]!;
    expect(lastStmt.kind).toBe('return_statement');
  });

  it('strips txPreimage property from stateful Rust contracts', () => {
    const source = `
use runar::prelude::*;

#[runar::contract]
pub struct Counter {
    pub count: Bigint,
    pub tx_preimage: SigHashPreimage,
}

impl Counter {
    pub fn increment(&mut self) {
        self.count = self.count + 1;
    }
}
`;
    const result = parseRustSource(source, 'Counter.runar.rs');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    // txPreimage should be stripped — it's implicit for StatefulSmartContract
    const propNames = result.contract!.properties.map(p => p.name);
    expect(propNames).not.toContain('txPreimage');
    expect(propNames).toContain('count');
  });

  it('private methods with return types pass full pipeline', () => {
    const source = `
use runar::prelude::*;

#[runar::contract]
pub struct Calc {
    #[readonly]
    pub x: Bigint,
}

impl Calc {
    fn double(&self, n: Bigint) -> Bigint {
        n + n
    }

    pub fn check(&self, v: Bigint) {
        assert!(self.double(v) == self.x);
    }
}
`;
    const result = parse(source, 'Calc.runar.rs');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);

    const valResult = validate(result.contract!);
    expect(valResult.errors.filter(e => e.severity === 'error')).toEqual([]);

    const tcResult = typecheck(result.contract!);
    expect(tcResult.errors.filter(e => e.severity === 'error')).toEqual([]);
  });

  it('parses a bare impl block without #[runar::methods]', () => {
    const source = `
use runar::prelude::*;

#[runar::contract]
pub struct Counter {
    pub count: Bigint,
}

impl Counter {
    pub fn increment(&mut self) {
        self.count += 1;
    }

    fn helper(&self) {
        assert!(self.count > 0);
    }
}
`;
    const result = parseRustSource(source, 'Counter.runar.rs');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract!.methods.map(m => m.name)).toEqual(['increment', 'helper']);
    expect(result.contract!.methods[0]!.visibility).toBe('public');
    expect(result.contract!.methods[1]!.visibility).toBe('private');
  });

  it('merges multiple impl blocks in source order', () => {
    const source = `
use runar::prelude::*;

#[runar::contract]
pub struct Multi {
    #[readonly]
    pub x: Bigint,
}

impl Multi {
    pub fn first(&self) {
        assert!(self.x > 0);
    }
}

impl Multi {
    pub fn second(&self) {
        assert!(self.x < 100);
    }
}
`;
    const result = parseRustSource(source, 'Multi.runar.rs');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract!.methods.map(m => m.name)).toEqual(['first', 'second']);
  });

  it('parses an impl block declared before the struct', () => {
    const source = `
use runar::prelude::*;

impl Early {
    pub fn check(&self) {
        assert!(self.x > 0);
    }
}

#[runar::contract]
pub struct Early {
    #[readonly]
    pub x: Bigint,
}
`;
    const result = parseRustSource(source, 'Early.runar.rs');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract!.name).toBe('Early');
    expect(result.contract!.methods.map(m => m.name)).toEqual(['check']);
  });

  it('rejects the removed #[runar::methods] attribute', () => {
    const source = `
use runar::prelude::*;

#[runar::contract]
pub struct Old {
    #[readonly]
    pub x: Bigint,
}

#[runar::methods(Old)]
impl Old {
    pub fn check(&self) {
        assert!(self.x > 0);
    }
}
`;
    const result = parseRustSource(source, 'Old.runar.rs');
    expect(result.errors.some(e => e.message.includes('#[runar::methods]'))).toBe(true);
  });

  it('rejects the removed #[public] attribute', () => {
    const source = `
use runar::prelude::*;

#[runar::contract]
pub struct Old {
    #[readonly]
    pub x: Bigint,
}

impl Old {
    #[public]
    pub fn check(&self) {
        assert!(self.x > 0);
    }
}
`;
    const result = parseRustSource(source, 'Old.runar.rs');
    expect(result.errors.some(e => e.message.includes('#[public]'))).toBe(true);
  });
});
