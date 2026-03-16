/**
 * Rust parser: verify all example contracts and conformance tests parse correctly.
 */

import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { parseRustSource } from '../passes/01-parse-rust.js';
import { readFileSync, existsSync, readdirSync } from 'fs';
import { join } from 'path';

// ---------------------------------------------------------------------------
// Conformance tests
// ---------------------------------------------------------------------------

const CONFORMANCE_DIR = join(__dirname, '..', '..', '..', '..', 'conformance', 'tests');

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
    it(`parses ${dir}.runar.rs conformance test`, () => {
      const path = join(CONFORMANCE_DIR, dir, `${dir}.runar.rs`);
      if (!existsSync(path)) return;
      const source = readFileSync(path, 'utf-8');
      const result = parse(source, `${dir}.runar.rs`);
      const errors = result.errors.filter(e => e.severity === 'error');
      expect(errors).toEqual([]);
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
      const rsPath = join(CONFORMANCE_DIR, dir, `${dir}.runar.rs`);
      const tsPath = join(CONFORMANCE_DIR, dir, `${dir}.runar.ts`);
      if (!existsSync(rsPath) || !existsSync(tsPath)) return;

      const rsResult = parse(readFileSync(rsPath, 'utf-8'), `${dir}.runar.rs`);
      const tsResult = parse(readFileSync(tsPath, 'utf-8'), `${dir}.runar.ts`);

      if (!rsResult.contract || !tsResult.contract) return;
      if (rsResult.errors.some(e => e.severity === 'error')) return;
      if (tsResult.errors.some(e => e.severity === 'error')) return;

      // Contract name
      expect(rsResult.contract.name).toBe(tsResult.contract.name);

      // Same number of properties
      expect(rsResult.contract.properties.length).toBe(tsResult.contract.properties.length);

      // Property names and readonly flags
      for (let j = 0; j < tsResult.contract.properties.length; j++) {
        expect(rsResult.contract.properties[j]!.name).toBe(tsResult.contract.properties[j]!.name);
        expect(rsResult.contract.properties[j]!.readonly).toBe(tsResult.contract.properties[j]!.readonly);
      }

      // Same number of methods
      expect(rsResult.contract.methods.length).toBe(tsResult.contract.methods.length);

      // Method names, visibility, and param counts
      for (let j = 0; j < tsResult.contract.methods.length; j++) {
        expect(rsResult.contract.methods[j]!.name).toBe(tsResult.contract.methods[j]!.name);
        expect(rsResult.contract.methods[j]!.visibility).toBe(tsResult.contract.methods[j]!.visibility);
        expect(rsResult.contract.methods[j]!.params.length).toBe(tsResult.contract.methods[j]!.params.length);
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
      expect(result.contract!.properties.length).toBeGreaterThanOrEqual(1);
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

#[runar::methods(P2PKH)]
impl P2PKH {
    #[public]
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

#[runar::methods(Test)]
impl Test {
    #[public]
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

#[runar::methods(Test)]
impl Test {
    #[public]
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

#[runar::methods(Counter)]
impl Counter {
    pub fn init(&mut self) {
        self.count = 0;
        self.active = true;
    }

    #[public]
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

#[runar::methods(Loop)]
impl Loop {
    #[public]
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
#[runar::methods(Test)]
impl Test { #[public] fn verify(&self) { assert!(self.x > 0); } }
`, 'Test.runar.rs');
    expect(stateless.contract!.parentClass).toBe('SmartContract');

    // Stateful: at least one mutable field
    const stateful = parseRustSource(`
use runar::prelude::*;
#[runar::contract]
struct Test { x: Bigint, }
#[runar::methods(Test)]
impl Test { #[public] fn set(&mut self) { self.x = 1; } }
`, 'Test.runar.rs');
    expect(stateful.contract!.parentClass).toBe('StatefulSmartContract');
  });
});
