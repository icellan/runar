import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  arbGeneratedContract,
  arbGeneratedStatefulContract,
  renderTypeScript,
  renderGo,
  renderRust,
  renderPython,
  renderZig,
  renderRuby,
  RENDERERS,
} from '../fuzzer/index.js';
import type { GeneratedContract as _GeneratedContract } from '../fuzzer/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Quick check that source parses without throwing (via compile). */
async function assertParseable(source: string, fileName: string): Promise<void> {
  const { compile } = await import('runar-compiler');
  const result = compile(source, { fileName, parseOnly: true });
  if (!result.success) {
    const errors = result.diagnostics.map((d) => d.message).join('\n');
    throw new Error(`Parse failed for ${fileName}:\n${errors}\n\nSource:\n${source}`);
  }
}

// ---------------------------------------------------------------------------
// 1. IR generator produces valid structure
// ---------------------------------------------------------------------------

describe('IR generators: structure', () => {
  it('arbGeneratedContract produces valid stateless contracts', () => {
    const contracts = fc.sample(arbGeneratedContract, { numRuns: 20 });
    for (const contract of contracts) {
      expect(contract.parentClass).toBe('SmartContract');
      expect(contract.properties.length).toBeGreaterThanOrEqual(1);
      expect(contract.methods.length).toBeGreaterThanOrEqual(1);
      // All properties should be readonly for SmartContract
      for (const prop of contract.properties) {
        expect(prop.readonly).toBe(true);
      }
    }
  });

  it('arbGeneratedStatefulContract produces valid stateful contracts', () => {
    const contracts = fc.sample(arbGeneratedStatefulContract, { numRuns: 20 });
    for (const contract of contracts) {
      expect(contract.parentClass).toBe('StatefulSmartContract');
      expect(contract.properties.length).toBeGreaterThanOrEqual(1);
      expect(contract.methods.length).toBeGreaterThanOrEqual(1);
      // At least one mutable property
      const mutable = contract.properties.filter((p) => !p.readonly);
      expect(mutable.length).toBeGreaterThanOrEqual(1);
      // At least one method mutates state
      const mutating = contract.methods.filter((m) => m.mutatesState);
      expect(mutating.length).toBeGreaterThanOrEqual(1);
    }
  });
});

// ---------------------------------------------------------------------------
// 2. TypeScript renderer produces parseable output
// ---------------------------------------------------------------------------

describe('TypeScript renderer', () => {
  it('renders stateless contracts that parse successfully', async () => {
    const contracts = fc.sample(arbGeneratedContract, { numRuns: 10, seed: 42 });
    for (const contract of contracts) {
      const source = renderTypeScript(contract);
      expect(source).toContain('SmartContract');
      expect(source).toContain('constructor');
      await assertParseable(source, `${contract.name}.runar.ts`);
    }
  });

  it('renders stateful contracts that parse successfully', async () => {
    const contracts = fc.sample(arbGeneratedStatefulContract, { numRuns: 10, seed: 42 });
    for (const contract of contracts) {
      const source = renderTypeScript(contract);
      expect(source).toContain('StatefulSmartContract');
      await assertParseable(source, `${contract.name}.runar.ts`);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. All renderers produce non-empty output
// ---------------------------------------------------------------------------

describe('Multi-format renderers', () => {
  const formats = ['ts', 'go', 'rs', 'py', 'zig', 'rb'] as const;

  it.each(formats)('%s renderer produces non-empty output', (format) => {
    const contracts = fc.sample(arbGeneratedContract, { numRuns: 5, seed: 123 });
    const render = RENDERERS[format];

    for (const contract of contracts) {
      const source = render(contract);
      expect(source.length).toBeGreaterThan(0);
      expect(source).toContain(contract.name);
    }
  });

  it('Go renderer uses correct syntax', () => {
    const contracts = fc.sample(arbGeneratedContract, { numRuns: 3, seed: 1 });
    for (const contract of contracts) {
      const source = renderGo(contract);
      expect(source).toContain('package contract');
      expect(source).toContain('import "runar"');
      expect(source).toContain('runar.SmartContract');
      expect(source).toContain('func (c *');
    }
  });

  it('Rust renderer uses correct syntax', () => {
    const contracts = fc.sample(arbGeneratedContract, { numRuns: 3, seed: 1 });
    for (const contract of contracts) {
      const source = renderRust(contract);
      expect(source).toContain('use runar::prelude::*');
      expect(source).toContain('#[runar::contract]');
      expect(source).toContain('#[public]');
      expect(source).toContain('&self');
    }
  });

  it('Python renderer uses correct syntax', () => {
    const contracts = fc.sample(arbGeneratedContract, { numRuns: 3, seed: 1 });
    for (const contract of contracts) {
      const source = renderPython(contract);
      expect(source).toContain('from runar import');
      expect(source).toContain('SmartContract');
      expect(source).toContain('@public');
      expect(source).toContain('assert_');
      expect(source).toContain('def __init__');
    }
  });

  it('Zig renderer uses correct syntax', () => {
    const contracts = fc.sample(arbGeneratedContract, { numRuns: 3, seed: 1 });
    for (const contract of contracts) {
      const source = renderZig(contract);
      expect(source).toContain('@import("runar")');
      expect(source).toContain('pub const Contract = runar.SmartContract');
      expect(source).toContain('pub fn init');
      expect(source).toContain('runar.assert');
    }
  });

  it('Ruby renderer uses correct syntax', () => {
    const contracts = fc.sample(arbGeneratedContract, { numRuns: 3, seed: 1 });
    for (const contract of contracts) {
      const source = renderRuby(contract);
      expect(source).toContain("require 'runar'");
      expect(source).toContain('Runar::SmartContract');
      expect(source).toContain('runar_public');
      expect(source).toContain('def initialize');
      expect(source).toContain('assert');
    }
  });
});

// ---------------------------------------------------------------------------
// 4. Stateful renderers use correct patterns
// ---------------------------------------------------------------------------

describe('Stateful contract renderers', () => {
  it('TypeScript stateful uses StatefulSmartContract and state mutation', () => {
    const contracts = fc.sample(arbGeneratedStatefulContract, { numRuns: 3, seed: 1 });
    for (const contract of contracts) {
      const source = renderTypeScript(contract);
      expect(source).toContain('StatefulSmartContract');
      // Should have an assignment to this.propName
      expect(source).toMatch(/this\.\w+ =/);
    }
  });

  it('Rust stateful uses &mut self', () => {
    const contracts = fc.sample(arbGeneratedStatefulContract, { numRuns: 3, seed: 1 });
    for (const contract of contracts) {
      const source = renderRust(contract);
      expect(source).toContain('&mut self');
    }
  });

  it('Zig stateful uses mutable pointer', () => {
    const contracts = fc.sample(arbGeneratedStatefulContract, { numRuns: 3, seed: 1 });
    for (const contract of contracts) {
      const source = renderZig(contract);
      expect(source).toContain('runar.StatefulSmartContract');
      // Should have *ContractName (mutable self)
      expect(source).toMatch(/self: \*\w+/);
    }
  });
});
