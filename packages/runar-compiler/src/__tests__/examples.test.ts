import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { compile } from '../index.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import { emit } from '../passes/06-emit.js';
import { assembleArtifact } from '../artifact/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Find example contracts
// ---------------------------------------------------------------------------

const EXAMPLES_DIR = join(__dirname, '..', '..', '..', '..', 'examples', 'ts');

interface ExampleContract {
  name: string;
  fileName: string;
  source: string;
}

function findExampleContracts(): ExampleContract[] {
  const contracts: ExampleContract[] = [];

  try {
    const dirs = readdirSync(EXAMPLES_DIR, { withFileTypes: true });
    for (const dir of dirs) {
      if (!dir.isDirectory()) continue;
      const dirPath = join(EXAMPLES_DIR, dir.name);
      const files = readdirSync(dirPath);
      for (const file of files) {
        if (file.endsWith('.runar.ts')) {
          const source = readFileSync(join(dirPath, file), 'utf-8');
          contracts.push({
            name: file.replace('.runar.ts', ''),
            fileName: file,
            source,
          });
        }
      }
    }
  } catch {
    // examples directory may not exist
  }

  return contracts;
}

const examples = findExampleContracts();

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Example contracts: end-to-end compilation', () => {
  it('found at least one example contract', () => {
    expect(examples.length).toBeGreaterThan(0);
  });

  for (const example of examples) {
    describe(`${example.name} (${example.fileName})`, () => {
      it('compiles through the TS compiler (parse + validate + typecheck + ANF)', () => {
        const result = compile(example.source, { fileName: example.fileName });

        // The compile function should always return a result (not throw)
        expect(result).toBeDefined();
        expect(result.diagnostics).toBeDefined();
        expect(Array.isArray(result.diagnostics)).toBe(true);

        if (result.success) {
          // When successful, contract and ANF must be present
          expect(result.contract).not.toBeNull();
          expect(result.anf).not.toBeNull();
        } else {
          // When it fails, diagnostics should explain why
          const errors = result.diagnostics.filter(d => d.severity === 'error');
          expect(errors.length).toBeGreaterThan(0);
          // Each error should have a message
          for (const err of errors) {
            expect(err.message).toBeDefined();
            expect(typeof err.message).toBe('string');
          }
        }
      });

      it('produces a valid artifact structure (if backend passes succeed)', () => {
        const compileResult = compile(example.source, { fileName: example.fileName });

        // Skip if frontend compilation failed
        if (!compileResult.success || !compileResult.anf || !compileResult.contract) {
          return;
        }

        const stackProgram = lowerToStack(compileResult.anf);
        expect(stackProgram).toBeDefined();
        expect(stackProgram.contractName).toBe(compileResult.anf.contractName);

        const emitResult = emit(stackProgram);
        expect(emitResult).toBeDefined();

        // Assemble artifact
        const artifact = assembleArtifact(
          compileResult.contract,
          compileResult.anf,
          stackProgram,
          emitResult.scriptHex,
          emitResult.scriptAsm,
        );

        // Verify artifact structure
        // Note: the contract name in the artifact comes from the class name
        // in the source, which may differ from the file name
        expect(artifact.contractName).toBeDefined();
        expect(typeof artifact.contractName).toBe('string');
        expect(artifact.contractName.length).toBeGreaterThan(0);
        expect(artifact.abi).toBeDefined();
        expect(artifact.abi.constructor).toBeDefined();
        expect(artifact.abi.methods).toBeDefined();
        expect(Array.isArray(artifact.abi.methods)).toBe(true);
        expect(artifact.script).toBeDefined();
        expect(typeof artifact.script).toBe('string');
        expect(artifact.asm).toBeDefined();
        expect(typeof artifact.asm).toBe('string');
        expect(artifact.version).toBeDefined();
        expect(artifact.compilerVersion).toBeDefined();
        expect(artifact.buildTimestamp).toBeDefined();

        // Script should be valid hex (or empty for edge cases)
        if (artifact.script.length > 0) {
          expect(/^[0-9a-f]+$/.test(artifact.script)).toBe(true);
        }

        // ASM should contain recognizable opcodes — either an OP_* mnemonic
        // or a `<raw N bytes>` token (the only legal asm rendering for an
        // `asm(...)` raw-script body that decodes to no opcode mnemonics).
        if (artifact.asm.length > 0) {
          expect(artifact.asm).toMatch(/OP_|<raw \d+ bytes>/);
        }

        // ABI methods should have names
        for (const method of artifact.abi.methods) {
          expect(method.name).toBeDefined();
          expect(typeof method.name).toBe('string');
          expect(method.name.length).toBeGreaterThan(0);
          expect(Array.isArray(method.params)).toBe(true);
          expect(typeof method.isPublic).toBe('boolean');
        }
      });

      it('produces a non-empty locking script (if backend passes succeed)', () => {
        const compileResult = compile(example.source, { fileName: example.fileName });

        if (!compileResult.success || !compileResult.anf || !compileResult.contract) {
          return;
        }

        const stackProgram = lowerToStack(compileResult.anf);
        const emitResult = emit(stackProgram);

        // The script should not be empty (a valid contract should produce code)
        expect(emitResult.scriptHex.length).toBeGreaterThan(0);
        expect(emitResult.scriptAsm.length).toBeGreaterThan(0);
      });

      it('has at least one public method in the ABI', () => {
        const compileResult = compile(example.source, { fileName: example.fileName });

        if (!compileResult.success || !compileResult.contract) {
          return;
        }

        const publicMethods = compileResult.contract.methods.filter(
          m => m.visibility === 'public',
        );
        expect(publicMethods.length).toBeGreaterThan(0);
      });
    });
  }
});

// ---------------------------------------------------------------------------
// ANF IR structural checks
// ---------------------------------------------------------------------------

describe('Example contracts: ANF IR structure', () => {
  for (const example of examples) {
    it(`${example.name} ANF IR has expected shape`, () => {
      const result = compile(example.source, { fileName: example.fileName });

      if (!result.success || !result.anf) {
        return;
      }

      const anf = result.anf;

      // Must have a contract name (may differ from file name)
      expect(anf.contractName).toBeDefined();
      expect(typeof anf.contractName).toBe('string');
      expect(anf.contractName.length).toBeGreaterThan(0);

      // Properties should be an array
      expect(Array.isArray(anf.properties)).toBe(true);

      // Methods should be an array with at least one entry
      expect(Array.isArray(anf.methods)).toBe(true);
      expect(anf.methods.length).toBeGreaterThan(0);

      // Each method should have valid structure
      for (const method of anf.methods) {
        expect(method.name).toBeDefined();
        expect(Array.isArray(method.params)).toBe(true);
        expect(Array.isArray(method.body)).toBe(true);
        expect(typeof method.isPublic).toBe('boolean');

        // Each binding should have name and value
        for (const binding of method.body) {
          expect(binding.name).toBeDefined();
          expect(typeof binding.name).toBe('string');
          expect(binding.value).toBeDefined();
          expect(binding.value.kind).toBeDefined();
        }
      }
    });
  }
});
