import { describe, it, expect } from 'vitest';
import { Project, SyntaxKind } from 'ts-morph';
import { flatten } from './support/diagnostic-sites.js';

/**
 * Unit tests for the flatten() function, especially its ability to resolve
 * top-level const identifiers while rejecting locals, let/var, and nested consts.
 */

describe('flatten() — const resolution', () => {
  /**
   * Helper: create a SourceFile with the given source code and extract an
   * identifier node for the argument to makeDiagnostic(...).
   */
  function getIdentifierForFlattening(sourceCode: string): { node: any; sourceFile: any } | null {
    const project = new Project({ skipAddingFilesFromTsConfig: true });
    const sf = project.createSourceFile('test.ts', sourceCode);

    // Find the makeDiagnostic call and get its first argument
    const calls = sf.getDescendantsOfKind(SyntaxKind.CallExpression);
    for (const call of calls) {
      if (call.getExpression().getText() === 'makeDiagnostic') {
        const args = call.getArguments();
        if (args.length > 0) {
          return { node: args[0]!, sourceFile: sf };
        }
      }
    }
    return null;
  }

  it('(a) resolves const M = "a" + "b"; makeDiagnostic(M, …) to "ab"', () => {
    const source = `
      const M = 'a' + 'b';
      makeDiagnostic(M, 'error', {});
    `;
    const result = getIdentifierForFlattening(source);
    expect(result).not.toBeNull();
    if (result) {
      const flattened = flatten(result.node, result.sourceFile);
      expect(flattened).toBe('ab');
    }
  });

  it('(b) an identifier naming a let resolves to null', () => {
    const source = `
      let M = 'hello';
      makeDiagnostic(M, 'error', {});
    `;
    const result = getIdentifierForFlattening(source);
    expect(result).not.toBeNull();
    if (result) {
      const flattened = flatten(result.node, result.sourceFile);
      expect(flattened).toBeNull();
    }
  });

  it('(c) an identifier naming a const inside a function resolves to null', () => {
    const source = `
      function foo() {
        const M = 'hello';
        makeDiagnostic(M, 'error', {});
      }
    `;
    const result = getIdentifierForFlattening(source);
    expect(result).not.toBeNull();
    if (result) {
      const flattened = flatten(result.node, result.sourceFile);
      expect(flattened).toBeNull();
    }
  });

  it('(d) an unknown identifier resolves to null', () => {
    const source = `
      makeDiagnostic(unknownIdentifier, 'error', {});
    `;
    const result = getIdentifierForFlattening(source);
    expect(result).not.toBeNull();
    if (result) {
      const flattened = flatten(result.node, result.sourceFile);
      expect(flattened).toBeNull();
    }
  });

  it('resolves const with template literal: const M = `hello`', () => {
    const source = `
      const M = \`hello\`;
      makeDiagnostic(M, 'error', {});
    `;
    const result = getIdentifierForFlattening(source);
    expect(result).not.toBeNull();
    if (result) {
      const flattened = flatten(result.node, result.sourceFile);
      expect(flattened).toBe('hello');
    }
  });

  it('resolves const with longer chain: const M = "a" + "b" + "c"', () => {
    const source = `
      const M = 'a' + 'b' + 'c';
      makeDiagnostic(M, 'error', {});
    `;
    const result = getIdentifierForFlattening(source);
    expect(result).not.toBeNull();
    if (result) {
      const flattened = flatten(result.node, result.sourceFile);
      expect(flattened).toBe('abc');
    }
  });

  it('distinguishes between const and var at module level', () => {
    const source = `
      var M = 'var is mutable';
      makeDiagnostic(M, 'error', {});
    `;
    const result = getIdentifierForFlattening(source);
    expect(result).not.toBeNull();
    if (result) {
      const flattened = flatten(result.node, result.sourceFile);
      // var should resolve to null, only const is allowed
      expect(flattened).toBeNull();
    }
  });
});
