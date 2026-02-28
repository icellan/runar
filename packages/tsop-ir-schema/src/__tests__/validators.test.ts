import { describe, it, expect } from 'vitest';
import { validateANF, validateArtifact } from '../validators.js';

// ---------------------------------------------------------------------------
// A minimal valid P2PKH program in ANF IR
// ---------------------------------------------------------------------------

interface TestMethod {
  [key: string]: unknown;
  name: string;
  params: Array<{ name: string; type: string }>;
  body: Array<{ name: string; value: Record<string, unknown> }>;
  isPublic: boolean;
}

interface TestProgram {
  [key: string]: unknown;
  contractName: string;
  properties: Array<{ name: string; type: string; readonly: boolean }>;
  methods: TestMethod[];
}

function makeValidP2PKH(): TestProgram {
  return {
    contractName: 'P2PKH',
    properties: [
      { name: 'pubKeyHash', type: 'Ripemd160', readonly: true },
    ],
    methods: [
      {
        name: 'unlock',
        params: [
          { name: 'sig', type: 'Sig' },
          { name: 'pubkey', type: 'PubKey' },
        ],
        body: [
          { name: 't0', value: { kind: 'load_param', name: 'pubkey' } },
          { name: 't1', value: { kind: 'call', func: 'hash160', args: ['t0'] } },
          { name: 't2', value: { kind: 'load_prop', name: 'pubKeyHash' } },
          { name: 't3', value: { kind: 'bin_op', op: '===', left: 't1', right: 't2' } },
          { name: 't4', value: { kind: 'assert', value: 't3' } },
          { name: 't5', value: { kind: 'load_param', name: 'sig' } },
          { name: 't6', value: { kind: 'load_param', name: 'pubkey' } },
          { name: 't7', value: { kind: 'call', func: 'checkSig', args: ['t5', 't6'] } },
          { name: 't8', value: { kind: 'assert', value: 't7' } },
        ],
        isPublic: true,
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// A minimal valid artifact
// ---------------------------------------------------------------------------

function makeValidArtifact() {
  return {
    version: 'tsop-v0.1.0',
    compilerVersion: '0.1.0',
    contractName: 'P2PKH',
    abi: {
      constructor: {
        params: [{ name: 'pubKeyHash', type: 'Ripemd160' }],
      },
      methods: [
        {
          name: 'unlock',
          params: [
            { name: 'sig', type: 'Sig' },
            { name: 'pubkey', type: 'PubKey' },
          ],
          isPublic: true,
        },
      ],
    },
    script: '76a91488ac',
    asm: 'OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG',
    buildTimestamp: '2025-01-15T12:00:00Z',
  };
}

// ---------------------------------------------------------------------------
// validateANF — valid programs
// ---------------------------------------------------------------------------

describe('validateANF', () => {
  it('validates a well-formed P2PKH program', () => {
    const result = validateANF(makeValidP2PKH());
    expect(result.valid).toBe(true);
  });

  it('validates a program with no properties', () => {
    const result = validateANF({
      contractName: 'Empty',
      properties: [],
      methods: [],
    });
    expect(result.valid).toBe(true);
  });

  it('validates a program with multiple methods', () => {
    const program = makeValidP2PKH();
    program.methods.push({
      name: 'anotherMethod',
      params: [],
      body: [
        { name: 't0', value: { kind: 'load_const', value: true } },
        { name: 't1', value: { kind: 'assert', value: 't0' } },
      ],
      isPublic: true,
    });
    const result = validateANF(program);
    expect(result.valid).toBe(true);
  });

  it('validates all ANF value kinds', () => {
    const program = {
      contractName: 'AllKinds',
      properties: [{ name: 'counter', type: 'int', readonly: false }],
      methods: [
        {
          name: 'test',
          params: [{ name: 'x', type: 'int' }],
          body: [
            { name: 't0', value: { kind: 'load_param', name: 'x' } },
            { name: 't1', value: { kind: 'load_prop', name: 'counter' } },
            { name: 't2', value: { kind: 'load_const', value: 42 } },
            { name: 't3', value: { kind: 'bin_op', op: '+', left: 't0', right: 't2' } },
            { name: 't4', value: { kind: 'unary_op', op: '-', operand: 't3' } },
            { name: 't5', value: { kind: 'call', func: 'hash160', args: ['t0'] } },
            { name: 't6', value: { kind: 'method_call', object: 'self', method: 'foo', args: ['t0'] } },
            {
              name: 't7',
              value: {
                kind: 'if',
                cond: 't3',
                then: [{ name: 'a0', value: { kind: 'load_const', value: 1 } }],
                else: [{ name: 'a1', value: { kind: 'load_const', value: 2 } }],
              },
            },
            {
              name: 't8',
              value: {
                kind: 'loop',
                count: 3,
                body: [{ name: 'i0', value: { kind: 'load_const', value: 0 } }],
                iterVar: 'i',
              },
            },
            { name: 't9', value: { kind: 'assert', value: 't3' } },
            { name: 't10', value: { kind: 'update_prop', name: 'counter', value: 't3' } },
            { name: 't11', value: { kind: 'get_state_script' } },
            { name: 't12', value: { kind: 'check_preimage', preimage: 't0' } },
          ],
          isPublic: true,
        },
      ],
    };
    const result = validateANF(program);
    expect(result.valid).toBe(true);
  });

  // -----------------------------------------------------------------------
  // Invalid programs
  // -----------------------------------------------------------------------

  it('rejects missing contractName', () => {
    const program = makeValidP2PKH();
    delete (program as Record<string, unknown>)['contractName'];
    const result = validateANF(program);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.length).toBeGreaterThan(0);
    }
  });

  it('rejects missing properties field', () => {
    const program = makeValidP2PKH();
    delete (program as Record<string, unknown>)['properties'];
    const result = validateANF(program);
    expect(result.valid).toBe(false);
  });

  it('rejects missing methods field', () => {
    const program = makeValidP2PKH();
    delete (program as Record<string, unknown>)['methods'];
    const result = validateANF(program);
    expect(result.valid).toBe(false);
  });

  it('rejects empty contractName', () => {
    const program = makeValidP2PKH();
    program.contractName = '';
    const result = validateANF(program);
    expect(result.valid).toBe(false);
  });

  it('rejects method missing name', () => {
    const program = makeValidP2PKH();
    delete (program.methods[0] as Record<string, unknown>)['name'];
    const result = validateANF(program);
    expect(result.valid).toBe(false);
  });

  it('rejects method missing isPublic', () => {
    const program = makeValidP2PKH();
    delete (program.methods[0] as Record<string, unknown>)['isPublic'];
    const result = validateANF(program);
    expect(result.valid).toBe(false);
  });

  it('rejects unknown kind in ANF value', () => {
    const program = {
      contractName: 'Bad',
      properties: [],
      methods: [
        {
          name: 'test',
          params: [],
          body: [
            { name: 't0', value: { kind: 'unknown_op', foo: 'bar' } },
          ],
          isPublic: true,
        },
      ],
    };
    const result = validateANF(program);
    expect(result.valid).toBe(false);
  });

  it('rejects additional properties on the top level', () => {
    const program = {
      ...makeValidP2PKH(),
      extraField: 'not allowed',
    };
    const result = validateANF(program);
    expect(result.valid).toBe(false);
  });

  it('rejects property missing required type field', () => {
    const program = {
      contractName: 'Bad',
      properties: [{ name: 'x', readonly: true }],
      methods: [],
    };
    const result = validateANF(program);
    expect(result.valid).toBe(false);
  });

  it('rejects non-object input', () => {
    const result = validateANF('not an object');
    expect(result.valid).toBe(false);
  });

  it('rejects null input', () => {
    const result = validateANF(null);
    expect(result.valid).toBe(false);
  });

  it('returns multiple errors for multiple violations', () => {
    const result = validateANF({});
    expect(result.valid).toBe(false);
    if (!result.valid) {
      // Missing contractName, properties, and methods
      expect(result.errors.length).toBeGreaterThanOrEqual(3);
    }
  });
});

// ---------------------------------------------------------------------------
// validateArtifact — valid artifacts
// ---------------------------------------------------------------------------

describe('validateArtifact', () => {
  it('validates a well-formed P2PKH artifact', () => {
    const result = validateArtifact(makeValidArtifact());
    expect(result.valid).toBe(true);
  });

  it('validates artifact with optional sourceMap', () => {
    const artifact = {
      ...makeValidArtifact(),
      sourceMap: {
        mappings: [
          { opcodeIndex: 0, sourceFile: 'P2PKH.ts', line: 10, column: 4 },
        ],
      },
    };
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(true);
  });

  it('validates artifact with optional stateFields', () => {
    const artifact = {
      ...makeValidArtifact(),
      stateFields: [
        { name: 'counter', type: 'int', index: 0 },
      ],
    };
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(true);
  });

  it('validates artifact with empty script', () => {
    const artifact = makeValidArtifact();
    artifact.script = '';
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(true);
  });

  // -----------------------------------------------------------------------
  // Invalid version format
  // -----------------------------------------------------------------------

  it('rejects invalid version format (missing tsop- prefix)', () => {
    const artifact = makeValidArtifact();
    artifact.version = 'v0.1.0';
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
  });

  it('rejects invalid version format (wrong separator)', () => {
    const artifact = makeValidArtifact();
    artifact.version = 'tsop-v0.1';
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
  });

  it('rejects version with extra parts', () => {
    const artifact = makeValidArtifact();
    artifact.version = 'tsop-v0.1.0.0';
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
  });

  it('rejects version without v prefix after tsop-', () => {
    const artifact = makeValidArtifact();
    artifact.version = 'tsop-0.1.0';
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
  });

  // -----------------------------------------------------------------------
  // Other invalid artifacts
  // -----------------------------------------------------------------------

  it('rejects missing required fields', () => {
    const result = validateArtifact({});
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.length).toBeGreaterThan(0);
    }
  });

  it('rejects non-hex script', () => {
    const artifact = makeValidArtifact();
    artifact.script = 'not-hex-zz';
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
  });

  it('rejects missing abi', () => {
    const artifact = makeValidArtifact();
    delete (artifact as Record<string, unknown>)['abi'];
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
  });

  it('rejects missing buildTimestamp', () => {
    const artifact = makeValidArtifact();
    delete (artifact as Record<string, unknown>)['buildTimestamp'];
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
  });

  it('rejects empty contractName', () => {
    const artifact = makeValidArtifact();
    artifact.contractName = '';
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
  });

  it('rejects additional properties on the top level', () => {
    const artifact = {
      ...makeValidArtifact(),
      extraField: 'not allowed',
    };
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
  });

  it('rejects null input', () => {
    const result = validateArtifact(null);
    expect(result.valid).toBe(false);
  });

  it('rejects ABI method with empty name', () => {
    const artifact = makeValidArtifact();
    artifact.abi.methods[0]!.name = '';
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
  });
});
