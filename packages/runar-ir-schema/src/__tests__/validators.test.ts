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
    version: 'runar-v0.1.0',
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
                start: 0,
                step: 1,
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

  it('rejects invalid version format (missing runar- prefix)', () => {
    const artifact = makeValidArtifact();
    artifact.version = 'v0.1.0';
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
  });

  it('rejects invalid version format (wrong separator)', () => {
    const artifact = makeValidArtifact();
    artifact.version = 'runar-v0.1';
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
  });

  it('rejects version with extra parts', () => {
    const artifact = makeValidArtifact();
    artifact.version = 'runar-v0.1.0.0';
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
  });

  it('rejects version without v prefix after runar-', () => {
    const artifact = makeValidArtifact();
    artifact.version = 'runar-0.1.0';
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

// ---------------------------------------------------------------------------
// Issue R-089 — `@sighash` fields the compilers emit but the schemas rejected.
//
// Every tier emits `{ kind: 'check_preimage', preimage, sighashFlag }` for a
// method that declares a non-default `@sighash` mode, and carries the same
// mode into `abi.methods[].sigHashType`. Both `$defs` are
// `additionalProperties: false`, so before this was fixed `validateANF` /
// `validateArtifact` REJECTED correct compiler output — the one artifact-level
// gate that could have caught a *dropped* sighash field could not process a
// *present* one.
//
// The fields are optional: absent means the default `ALL|FORKID` (0x41), which
// keeps every pre-existing golden byte-identical.
// ---------------------------------------------------------------------------

/** `SINGLE|FORKID` = 0x43 = 67 — the flag the Go/TS tiers emit for that mode. */
const SIGHASH_SINGLE_FORKID = 67;

function makeSighashANF(): TestProgram {
  return {
    contractName: 'Sighash',
    properties: [{ name: 'n', type: 'bigint', readonly: false }],
    methods: [
      {
        name: 'bump',
        params: [{ name: 'txPreimage', type: 'SigHashPreimage' }],
        body: [
          { name: 't0', value: { kind: 'load_param', name: 'txPreimage' } },
          {
            name: 't1',
            value: {
              kind: 'check_preimage',
              preimage: 't0',
              sighashFlag: SIGHASH_SINGLE_FORKID,
            },
          },
          { name: 't2', value: { kind: 'assert', value: 't1' } },
        ],
        isPublic: true,
      },
    ],
  };
}

describe('R-089 — check_preimage.sighashFlag (ANF)', () => {
  it('accepts a check_preimage carrying a non-default sighashFlag', () => {
    const result = validateANF(makeSighashANF());
    if (!result.valid) {
      throw new Error(
        'validateANF rejected a check_preimage with sighashFlag:\n' +
          result.errors.map((e) => `  ${e.path}: ${e.message} [${e.keyword}]`).join('\n'),
      );
    }
    expect(result.valid).toBe(true);
  });

  it('control: the same program without sighashFlag (default mode) still validates', () => {
    const anf = makeSighashANF();
    delete (anf.methods[0]!.body[1]!.value as Record<string, unknown>).sighashFlag;
    expect(validateANF(anf).valid).toBe(true);
  });

  it('rejects a non-integer sighashFlag', () => {
    const anf = makeSighashANF();
    (anf.methods[0]!.body[1]!.value as Record<string, unknown>).sighashFlag = 'SINGLE|FORKID';
    expect(validateANF(anf).valid).toBe(false);
  });

  it('still rejects a genuinely bogus extra property on check_preimage', () => {
    const anf = makeSighashANF();
    (anf.methods[0]!.body[1]!.value as Record<string, unknown>).notARealField = 1;
    const result = validateANF(anf);
    expect(result.valid).toBe(false);
    expect(
      (result as { errors: Array<{ keyword: string }> }).errors.some(
        (e) => e.keyword === 'additionalProperties',
      ),
    ).toBe(true);
  });
});

describe('R-089 — ABIMethod.sigHashType (artifact)', () => {
  function makeSighashArtifact() {
    const artifact = makeValidArtifact();
    (artifact.abi.methods[0] as Record<string, unknown>).sigHashType =
      SIGHASH_SINGLE_FORKID;
    return artifact;
  }

  it('accepts an ABI method carrying a non-default sigHashType', () => {
    const result = validateArtifact(makeSighashArtifact());
    if (!result.valid) {
      throw new Error(
        'validateArtifact rejected an ABI method with sigHashType:\n' +
          result.errors.map((e) => `  ${e.path}: ${e.message} [${e.keyword}]`).join('\n'),
      );
    }
    expect(result.valid).toBe(true);
  });

  it('control: the same artifact without sigHashType (default mode) still validates', () => {
    expect(validateArtifact(makeValidArtifact()).valid).toBe(true);
  });

  it('rejects a non-integer sigHashType', () => {
    const artifact = makeSighashArtifact();
    (artifact.abi.methods[0] as Record<string, unknown>).sigHashType = '0x43';
    expect(validateArtifact(artifact).valid).toBe(false);
  });

  it('still rejects a genuinely bogus extra property on an ABI method', () => {
    const artifact = makeSighashArtifact();
    (artifact.abi.methods[0] as Record<string, unknown>).notARealField = true;
    const result = validateArtifact(artifact);
    expect(result.valid).toBe(false);
    expect(
      (result as { errors: Array<{ keyword: string }> }).errors.some(
        (e) => e.keyword === 'additionalProperties',
      ),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// R-089 audit follow-up — `add_output.preimage` carries `''` as a sentinel.
//
// An EXPLICIT `this.addOutput(...)` has no verified-preimage temp to extract a
// codePart from, so all seven tiers emit `preimage: ''`; stack lowering reads
// it as "no ref" (`if (value.preimage) refs.push(...)` in 05-stack-lower.ts).
// The schema's `minLength: 1` therefore rejected 11 of the 74 CHECKED-IN
// golden ANFs. `check_preimage` / `deserialize_state` always name a real temp
// and keep their `minLength: 1`.
// ---------------------------------------------------------------------------

describe("R-089 — add_output.preimage accepts the '' sentinel", () => {
  function makeAddOutputANF(preimage: string): TestProgram {
    return {
      contractName: 'Emitter',
      properties: [{ name: 'n', type: 'bigint', readonly: false }],
      methods: [
        {
          name: 'pay',
          params: [],
          body: [
            { name: 't0', value: { kind: 'load_const', value: 1000 } },
            { name: 't1', value: { kind: 'load_prop', name: 'n' } },
            {
              name: 't2',
              value: {
                kind: 'add_output',
                satoshis: 't0',
                stateValues: ['t1'],
                preimage,
              },
            },
          ],
          isPublic: true,
        },
      ],
    };
  }

  it("accepts an explicit addOutput's empty preimage", () => {
    const result = validateANF(makeAddOutputANF(''));
    if (!result.valid) {
      throw new Error(
        "validateANF rejected add_output with the '' preimage sentinel:\n" +
          result.errors.map((e) => `  ${e.path}: ${e.message} [${e.keyword}]`).join('\n'),
      );
    }
    expect(result.valid).toBe(true);
  });

  it('control: a named preimage temp still validates', () => {
    expect(validateANF(makeAddOutputANF('t9')).valid).toBe(true);
  });

  it('still requires the preimage key to be present', () => {
    const anf = makeAddOutputANF('');
    delete (anf.methods[0]!.body[2]!.value as Record<string, unknown>).preimage;
    expect(validateANF(anf).valid).toBe(false);
  });

  it('control: check_preimage still rejects an empty preimage ref', () => {
    const anf = makeSighashANF();
    (anf.methods[0]!.body[1]!.value as Record<string, unknown>).preimage = '';
    const result = validateANF(anf);
    expect(result.valid).toBe(false);
    expect(
      (result as { errors: Array<{ keyword: string }> }).errors.some(
        (e) => e.keyword === 'minLength',
      ),
    ).toBe(true);
  });
});
