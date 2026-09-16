/**
 * Rúnar Program Fuzzer — generates random valid Rúnar contract source strings
 * for property-based testing (CSmith-inspired).
 *
 * Uses fast-check Arbitrary combinators to produce well-typed, syntactically
 * valid Rúnar contracts.
 */

import fc from 'fast-check';
import type {
  GeneratedContract,
  GeneratedProperty,
  GeneratedMethod,
  GeneratedParam,
  Expr,
  Stmt,
  ForStmt,
  IfStmt,
  RuinarType,
} from './contract-ir.js';

// ---------------------------------------------------------------------------
// Primitive types available in Rúnar
// ---------------------------------------------------------------------------

const PROPERTY_TYPES = ['bigint', 'boolean', 'ByteString', 'PubKey', 'Sig'] as const;
type PropertyType = (typeof PROPERTY_TYPES)[number];

// ---------------------------------------------------------------------------
// Name generators
// ---------------------------------------------------------------------------

const arbPropertyName: fc.Arbitrary<string> = fc
  .integer({ min: 0, max: 99 })
  .map((n) => `prop${n}`);

const arbParamName: fc.Arbitrary<string> = fc
  .integer({ min: 0, max: 99 })
  .map((n) => `param${n}`);

const arbLocalName: fc.Arbitrary<string> = fc
  .integer({ min: 0, max: 99 })
  .map((n) => `local${n}`);

const arbMethodName: fc.Arbitrary<string> = fc
  .integer({ min: 0, max: 9 })
  .map((n) => `method${n}`);

const arbContractName: fc.Arbitrary<string> = fc
  .integer({ min: 0, max: 99 })
  .map((n) => `TestContract${n}`);

const arbPropertyType: fc.Arbitrary<PropertyType> = fc.constantFrom(...PROPERTY_TYPES);

// ---------------------------------------------------------------------------
// Expression generators
// ---------------------------------------------------------------------------

interface PropertyDef {
  name: string;
  type: PropertyType;
}

interface ParamDef {
  name: string;
  type: PropertyType;
}

function arbBigintLiteral(): fc.Arbitrary<string> {
  return fc.bigInt({ min: -1000n, max: 1000n }).map((n) => `${n}n`);
}

function arbBoolLiteral(): fc.Arbitrary<string> {
  return fc.boolean().map((b) => String(b));
}

/** Generate a random ByteString literal expression. */
export function arbByteStringLiteral(): fc.Arbitrary<string> {
  return fc
    .array(fc.integer({ min: 0, max: 255 }), { minLength: 0, maxLength: 8 })
    .map(
      (bytes) =>
        `toByteString('${bytes.map((b) => b.toString(16).padStart(2, '0')).join('')}')`,
    );
}

/**
 * A non-zero divisor literal for `/` and `%`. Always a fixed literal (never
 * a variable) so the resulting expression is well-defined regardless of the
 * random witness value drawn for the left-hand side at spend time — the
 * execution oracle (`runDifferentialExecution`, driven by
 * `arbArithmeticContract` / `arbStatelessContract`) synthesizes fresh
 * bigint witnesses per spend and cannot itself guarantee a variable operand
 * is non-zero.
 */
function arbNonZeroDivisorLiteral(): fc.Arbitrary<string> {
  return fc.integer({ min: 1, max: 20 }).chain((n) =>
    fc.constantFrom(`${n}n`, `${-n}n`),
  );
}

/**
 * Non-negative bounded shift count (0..16). OP_LSHIFT/OP_RSHIFT abort on a
 * negative shift, so the RHS of a generated shift is always a small
 * non-negative literal — the shift then reaches the execution oracle with a
 * defined result (interpreter and script share the byte-array shift semantics).
 */
function arbSmallShiftLiteral(): fc.Arbitrary<string> {
  return fc.integer({ min: 0, max: 16 }).map((n) => `${n}n`);
}

/**
 * Generate a random arithmetic expression using available bigint variables.
 */
function arbArithExpr(bigintVars: string[], depth: number): fc.Arbitrary<string> {
  if (depth <= 0 || bigintVars.length === 0) {
    return fc.oneof(
      arbBigintLiteral(),
      bigintVars.length > 0
        ? fc.constantFrom(...bigintVars)
        : arbBigintLiteral(),
    );
  }

  const leaf = arbArithExpr(bigintVars, 0);
  const binOps = ['+', '-', '*'] as const;

  return fc.oneof(
    leaf,
    fc
      .tuple(
        arbArithExpr(bigintVars, depth - 1),
        fc.constantFrom(...binOps),
        arbArithExpr(bigintVars, depth - 1),
      )
      .map(([l, op, r]) => `(${l} ${op} ${r})`),
    // Division / modulo — RHS is always a non-zero literal (see
    // arbNonZeroDivisorLiteral) so `/`/`%` reach the execution oracle with a
    // well-defined result instead of a div-by-zero reject on both engines.
    fc
      .tuple(
        arbArithExpr(bigintVars, depth - 1),
        fc.constantFrom('/' as const, '%' as const),
        arbNonZeroDivisorLiteral(),
      )
      .map(([l, op, r]) => `(${l} ${op} ${r})`),
    // Shifts (bounded non-negative literal count) and bitwise ops. These lower
    // to byte-array Script opcodes (OP_LSHIFT/OP_RSHIFT/OP_AND/OP_OR/OP_XOR);
    // the interpreter now models the same byte semantics, so they reach the
    // execution oracle in agreement — a length-mismatch `& | ^` aborts on BOTH
    // the interpreter and the script (audit #10 / the shift-bitwise fix).
    fc
      .tuple(
        arbArithExpr(bigintVars, depth - 1),
        fc.constantFrom('<<' as const, '>>' as const),
        arbSmallShiftLiteral(),
      )
      .map(([l, op, r]) => `(${l} ${op} ${r})`),
    fc
      .tuple(
        arbArithExpr(bigintVars, depth - 1),
        fc.constantFrom('&' as const, '|' as const, '^' as const),
        arbArithExpr(bigintVars, depth - 1),
      )
      .map(([l, op, r]) => `(${l} ${op} ${r})`),
    // Chained byte-ops: a shift RESULT (fixed-length, possibly NON-minimal on
    // chain — e.g. `2 << 8` leaves a 1-byte 0x00) feeding a length-sensitive
    // `& | ^`. This is the exact shape whose interpreter-vs-script divergence
    // audit #10 (chained byte-op length) fixed — the interpreter now threads the
    // real stack bytes so both engines agree (compute together, or abort together
    // on length mismatch). A dedicated arm keeps the execution-fuzz corpus
    // sampling this shape reliably; the generic oneof rarely nests a shift under
    // a bitwise at the small fixed-seed corpus the PR CI gate uses.
    fc
      .tuple(
        arbArithExpr(bigintVars, depth - 1),
        arbSmallShiftLiteral(),
        fc.constantFrom('&' as const, '|' as const, '^' as const),
        arbArithExpr(bigintVars, depth - 1),
      )
      .map(([l, k, op, r]) => `(((${l}) << ${k}) ${op} (${r}))`),
  );
}

/**
 * Generate a random boolean expression using available variables.
 */
function arbBoolExpr(
  bigintVars: string[],
  boolVars: string[],
  depth: number,
): fc.Arbitrary<string> {
  if (depth <= 0) {
    return fc.oneof(
      arbBoolLiteral(),
      boolVars.length > 0 ? fc.constantFrom(...boolVars) : arbBoolLiteral(),
    );
  }

  const comparisons = ['===', '!==', '<', '<=', '>', '>='] as const;
  const logicalOps = ['&&', '||'] as const;

  const comparisonExpr =
    bigintVars.length > 0
      ? fc
          .tuple(
            arbArithExpr(bigintVars, depth - 1),
            fc.constantFrom(...comparisons),
            arbArithExpr(bigintVars, depth - 1),
          )
          .map(([l, op, r]) => `(${l} ${op} ${r})`)
      : arbBoolLiteral();

  return fc.oneof(
    comparisonExpr,
    fc
      .tuple(
        arbBoolExpr(bigintVars, boolVars, depth - 1),
        fc.constantFrom(...logicalOps),
        arbBoolExpr(bigintVars, boolVars, depth - 1),
      )
      .map(([l, op, r]) => `(${l} ${op} ${r})`),
    arbBoolExpr(bigintVars, boolVars, depth - 1).map((e) => `!(${e})`),
  );
}

// ---------------------------------------------------------------------------
// Statement generators
// ---------------------------------------------------------------------------

function arbAssertStatement(
  bigintVars: string[],
  boolVars: string[],
): fc.Arbitrary<string> {
  return arbBoolExpr(bigintVars, boolVars, 2).map(
    (cond) => `    assert(${cond});`,
  );
}

function arbVarDeclStatement(
  bigintVars: string[],
): fc.Arbitrary<{ stmt: string; name: string; type: 'bigint' }> {
  return fc.tuple(arbLocalName, arbArithExpr(bigintVars, 2)).map(([name, expr]) => ({
    stmt: `    let ${name}: bigint = ${expr};`,
    name,
    type: 'bigint' as const,
  }));
}

function arbIfStatement(
  bigintVars: string[],
  boolVars: string[],
): fc.Arbitrary<string> {
  return fc
    .tuple(
      arbBoolExpr(bigintVars, boolVars, 1),
      arbAssertStatement(bigintVars, boolVars),
    )
    .map(
      ([cond, body]) =>
        `    if (${cond}) {\n  ${body}\n    }`,
    );
}

// ---------------------------------------------------------------------------
// Method body generator
// ---------------------------------------------------------------------------

function arbMethodBody(
  properties: PropertyDef[],
  params: ParamDef[],
): fc.Arbitrary<string> {
  // Collect available variable names by type.
  const bigintVars = [
    ...properties.filter((p) => p.type === 'bigint').map((p) => `this.${p.name}`),
    ...params.filter((p) => p.type === 'bigint').map((p) => p.name),
  ];
  const boolVars = [
    ...properties.filter((p) => p.type === 'boolean').map((p) => `this.${p.name}`),
    ...params.filter((p) => p.type === 'boolean').map((p) => p.name),
  ];

  return fc
    .tuple(
      // 0-2 variable declarations
      fc.array(arbVarDeclStatement(bigintVars), { minLength: 0, maxLength: 2 }),
      // 0-1 if statements
      fc.array(arbIfStatement(bigintVars, boolVars), { minLength: 0, maxLength: 1 }),
      // 1-2 assert statements (method must end with assert)
      fc.array(arbAssertStatement(bigintVars, boolVars), {
        minLength: 1,
        maxLength: 2,
      }),
    )
    .map(([decls, ifs, asserts]) => {
      const allBigintVars = [
        ...bigintVars,
        ...decls.map((d) => d.name),
      ];
      // Build body with all available vars for the final asserts.
      const lines: string[] = [];
      for (const d of decls) {
        lines.push(d.stmt);
      }
      for (const ifStmt of ifs) {
        lines.push(ifStmt);
      }
      for (const a of asserts) {
        lines.push(a);
      }
      void allBigintVars; // used above transitively
      return lines.join('\n');
    });
}

// ---------------------------------------------------------------------------
// Contract generator
// ---------------------------------------------------------------------------

function arbMethod(
  properties: PropertyDef[],
): fc.Arbitrary<string> {
  return fc
    .tuple(
      arbMethodName,
      // 0-3 parameters (bigint or boolean only for simplicity)
      fc.array(
        fc.tuple(arbParamName, fc.constantFrom('bigint' as const, 'boolean' as const)),
        { minLength: 0, maxLength: 3 },
      ),
    )
    .chain(([name, paramDefs]) => {
      // Deduplicate parameter names.
      const seen = new Set<string>();
      const uniqueParams: ParamDef[] = [];
      for (const [pName, pType] of paramDefs) {
        const uniqueName = seen.has(pName) ? `${pName}_` : pName;
        seen.add(uniqueName);
        uniqueParams.push({ name: uniqueName, type: pType });
      }

      const paramStr = uniqueParams
        .map((p) => `${p.name}: ${p.type}`)
        .join(', ');

      return arbMethodBody(properties, uniqueParams).map(
        (body) =>
          `  public ${name}(${paramStr}) {\n${body}\n  }`,
      );
    });
}

function arbPropertyDefs(): fc.Arbitrary<PropertyDef[]> {
  return fc
    .array(fc.tuple(arbPropertyName, arbPropertyType), {
      minLength: 1,
      maxLength: 3,
    })
    .map((defs) => {
      // Deduplicate property names.
      const seen = new Set<string>();
      const result: PropertyDef[] = [];
      for (const [name, type] of defs) {
        const uniqueName = seen.has(name) ? `${name}_` : name;
        seen.add(uniqueName);
        result.push({ name: uniqueName, type });
      }
      return result;
    });
}

function arbConstructor(properties: PropertyDef[]): string {
  const params = properties.map((p) => `${p.name}: ${p.type}`).join(', ');
  const superArgs = properties.map((p) => p.name).join(', ');
  const assignments = properties
    .map((p) => `    this.${p.name} = ${p.name};`)
    .join('\n');
  return `  constructor(${params}) {\n    super(${superArgs});\n${assignments}\n  }`;
}

function generateContractSource(
  contractName: string,
  properties: PropertyDef[],
  methods: string[],
): string {
  const propDecls = properties
    .map((p) => `  readonly ${p.name}: ${p.type};`)
    .join('\n');

  const ctor = arbConstructor(properties);

  const imports = [
    `import { SmartContract, assert } from 'runar-lang';`,
  ];

  // Add type imports if needed.
  const usedTypes = new Set(properties.map((p) => p.type));
  const typeImports: string[] = [];
  if (usedTypes.has('ByteString')) typeImports.push('ByteString', 'toByteString');
  if (usedTypes.has('PubKey')) typeImports.push('PubKey');
  if (usedTypes.has('Sig')) typeImports.push('Sig');
  if (typeImports.length > 0) {
    imports.push(
      `import { ${typeImports.join(', ')} } from 'runar-lang';`,
    );
  }

  return `${imports.join('\n')}

export class ${contractName} extends SmartContract {
${propDecls}

${ctor}

${methods.join('\n\n')}
}
`;
}

// ---------------------------------------------------------------------------
// Public arbitraries
// ---------------------------------------------------------------------------

/**
 * Generate a random valid Rúnar contract source string.
 */
export const arbContract: fc.Arbitrary<string> = fc
  .tuple(arbContractName, arbPropertyDefs())
  .chain(([name, props]) =>
    fc
      .tuple(
        fc.constant(name),
        fc.constant(props),
        fc.array(arbMethod(props), { minLength: 1, maxLength: 3 }),
      )
      .map(([contractName, properties, methods]) =>
        generateContractSource(contractName, properties, methods),
      ),
  );

/**
 * Generate contracts with no properties (stateless).
 * Methods use only their parameters.
 */
export const arbStatelessContract: fc.Arbitrary<string> = fc
  .tuple(
    arbContractName,
    fc.array(
      fc
        .tuple(
          arbMethodName,
          fc.array(
            fc.tuple(arbParamName, fc.constant('bigint' as PropertyType)),
            { minLength: 1, maxLength: 3 },
          ),
        )
        .chain(([name, paramDefs]) => {
          const seen = new Set<string>();
          const uniqueParams: ParamDef[] = [];
          for (const [pName, pType] of paramDefs) {
            const uniqueName = seen.has(pName) ? `${pName}_` : pName;
            seen.add(uniqueName);
            uniqueParams.push({ name: uniqueName, type: pType });
          }
          const bigintVars = uniqueParams.map((p) => p.name);
          const paramStr = uniqueParams
            .map((p) => `${p.name}: ${p.type}`)
            .join(', ');
          return arbAssertStatement(bigintVars, []).map(
            (body) =>
              `  public ${name}(${paramStr}) {\n${body}\n  }`,
          );
        }),
      { minLength: 1, maxLength: 2 },
    ),
  )
  .map(([contractName, methods]) => {
    return `import { SmartContract, assert } from 'runar-lang';

export class ${contractName} extends SmartContract {
  constructor() { super(); }

${methods.join('\n\n')}
}
`;
  });

/**
 * Generate contracts focused on arithmetic operations.
 */
export const arbArithmeticContract: fc.Arbitrary<string> = fc
  .tuple(
    arbContractName,
    // 1-3 bigint properties
    fc.array(arbPropertyName, { minLength: 1, maxLength: 3 }).map((names) => {
      const seen = new Set<string>();
      return names.map((n) => {
        const unique = seen.has(n) ? `${n}_` : n;
        seen.add(unique);
        return { name: unique, type: 'bigint' as PropertyType };
      });
    }),
  )
  .chain(([contractName, properties]) =>
    fc
      .array(
        fc
          .tuple(
            arbMethodName,
            fc.array(
              fc.tuple(arbParamName, fc.constant('bigint' as PropertyType)),
              { minLength: 1, maxLength: 3 },
            ),
          )
          .chain(([name, paramDefs]) => {
            const seen = new Set<string>();
            const uniqueParams: ParamDef[] = [];
            for (const [pName, pType] of paramDefs) {
              const uniqueName = seen.has(pName) ? `${pName}_` : pName;
              seen.add(uniqueName);
              uniqueParams.push({ name: uniqueName, type: pType });
            }
            const bigintVars = [
              ...properties.map((p) => `this.${p.name}`),
              ...uniqueParams.map((p) => p.name),
            ];
            const paramStr = uniqueParams
              .map((p) => `${p.name}: ${p.type}`)
              .join(', ');
            return fc
              .tuple(
                arbArithExpr(bigintVars, 3),
                arbArithExpr(bigintVars, 3),
              )
              .map(
                ([lhs, rhs]) =>
                  `  public ${name}(${paramStr}) {\n    assert(${lhs} === ${rhs});\n  }`,
              );
          }),
        { minLength: 1, maxLength: 3 },
      )
      .map((methods) =>
        generateContractSource(contractName, properties, methods),
      ),
  );

/**
 * Generate contracts focused on cryptographic operations.
 */
export const arbCryptoContract: fc.Arbitrary<string> = fc
  .tuple(
    arbContractName,
    fc.array(arbPropertyName, { minLength: 1, maxLength: 2 }).map((names) => {
      const seen = new Set<string>();
      return names.map((n) => {
        const unique = seen.has(n) ? `${n}_` : n;
        seen.add(unique);
        return { name: unique, type: 'PubKey' as PropertyType };
      });
    }),
  )
  .chain(([contractName, properties]) =>
    fc
      .array(
        arbMethodName.map(
          (name) =>
            `  public ${name}(sig: Sig, msg: ByteString) {\n` +
            `    assert(checkSig(sig, this.${properties[0]!.name}));\n` +
            `    assert(sha256(msg) !== toByteString('${'00'.repeat(32)}'));\n` +
            `  }`,
        ),
        { minLength: 1, maxLength: 2 },
      )
      .map((methods) => {
        const propDecls = properties
          .map((p) => `  readonly ${p.name}: ${p.type};`)
          .join('\n');
        const ctorParams = properties.map((p) => `${p.name}: ${p.type}`).join(', ');
        const ctorBody = properties
          .map((p) => `    this.${p.name} = ${p.name};`)
          .join('\n');

        return `import { SmartContract, assert, checkSig, sha256 } from 'runar-lang';
import { PubKey, Sig, ByteString, toByteString } from 'runar-lang';

export class ${contractName} extends SmartContract {
${propDecls}

  constructor(${ctorParams}) {
    super(${properties.map((p) => p.name).join(', ')});
${ctorBody}
  }

${methods.join('\n\n')}
}
`;
      }),
  );

// ===========================================================================
// IR-based generators (language-neutral)
// ===========================================================================

/**
 * Configuration for the IR-based contract generator.
 */
export interface GeneratorConfig {
  maxProperties: number;
  maxExprDepth: number;
  maxMethods: number;
  maxStatements: number;
  maxParams: number;
}

const DEFAULT_CONFIG: GeneratorConfig = {
  maxProperties: 3,
  maxExprDepth: 3,
  maxMethods: 3,
  maxStatements: 4,
  maxParams: 3,
};

// ---------------------------------------------------------------------------
// IR type generator
// ---------------------------------------------------------------------------

export const arbRuinarType: fc.Arbitrary<RuinarType> = fc.oneof(
  { weight: 5, arbitrary: fc.constant('bigint' as RuinarType) },
  { weight: 3, arbitrary: fc.constant('boolean' as RuinarType) },
  { weight: 1, arbitrary: fc.constant('ByteString' as RuinarType) },
  { weight: 1, arbitrary: fc.constant('PubKey' as RuinarType) },
);

// ---------------------------------------------------------------------------
// IR expression generators
// ---------------------------------------------------------------------------

function arbBigintLiteralIR(): fc.Arbitrary<Expr> {
  return fc.bigInt({ min: -100n, max: 100n }).map(
    (v): Expr => ({ kind: 'bigint_literal', value: v }),
  );
}

function arbBoolLiteralIR(): fc.Arbitrary<Expr> {
  return fc.boolean().map(
    (v): Expr => ({ kind: 'bool_literal', value: v }),
  );
}

export function arbByteStringLiteralIR(): fc.Arbitrary<Expr> {
  return fc
    .array(fc.integer({ min: 0, max: 255 }), { minLength: 0, maxLength: 4 })
    .map((bytes): Expr => ({
      kind: 'bytestring_literal',
      hex: bytes.map((b) => b.toString(16).padStart(2, '0')).join(''),
    }));
}

/**
 * A non-zero divisor literal for `/` and `%` (IR form). See
 * `arbNonZeroDivisorLiteral` above — same rationale: `arbGeneratedContract`
 * feeds `execute-differential.ts`'s witness-driven execution oracle, so the
 * divisor must be fixed at generation time, not left to a runtime witness.
 */
function arbNonZeroDivisorLiteralIR(): fc.Arbitrary<Expr> {
  return fc.integer({ min: 1, max: 20 }).chain((n) =>
    fc.constantFrom<Expr>(
      { kind: 'bigint_literal', value: BigInt(n) },
      { kind: 'bigint_literal', value: BigInt(-n) },
    ),
  );
}

/**
 * Non-negative bounded shift count (0..16), IR form. Mirrors
 * `arbSmallShiftLiteral` above: OP_LSHIFT/OP_RSHIFT abort on a negative
 * shift, so the RHS of a generated shift is always a small non-negative
 * literal — the shift then reaches the execution oracle with a defined
 * result.
 */
function arbSmallShiftLiteralIR(): fc.Arbitrary<Expr> {
  return fc.integer({ min: 0, max: 16 }).map(
    (n): Expr => ({ kind: 'bigint_literal', value: BigInt(n) }),
  );
}

/**
 * Exponent literal for `pow`, straddling the ENFORCED domain (R-169).
 *
 * `pow` unrolls 32 conditional multiplies, so it computes `base^min(exp, 32)`
 * and the emitted script refuses anything outside `0 <= exp <= 32` with
 * `OP_DUP <0> <33> OP_WITHIN OP_VERIFY`. The constant folder declines outside
 * the same bound and the interpreter throws there, so the oracle sees the
 * script and the interpreter REFUSE TOGETHER — which is the property worth
 * fuzzing, and the one that was never checked.
 *
 * The range deliberately covers both sides of the guard rather than staying
 * inside it. Confining a corpus to the easy half is exactly how `pow`'s clamp
 * survived three review rounds: there was no `pow` in any fixture past its
 * bound, the fuzzer never generated `pow` AT ALL, and the single `pow` in any
 * test in the repo sat at `exp = 10n`.
 */
function arbPowExponentLiteralIR(): fc.Arbitrary<Expr> {
  return fc.integer({ min: -2, max: 40 }).map(
    (n): Expr => ({ kind: 'bigint_literal', value: BigInt(n) }),
  );
}

/**
 * Multi-byte-magnitude literal, used ONLY inside the shift/bitwise arms of
 * `arbBigintExprIR` below (C6 / deep-review finding). `arbBigintLiteralIR`'s
 * [-100, 100] range never needs more than one Bitcoin script-number byte, so
 * a corpus built only from that range could never re-catch a #141-shaped
 * regression: #141 was a byte-array-truncation bug (OP_LSHIFT/OP_RSHIFT/
 * OP_AND/OP_OR/OP_XOR operate on the operands' raw script-number bytes, not
 * their numeric value) that only manifests once an operand's minimal
 * script-number encoding needs a second byte (e.g. 255 needs one — the sign
 * bit doesn't fit in a single byte). 70000 stays inside the magnitude already
 * regression-tested against the real VM (see
 * `packages/runar-testing/src/__tests__/script-number-bitwise.test.ts`,
 * which fuzzes |value| < 70000 against ScriptVM) while reliably producing
 * 2-3 byte operands.
 */
function arbWideBigintLiteralIR(): fc.Arbitrary<Expr> {
  return fc.bigInt({ min: -70000n, max: 70000n }).map(
    (v): Expr => ({ kind: 'bigint_literal', value: v }),
  );
}

/** Generate a bigint-typed expression using available vars. */
function arbBigintExprIR(
  bigintVars: string[],
  depth: number,
): fc.Arbitrary<Expr> {
  if (depth <= 0) {
    const options: fc.Arbitrary<Expr>[] = [arbBigintLiteralIR()];
    if (bigintVars.length > 0) {
      options.push(fc.constantFrom(...bigintVars).map(
        (name): Expr => name.startsWith('this.')
          ? { kind: 'property_ref', name: name.slice(5) }
          : { kind: 'var_ref', name },
      ));
    }
    return fc.oneof(...options);
  }

  const leaf = arbBigintExprIR(bigintVars, 0);
  const ops: Array<'+' | '-' | '*'> = ['+', '-', '*'];

  return fc.oneof(
    leaf,
    // Binary arithmetic
    fc.tuple(
      arbBigintExprIR(bigintVars, depth - 1),
      fc.constantFrom(...ops),
      arbBigintExprIR(bigintVars, depth - 1),
    ).map(([left, op, right]): Expr => ({ kind: 'binary', op, left, right })),
    // Division / modulo — RHS restricted to a non-zero literal (see
    // arbNonZeroDivisorLiteralIR) so OP_DIV/OP_MOD reach the execution
    // oracle with a well-defined result on every synthesized witness.
    fc.tuple(
      arbBigintExprIR(bigintVars, depth - 1),
      fc.constantFrom('/' as const, '%' as const),
      arbNonZeroDivisorLiteralIR(),
    ).map(([left, op, right]): Expr => ({ kind: 'binary', op, left, right })),
    // Math builtins
    fc.tuple(
      fc.constantFrom('abs'),
      arbBigintExprIR(bigintVars, depth - 1),
    ).map(([fn, arg]): Expr => ({ kind: 'call', fn, args: [arg] })),
    fc.tuple(
      fc.constantFrom('min', 'max'),
      arbBigintExprIR(bigintVars, depth - 1),
      arbBigintExprIR(bigintVars, depth - 1),
    ).map(([fn, a, b]): Expr => ({ kind: 'call', fn, args: [a, b] })),
    // pow(base, <literal exponent>) — R-169. The exponent is fixed at
    // generation time (like the divisor and shift-count arms) so the execution
    // oracle sees a decided result, and it straddles the 0..32 guard so the
    // corpus exercises the REFUSAL as well as the computation. The base is a
    // depth-0 leaf on purpose: a nested `pow(pow(x, 32), 32)` would ask the
    // script for a 10^3000 script number and the arm would be testing the
    // bignum encoder rather than pow.
    fc.tuple(
      arbBigintExprIR(bigintVars, 0),
      arbPowExponentLiteralIR(),
    ).map(([base, exp]): Expr => ({ kind: 'call', fn: 'pow', args: [base, exp] })),
    // Shifts (bounded non-negative literal count) and bitwise ops (C6 —
    // these lower to byte-array Script opcodes OP_LSHIFT/OP_RSHIFT/OP_AND/
    // OP_OR/OP_XOR; the interpreter models the same byte semantics since
    // #141, so they reach the execution oracle in agreement — a
    // length-mismatch `& | ^` aborts on BOTH the interpreter and the script).
    // `arbWideBigintLiteralIR` keeps at least one operand able to cross the
    // single-byte scriptnum boundary instead of confining the corpus to
    // `arbBigintLiteralIR`'s [-100, 100] range.
    fc.tuple(
      fc.oneof(arbBigintExprIR(bigintVars, depth - 1), arbWideBigintLiteralIR()),
      fc.constantFrom('<<' as const, '>>' as const),
      arbSmallShiftLiteralIR(),
    ).map(([left, op, right]): Expr => ({ kind: 'binary', op, left, right })),
    fc.tuple(
      fc.oneof(arbBigintExprIR(bigintVars, depth - 1), arbWideBigintLiteralIR()),
      fc.constantFrom('&' as const, '|' as const, '^' as const),
      fc.oneof(arbBigintExprIR(bigintVars, depth - 1), arbWideBigintLiteralIR()),
    ).map(([left, op, right]): Expr => ({ kind: 'binary', op, left, right })),
    // Chained byte-op: a shift RESULT (fixed-length, possibly NON-minimal on
    // chain — e.g. `2 << 8` leaves a 1-byte 0x00) feeding a length-sensitive
    // `& | ^`. This is the exact shape #141's fix (chained byte-op length)
    // targets — a dedicated arm keeps the corpus sampling it reliably rather
    // than relying on the generic oneof to nest a shift under a bitwise op.
    fc.tuple(
      fc.oneof(arbBigintExprIR(bigintVars, depth - 1), arbWideBigintLiteralIR()),
      arbSmallShiftLiteralIR(),
      fc.constantFrom('&' as const, '|' as const, '^' as const),
      fc.oneof(arbBigintExprIR(bigintVars, depth - 1), arbWideBigintLiteralIR()),
    ).map(([l, k, op, r]): Expr => ({
      kind: 'binary',
      op,
      left: { kind: 'binary', op: '<<', left: l, right: k },
      right: r,
    })),
  );
}

/** Generate a boolean-typed expression. */
function arbBoolExprIR(
  bigintVars: string[],
  boolVars: string[],
  depth: number,
): fc.Arbitrary<Expr> {
  if (depth <= 0) {
    const options: fc.Arbitrary<Expr>[] = [arbBoolLiteralIR()];
    if (boolVars.length > 0) {
      options.push(fc.constantFrom(...boolVars).map(
        (name): Expr => name.startsWith('this.')
          ? { kind: 'property_ref', name: name.slice(5) }
          : { kind: 'var_ref', name },
      ));
    }
    return fc.oneof(...options);
  }

  const comparisons: Array<'===' | '!==' | '<' | '>' | '<=' | '>='> =
    ['===', '!==', '<', '>', '<=', '>='];

  return fc.oneof(
    // Comparison
    bigintVars.length > 0
      ? fc.tuple(
          arbBigintExprIR(bigintVars, depth - 1),
          fc.constantFrom(...comparisons),
          arbBigintExprIR(bigintVars, depth - 1),
        ).map(([left, op, right]): Expr => ({ kind: 'binary', op, left, right }))
      : arbBoolLiteralIR(),
    // Logical
    fc.tuple(
      arbBoolExprIR(bigintVars, boolVars, depth - 1),
      fc.constantFrom('&&' as const, '||' as const),
      arbBoolExprIR(bigintVars, boolVars, depth - 1),
    ).map(([left, op, right]): Expr => ({ kind: 'binary', op, left, right })),
    // Negation
    arbBoolExprIR(bigintVars, boolVars, depth - 1).map(
      (operand): Expr => ({ kind: 'unary', op: '!', operand }),
    ),
  );
}

// ---------------------------------------------------------------------------
// IR statement generators
// ---------------------------------------------------------------------------

function arbAssertStmtIR(
  bigintVars: string[],
  boolVars: string[],
): fc.Arbitrary<Stmt> {
  return arbBoolExprIR(bigintVars, boolVars, 2).map(
    (condition): Stmt => ({ kind: 'assert', condition }),
  );
}

function arbVarDeclStmtIR(
  bigintVars: string[],
): fc.Arbitrary<{ stmt: Stmt; name: string; type: RuinarType }> {
  return fc.tuple(
    fc.integer({ min: 0, max: 99 }).map((n) => `local${n}`),
    arbBigintExprIR(bigintVars, 2),
  ).map(([name, value]) => ({
    stmt: { kind: 'var_decl' as const, name, type: 'bigint' as const, value, mutable: false },
    name,
    type: 'bigint' as RuinarType,
  }));
}

// ---------------------------------------------------------------------------
// Branch SHAPES (the 2026-08 branch-merged-locals blind spot)
// ---------------------------------------------------------------------------

/**
 * WHY THESE EXIST
 * ---------------
 * Until 2026-08 `arbIfStmtIR` could emit exactly ONE branch shape: `then` and
 * `else_` were each a single statement drawn from `arbAssertStmtIR`. A branch
 * arm that REASSIGNS anything was not merely unlikely, it was OUTSIDE THE
 * REACHABLE SPACE of `arbGeneratedContract` — and so was every local
 * reassignment anywhere in it, because `arbVarDeclStmtIR` hard-coded
 * `mutable: false` and no other statement generator emitted an `assign` with
 * `isProperty: false`.
 *
 * That is exactly the shape of the confirmed branch-merged-local miscompile
 * (PALMER-1, `conformance/tests/branch-merged-locals/`): two locals seeded
 * from state, the arms of an `if` rebinding DIFFERENT ones, both read after
 * the branch. It compiled cleanly, passed the ANF-interpreter tests, and was
 * rejected by the real Script interpreter — a permanently unspendable contract
 * from idiomatic source. The generator that drives BOTH the 7-tier `--ir`
 * parity fuzzer and the `--execute` absolute oracle could never have produced
 * it, at any seed or budget.
 *
 * The family below is the fix for the SPACE. `assert-only` is the historical
 * shape, kept verbatim so no existing coverage is lost; every other member
 * declares its carriers as MUTABLE locals before the branch and ends with an
 * assert that READS every carrier, so a mis-resolved post-branch reference
 * changes the spend verdict instead of being dead.
 */
export type BranchShape =
  /** Historical shape: both arms are a single `assert`, nothing is rebound. */
  | 'assert-only'
  /** No branch at all: a mutable local rebound in STRAIGHT-LINE code, then
   *  read. Before 2026-08 the only `assign` with `isProperty: false` in the
   *  whole IR generator lived inside the exec-oracle's loop bodies. */
  | 'straight-line-rebind'
  /** One arm (no `else`) rebinds ONE local, which is read after the branch. */
  | 'rebind-read-after'
  /** BOTH arms rebind the SAME single local, which is read after the branch —
   *  the k=1 merge. `both-arms-rebind-both` is its k=2 sibling; the pair is
   *  what tells a k-sensitive merge bug apart from a general one, and that
   *  distinction has already paid: forcing this shape on 2026-08-06 found the
   *  k=1 branch-merge defect the 2026-08-05 k>=2 fix had not covered (see
   *  `packages/runar-testing/src/__tests__/fuzzer-branch-shapes.test.ts`). */
  | 'both-arms-rebind-one'
  /** One arm rebinds >= 2 locals; the other only asserts. */
  | 'multi-rebind-one-arm'
  /** The PALMER-1 shape: `then` rebinds `merge0`, `else` rebinds `merge1`. */
  | 'asymmetric-rebind'
  /** Both arms rebind BOTH locals — the balanced control for the above. */
  | 'both-arms-rebind-both'
  /**
   * The issue-#149 shape: an inner `if` that merges `merge0` in BOTH arms,
   * nested inside an outer `if` with NO `else`, with `merge1` left LIVE and
   * UNTOUCHED beside it.
   *
   * Every other member of this family has ONE `if`. Measured on the pre-#149
   * generator, `arbGeneratedContract` reached a maximum `if`-nesting depth of 1
   * over 3000 samples — it never nested, so `--execute` (which draws its whole
   * corpus from here) was structurally blind to the defect while `--tri-modal`
   * and `--spend-oracle` had both been extended to reach it.
   *
   * TWO degrees of freedom are required TOGETHER, which is why no combination
   * of the single-`if` shapes above can stand in for it:
   *
   *  1. the inner `if` rebinds only a PREFIX of the carriers (`merge0`), so
   *     `merge1` stays live and untouched in the slot region the outer arm
   *     INHERITED from the parent — the slots an adopted result has to cross.
   *     When every local is a declared result there is no inherited slot left
   *     to rotate past and the adopt-then-remove sequence disturbs no layout;
   *  2. the OUTER `if` has NO `else`, so only ONE outer path rearranges that
   *     region: the two paths leave equal DEPTH with different LAYOUT, which is
   *     invisible to both the reconcile's name-set check and Layer C's depth
   *     check. With an outer `else` both paths get rearranged and every
   *     post-`OP_ENDIF` read resolves the same way on either.
   *
   * The inner `if` keeps a real `else` on purpose: the confirmed #149 inner
   * `if` had one, and the repair must not be gated on its absence.
   *
   * MEASURED, not asserted. Against the compiler with the `sinkBelow` repair in
   * `lowerIf` (`packages/runar-compiler/src/passes/05-stack-lower.ts`)
   * temporarily reverted, `--execute --num 1000` reports, per seed:
   *
   *      seed        WITHOUT this shape      WITH this shape
   *      424242       0 / 11874 spends       11 / 11874 spends
   *      20260817     0 / 11862 spends       14 / 11862 spends
   *      909090       0 / 11712 spends       17 / 11712 spends
   *
   * and 0 on all three once the repair is restored. The left column is the gap
   * this shape closes: the harness was not merely unlucky, the layout was
   * OUTSIDE its reachable space. Note the rate — roughly 1 divergence per 1000
   * contracts, because a divergence is only visible when the interpreter
   * accepts the whole method (~7% of spends) — so a gate run at `--num 60`
   * will NOT see a #149 regression even now.
   *
   * See `conformance/fuzzer/spend-shapes.ts` (`nested-sibling`) for the same
   * two degrees of freedom in the Spend-oracle corpus, and
   * `packages/runar-testing/src/__tests__/branch-inherited-layout-directions-vm.test.ts`
   * for the hand-reduced witnesses in both directions.
   */
  | 'nested-sibling-no-else'
  /** A PROPERTY write inside an arm (stateful contracts only). */
  | 'prop-write-in-arm';

/** Branch shapes reachable in a stateless `SmartContract` (no property writes:
 *  every property is readonly there). */
export const BRANCH_SHAPES: readonly BranchShape[] = [
  'assert-only',
  'straight-line-rebind',
  'rebind-read-after',
  'both-arms-rebind-one',
  'multi-rebind-one-arm',
  'asymmetric-rebind',
  'both-arms-rebind-both',
  'nested-sibling-no-else',
];

/** Branch shapes reachable in a `StatefulSmartContract` — the stateless set
 *  plus the conditional property write (`conformance/tests/cond-write-multi-field`). */
export const STATEFUL_BRANCH_SHAPES: readonly BranchShape[] = [
  ...BRANCH_SHAPES,
  'prop-write-in-arm',
];

/** The merged locals, named so the reachability test can re-derive the shape
 *  from the IR without trusting a label. */
const MERGE_LOCALS = ['merge0', 'merge1'] as const;

/** Mutable locals a branch shape declares BEFORE its branch, in order. */
export function branchShapeCarriers(shape: BranchShape): string[] {
  switch (shape) {
    case 'assert-only':
      return [];
    case 'straight-line-rebind':
    case 'rebind-read-after':
    case 'both-arms-rebind-one':
    case 'prop-write-in-arm':
      return [MERGE_LOCALS[0]];
    case 'multi-rebind-one-arm':
    case 'asymmetric-rebind':
    case 'both-arms-rebind-both':
    // `merge0` is the inner `if`'s declared result; `merge1` is the live
    // untouched sibling it has to rotate past. Both are declared before the
    // outer branch, in this order — `merge0` deeper, which is what puts an
    // inherited slot between the adopted result and its stale pre-`if` copy.
    case 'nested-sibling-no-else':
      return [...MERGE_LOCALS];
  }
}

/** `target = <bigint expr>` over a local. */
function arbLocalRebind(target: string, bigintVars: string[]): fc.Arbitrary<Stmt> {
  return arbBigintExprIR(bigintVars, 1).map((value): Stmt => ({
    kind: 'assign',
    target,
    value,
    isProperty: false,
  }));
}

/**
 * A terminal assert that READS every carrier. Without it a rebound local is
 * dead after the branch, so a post-branch reference resolved to the wrong slot
 * would not change any engine's verdict and no oracle downstream could see it.
 */
function arbCarrierReadClause(
  carriers: string[],
  bigintVars: string[],
): fc.Arbitrary<Stmt> {
  return fc
    .tuple(
      ...carriers.map((c) =>
        fc
          .tuple(
            fc.constantFrom('===' as const, '!==' as const, '<' as const, '>' as const,
              '<=' as const, '>=' as const),
            arbBigintExprIR(bigintVars, 1),
          )
          .map(([op, right]): Expr => ({
            kind: 'binary',
            op,
            left: { kind: 'var_ref', name: c },
            right,
          })),
      ),
    )
    .map((clauses): Stmt => ({
      kind: 'assert',
      condition: (clauses as Expr[]).reduce((left, right): Expr => ({
        kind: 'binary',
        op: '&&',
        left,
        right,
      })),
    }));
}

/**
 * The ORDER-SENSITIVE post-branch read for `nested-sibling-no-else`:
 * `merged <relop> sibling`, with `relop` drawn from the four RELATIONAL
 * operators only.
 *
 * `===` / `!==` are deliberately excluded: they are symmetric in their
 * operands, so a script that read the two slots CROSSED reports the same
 * verdict as one that read them correctly, and every downstream oracle agrees
 * on bytes that resolved the wrong stack positions. That is not hypothetical —
 * it was measured directly on the tri-modal generator, whose commutative read
 * clause reported agreement on a rotated layout. A relational read flips
 * whenever the two values differ, which is the whole point of the shape.
 */
function arbSiblingReadClause(
  merged: string,
  sibling: string,
): fc.Arbitrary<Stmt> {
  return fc
    .constantFrom('<' as const, '>' as const, '<=' as const, '>=' as const)
    .map((op): Stmt => ({
      kind: 'assert',
      condition: {
        kind: 'binary',
        op,
        left: { kind: 'var_ref', name: merged },
        right: { kind: 'var_ref', name: sibling },
      },
    }));
}

/**
 * A branch block of the requested shape: carrier declarations, the branch (or
 * straight-line rebind), and the carrier read. `mutableProps` is the list of
 * writable bigint property names — empty for a stateless contract, which is
 * why `prop-write-in-arm` is stateful-only.
 */
function arbBranchBlockIR(
  shape: BranchShape,
  bigintVars: string[],
  boolVars: string[],
  mutableProps: string[],
): fc.Arbitrary<Stmt[]> {
  if (shape === 'assert-only') {
    // Byte-for-byte the pre-2026-08 shape, so the historical corpus stays
    // reachable rather than being replaced by the widened family.
    return fc
      .tuple(
        arbBoolExprIR(bigintVars, boolVars, 1),
        arbAssertStmtIR(bigintVars, boolVars),
        fc.option(arbAssertStmtIR(bigintVars, boolVars)),
      )
      .map(([condition, thenStmt, elseStmt]): Stmt[] => [
        {
          kind: 'if',
          condition,
          then: [thenStmt],
          else_: elseStmt ? [elseStmt] : undefined,
        },
      ]);
  }

  const carriers = branchShapeCarriers(shape);
  // The carriers are in scope for the rebind expressions and the read clause,
  // so an arm can read the other merged local as well as write its own.
  const inner = [...carriers, ...bigintVars];

  if (shape === 'nested-sibling-no-else') {
    // Drawn on its own so the other shapes' draw sequences are untouched: this
    // is the only member that needs TWO conditions (outer and inner) and a
    // dedicated read clause, and folding those into the shared tuple below
    // would reshuffle the whole fixed-seed corpus for no gain.
    const [merged, sibling] = carriers as [string, string];
    return fc
      .tuple(
        fc.tuple(arbBigintExprIR(bigintVars, 1), arbBigintExprIR(bigintVars, 1)),
        arbBoolExprIR(bigintVars, boolVars, 1),
        arbBoolExprIR(bigintVars, boolVars, 1),
        arbLocalRebind(merged, inner),
        arbLocalRebind(merged, inner),
        arbSiblingReadClause(merged, sibling),
      )
      .map(([inits, outerCond, innerCond, thenRebind, elseRebind, readClause]): Stmt[] => {
        const decls: Stmt[] = carriers.map((name, i) => ({
          kind: 'var_decl',
          name,
          type: 'bigint',
          value: inits[i]!,
          mutable: true,
        }));
        return [
          ...decls,
          {
            kind: 'if',
            condition: outerCond,
            // NO else on the outer `if` — degree of freedom (2).
            then: [
              {
                kind: 'if',
                condition: innerCond,
                // Only `merged` is rebound, so `sibling` stays live and
                // untouched in the inherited region — degree of freedom (1).
                then: [thenRebind],
                else_: [elseRebind],
              },
            ],
            else_: undefined,
          },
          readClause,
        ];
      });
  }

  return fc
    .tuple(
      // Carrier initialisers.
      fc.tuple(...carriers.map(() => arbBigintExprIR(bigintVars, 1))),
      arbBoolExprIR(bigintVars, boolVars, 1),
      // Enough rebinds for the widest shape (both arms rebind both locals).
      fc.tuple(
        arbLocalRebind(carriers[0]!, inner),
        arbLocalRebind(carriers[carriers.length - 1]!, inner),
        arbLocalRebind(carriers[0]!, inner),
        arbLocalRebind(carriers[carriers.length - 1]!, inner),
      ),
      arbAssertStmtIR(inner, boolVars),
      mutableProps.length > 0
        ? fc
            .tuple(fc.constantFrom(...mutableProps), arbBigintExprIR(inner, 1))
            .map(([target, value]): Stmt => ({
              kind: 'assign',
              target,
              value,
              isProperty: true,
            }))
        : fc.constant<Stmt | null>(null),
      arbCarrierReadClause(carriers, inner),
    )
    .map(([inits, condition, rebinds, elseAssert, propWrite, readClause]): Stmt[] => {
      const decls: Stmt[] = carriers.map((name, i) => ({
        kind: 'var_decl',
        name,
        type: 'bigint',
        value: inits[i]!,
        mutable: true,
      }));
      const [r0, r1, r2, r3] = rebinds;
      let branch: Stmt;
      switch (shape) {
        case 'straight-line-rebind':
          // No branch at all — the straight-line local reassignment that had
          // no representation anywhere in this generator.
          return [...decls, r0, readClause];
        case 'rebind-read-after':
          branch = { kind: 'if', condition, then: [r0], else_: undefined };
          break;
        case 'both-arms-rebind-one':
          branch = { kind: 'if', condition, then: [r0], else_: [r1] };
          break;
        case 'multi-rebind-one-arm':
          branch = { kind: 'if', condition, then: [r0, r1], else_: [elseAssert] };
          break;
        case 'asymmetric-rebind':
          branch = { kind: 'if', condition, then: [r0], else_: [r1] };
          break;
        case 'both-arms-rebind-both':
          branch = { kind: 'if', condition, then: [r0, r1], else_: [r2, r3] };
          break;
        case 'prop-write-in-arm':
          // A conditional STATE write beside a local rebind — the shape of
          // `conformance/tests/cond-write-multi-field`. Stateful-only: a
          // stateless contract has no writable property, so `propWrite` is
          // null there. Say so instead of building a statement list with a
          // hole in it, which surfaces as `Cannot read properties of null`
          // from inside a renderer, several frames from the real mistake.
          if (!propWrite) {
            throw new Error(
              "branch shape 'prop-write-in-arm' needs a writable bigint property: " +
              'draw it from arbGeneratedStatefulContractWithShape, not the ' +
              'stateless generator.',
            );
          }
          branch = { kind: 'if', condition, then: [propWrite, r0], else_: [r1] };
          break;
      }
      return [...decls, branch, readClause];
    });
}

// ---------------------------------------------------------------------------
// Loop SHAPES for the cross-tier `--ir` generator
// ---------------------------------------------------------------------------

/**
 * WHY THESE EXIST
 * ---------------
 * `arbMethodIR` / `arbStatefulMethodIR` never emitted a `ForStmt`, so the
 * 7-tier `--ir` parity fuzzer had NEVER compiled a loop in any tier — and the
 * native renderers refused one outright. The 2026-08 loop-carried-local
 * miscompile moved bytes identically across all seven tiers; a cross-tier
 * parity fuzzer would not have caught it either way, but it also could not
 * have caught a tier that lowered the FIX differently, because it had no loop
 * in its reachable space at all.
 *
 * The shapes are deliberately narrow: ascending, unit-step, half-open bounds —
 * the only loop form all nine surface syntaxes express losslessly (the Rust
 * DSL has `for i in a..b` and nothing else; see `requireNativeLoopForm` in
 * `renderers.ts`). Bodies stay additive and small because a bounded loop is
 * UNROLLED, so the body is emitted `count` times in every tier.
 */
export type IrLoopShape =
  /** One carried local, self-accumulating. */
  | 'single-carrier'
  /** Two carried locals; the first is rebound then READ by the second in the
   *  same iteration — the confirmed 2026-08 miscompile topology. */
  | 'k2-cross-read'
  /** The same cross-read one scope deeper, inside a NESTED loop. */
  | 'nested-cross-read';

export const IR_LOOP_SHAPES: readonly IrLoopShape[] = [
  'single-carrier',
  'k2-cross-read',
  'nested-cross-read',
];

/** The loop-carried locals a shape declares, in order. */
export function irLoopShapeCarriers(shape: IrLoopShape): string[] {
  return shape === 'single-carrier' ? ['sum0'] : ['sum0', 'sum1'];
}

/**
 * An accumulate term. Prefers a runtime bigint (property or parameter) so the
 * body survives constant folding — a bounded loop is unrolled, and a body over
 * literals and the loop counter alone is folded away before stack lowering, so
 * the shape would be in the corpus and still never reach the code under test.
 * Falls back to the loop counter when the method has no bigint in scope.
 */
function arbLoopTermIR(runtimeVars: string[], iterVars: string[]): fc.Arbitrary<Expr> {
  const pool = runtimeVars.length > 0 ? runtimeVars : iterVars;
  return fc.constantFrom(...pool).map((name): Expr =>
    name.startsWith('this.')
      ? { kind: 'property_ref', name: name.slice(5) }
      : { kind: 'var_ref', name },
  );
}

/** `target = target <op> <term>`. */
function accumulateStmtIR(target: string, op: '+' | '-', term: Expr): Stmt {
  return {
    kind: 'assign',
    target,
    value: { kind: 'binary', op, left: { kind: 'var_ref', name: target }, right: term },
    isProperty: false,
  };
}

/**
 * A loop block of the requested shape: carrier declarations, the (possibly
 * nested) loop, and a terminal assert reading every carrier so the loop result
 * decides the spend verdict.
 */
function arbIrLoopBlock(
  shape: IrLoopShape,
  bigintVars: string[],
): fc.Arbitrary<Stmt[]> {
  const carriers = irLoopShapeCarriers(shape);
  const nested = shape === 'nested-cross-read';
  const iterVars = nested ? ['k0', 'k1'] : ['k0'];
  // The iteration variables are scoped to the loop, so only the carriers and
  // the method's own props/params may appear in the POST-loop read clause.
  const afterLoop = [...carriers, ...bigintVars];

  return fc
    .tuple(
      fc.tuple(...carriers.map(() => arbBigintExprIR(bigintVars, 1))),
      // Bounds: ascending, unit step, half-open — the cross-tier subset.
      fc.tuple(fc.integer({ min: 0, max: 2 }), fc.integer({ min: 1, max: 3 })),
      fc.tuple(fc.integer({ min: 0, max: 2 }), fc.integer({ min: 1, max: 2 })),
      fc.constantFrom('+' as const, '-' as const),
      fc.constantFrom('+' as const, '-' as const),
      arbLoopTermIR(bigintVars, iterVars),
      arbCarrierReadClause(carriers, afterLoop),
    )
    .map(([inits, outerB, innerB, accOp, crossOp, term, readClause]): Stmt[] => {
      const decls: Stmt[] = carriers.map((name, i) => ({
        kind: 'var_decl',
        name,
        type: 'bigint',
        value: inits[i]!,
        mutable: true,
      }));
      const body: Stmt[] =
        shape === 'single-carrier'
          ? [accumulateStmtIR('sum0', accOp, term)]
          : [
              accumulateStmtIR('sum0', accOp, term),
              // `sum0` was just rebound and is READ here, in the same iteration.
              accumulateStmtIR('sum1', crossOp, { kind: 'var_ref', name: 'sum0' }),
            ];
      const innerLoop: Stmt = {
        kind: 'for',
        iterVar: 'k1',
        start: BigInt(innerB[0]),
        bound: BigInt(innerB[0] + innerB[1]),
        op: '<',
        step: 1,
        body,
      };
      const loop: Stmt = {
        kind: 'for',
        iterVar: 'k0',
        start: BigInt(outerB[0]),
        bound: BigInt(outerB[0] + outerB[1]),
        op: '<',
        step: 1,
        body: nested ? [innerLoop] : body,
      };
      return [...decls, loop, readClause];
    });
}

// ---------------------------------------------------------------------------
// IR method and contract generators
// ---------------------------------------------------------------------------

function arbMethodIR(
  properties: GeneratedProperty[],
  config: GeneratorConfig,
  forceBranchShape?: BranchShape,
  forceLoopShape?: IrLoopShape,
): fc.Arbitrary<GeneratedMethod> {
  return fc.tuple(
    fc.integer({ min: 0, max: 9 }).map((n) => `method${n}`),
    fc.array(
      fc.tuple(
        fc.integer({ min: 0, max: 99 }).map((n) => `param${n}`),
        fc.constantFrom('bigint' as RuinarType, 'boolean' as RuinarType),
      ),
      { minLength: 0, maxLength: config.maxParams },
    ),
  ).chain(([name, paramDefs]) => {
    // Deduplicate
    const seen = new Set<string>();
    const params: GeneratedParam[] = [];
    for (const [pName, pType] of paramDefs) {
      const unique = seen.has(pName) ? `${pName}X` : pName;
      seen.add(unique);
      params.push({ name: unique, type: pType });
    }

    const bigintVars = [
      ...properties.filter((p) => p.type === 'bigint').map((p) => `this.${p.name}`),
      ...params.filter((p) => p.type === 'bigint').map((p) => p.name),
    ];
    const boolVars = [
      ...properties.filter((p) => p.type === 'boolean').map((p) => `this.${p.name}`),
      ...params.filter((p) => p.type === 'boolean').map((p) => p.name),
    ];

    // Stateless contracts have no writable properties, so no property write
    // can appear in a branch arm here — that shape is stateful-only.
    const branchBlock = fc
      .constantFrom(...(forceBranchShape ? [forceBranchShape] : BRANCH_SHAPES))
      .chain((shape) => arbBranchBlockIR(shape, bigintVars, boolVars, []));
    const loopBlock = fc
      .constantFrom(...(forceLoopShape ? [forceLoopShape] : IR_LOOP_SHAPES))
      .chain((shape) => arbIrLoopBlock(shape, bigintVars));

    return fc.tuple(
      fc.array(arbVarDeclStmtIR(bigintVars), { minLength: 0, maxLength: 2 }),
      fc.array(branchBlock, {
        minLength: forceBranchShape ? 1 : 0,
        maxLength: 1,
      }),
      // At most ONE loop per method: a bounded loop is unrolled, so each extra
      // one multiplies the emitted Stack IR in all seven tiers.
      fc.array(loopBlock, { minLength: forceLoopShape ? 1 : 0, maxLength: 1 }),
      fc.array(arbAssertStmtIR(bigintVars, boolVars), { minLength: 1, maxLength: 2 }),
    ).map(([decls, branches, loops, asserts]): GeneratedMethod => {
      const body: Stmt[] = [
        ...decls.map((d) => d.stmt),
        ...branches.flat(),
        ...loops.flat(),
        ...asserts,
      ];

      return {
        name,
        visibility: 'public',
        params,
        body,
        mutatesState: false,
      };
    });
  });
}

function arbStatefulMethodIR(
  properties: GeneratedProperty[],
  config: GeneratorConfig,
  forceBranchShape?: BranchShape,
  forceLoopShape?: IrLoopShape,
): fc.Arbitrary<GeneratedMethod> {
  const mutableProps = properties.filter((p) => !p.readonly);

  return fc.tuple(
    fc.integer({ min: 0, max: 9 }).map((n) => `method${n}`),
    fc.array(
      fc.tuple(
        fc.integer({ min: 0, max: 99 }).map((n) => `param${n}`),
        fc.constant('bigint' as RuinarType),
      ),
      { minLength: 0, maxLength: config.maxParams },
    ),
  ).chain(([name, paramDefs]) => {
    const seen = new Set<string>();
    const params: GeneratedParam[] = [];
    for (const [pName, pType] of paramDefs) {
      const unique = seen.has(pName) ? `${pName}X` : pName;
      seen.add(unique);
      params.push({ name: unique, type: pType });
    }

    const bigintVars = [
      ...properties.filter((p) => p.type === 'bigint').map((p) => `this.${p.name}`),
      ...params.filter((p) => p.type === 'bigint').map((p) => p.name),
    ];
    const boolVars = properties.filter((p) => p.type === 'boolean').map((p) => `this.${p.name}`);

    const mutableBigintProps = mutableProps
      .filter((p) => p.type === 'bigint')
      .map((p) => p.name);
    // `prop-write-in-arm` needs a writable bigint property; drop it when the
    // drawn contract has none (every mutable property could be non-bigint).
    const shapePool = mutableBigintProps.length > 0 ? STATEFUL_BRANCH_SHAPES : BRANCH_SHAPES;
    const branchBlock = fc
      .constantFrom(...(forceBranchShape ? [forceBranchShape] : shapePool))
      .chain((shape) => arbBranchBlockIR(shape, bigintVars, boolVars, mutableBigintProps));
    const loopBlock = fc
      .constantFrom(...(forceLoopShape ? [forceLoopShape] : IR_LOOP_SHAPES))
      .chain((shape) => arbIrLoopBlock(shape, bigintVars));

    return fc.tuple(
      // State mutations
      fc.array(
        fc.tuple(
          fc.constantFrom(...mutableBigintProps),
          arbBigintExprIR(bigintVars, 1),
        ).map(([target, value]): Stmt => ({
          kind: 'assign',
          target,
          value,
          isProperty: true,
        })),
        { minLength: 1, maxLength: Math.min(2, mutableProps.length) },
      ),
      fc.array(arbAssertStmtIR(bigintVars, boolVars), { minLength: 0, maxLength: 1 }),
      fc.array(branchBlock, { minLength: forceBranchShape ? 1 : 0, maxLength: 1 }),
      fc.array(loopBlock, { minLength: forceLoopShape ? 1 : 0, maxLength: 1 }),
      // The multi-output intrinsic (`this.addOutput(sats, ...)`). Drawn as a
      // 0-or-1 element array so roughly half the methods carry an EXPLICIT
      // continuation and the rest keep the compiler-injected implicit one —
      // both paths then have to agree across every tier.
      arbAddOutputStmt(mutableProps),
    ).map(([mutations, asserts, branches, loops, addOutputs]): GeneratedMethod => ({
      name,
      visibility: 'public',
      params,
      // `add_output` goes LAST: its operands are the post-mutation property
      // values, which is the shape every checked-in example uses.
      body: [...asserts, ...branches.flat(), ...loops.flat(), ...mutations, ...addOutputs],
      mutatesState: true,
    }));
  });
}

/**
 * `this.addOutput(satoshis, ...values)` — the multi-output intrinsic.
 *
 * Until 2026-08 `contract-ir.ts` had no node for it, so the intrinsic was
 * unreachable from EVERY IR-based generator and its cross-tier parity was
 * untested: `conformance/fuzzer/spend-shapes.ts` exercised it under the
 * absolute post-state oracle, but that harness is TypeScript-only and proves
 * nothing about the other six frontends.
 *
 * `values` is positional against the MUTABLE properties in DECLARATION ORDER,
 * so the arity is fixed by the contract, not drawn. Passing each property's own
 * post-mutation value makes the explicit continuation semantically equal to the
 * implicit one the compiler would otherwise inject — any tier that disagrees
 * about the state layout produces different bytes and fails the `--hex` gate.
 */
function arbAddOutputStmt(
  mutableProps: GeneratedProperty[],
): fc.Arbitrary<Stmt[]> {
  if (mutableProps.length === 0) return fc.constant([]);
  return fc.option(
    fc.constantFrom(0n, 1n, 1000n).map((satoshis): Stmt => ({
      kind: 'add_output',
      satoshis,
      values: mutableProps.map((p) => ({ kind: 'property_ref', name: p.name })),
    })),
    { nil: undefined },
  ).map((s) => (s ? [s] : []));
}

/**
 * Method names are drawn independently per method (`method0`..`method9`), so a
 * contract with several methods can draw the same name twice. The surface
 * languages do NOT agree on what that means: TypeScript and Ruby take the LAST
 * definition and discard the first, while Java sees two different parameter
 * lists and treats them as an OVERLOAD, keeping both. The same
 * `GeneratedContract` therefore renders to genuinely different PROGRAMS per
 * tier, and the "cross-tier divergence" that follows is a generator artifact,
 * not a compiler bug. (Seed 987654 at `--num 200` hit it: {ts,go,rust,python}
 * vs {java,ruby}, 2 bytes apart.)
 *
 * Uniquify with the same `X`-suffix convention the property and parameter draws
 * already use.
 */
function dedupeMethodNames(methods: GeneratedMethod[]): GeneratedMethod[] {
  const seen = new Set<string>();
  return methods.map((m) => {
    let name = m.name;
    while (seen.has(name)) name += 'X';
    seen.add(name);
    return name === m.name ? m : { ...m, name };
  });
}

function arbGeneratedContractOf(
  forceBranchShape?: BranchShape,
  forceLoopShape?: IrLoopShape,
): fc.Arbitrary<GeneratedContract> {
  return fc
  .tuple(
    fc.integer({ min: 0, max: 99 }).map((n) => `FuzzContract${n}`),
    fc.array(
      fc.tuple(
        fc.integer({ min: 0, max: 99 }).map((n) => `prop${n}`),
        fc.constantFrom('bigint' as RuinarType, 'boolean' as RuinarType),
      ),
      { minLength: 1, maxLength: DEFAULT_CONFIG.maxProperties },
    ),
  )
  .chain(([name, propDefs]) => {
    const seen = new Set<string>();
    const properties: GeneratedProperty[] = [];
    for (const [pName, pType] of propDefs) {
      const unique = seen.has(pName) ? `${pName}X` : pName;
      seen.add(unique);
      properties.push({ name: unique, type: pType, readonly: true });
    }

    return fc
      .array(arbMethodIR(properties, DEFAULT_CONFIG, forceBranchShape, forceLoopShape), {
        minLength: 1,
        maxLength: DEFAULT_CONFIG.maxMethods,
      })
      .map((methods): GeneratedContract => ({
        name,
        parentClass: 'SmartContract',
        properties,
        methods: dedupeMethodNames(methods),
      }));
  });
}

/**
 * Generate a random stateless GeneratedContract IR.
 */
export const arbGeneratedContract: fc.Arbitrary<GeneratedContract> = arbGeneratedContractOf();

/**
 * The same generator with the branch topology and/or the loop topology PINNED.
 * Only tests use these: they turn "every shape is reachable" from a probability
 * argument into a deterministic, per-shape assertion (the same device
 * `arbExecCaseWithLoopShape` provides for the exec-oracle corpus).
 */
export function arbGeneratedContractWithShape(
  branch?: BranchShape,
  loop?: IrLoopShape,
): fc.Arbitrary<GeneratedContract> {
  return arbGeneratedContractOf(branch, loop);
}

function arbGeneratedStatefulContractOf(
  forceBranchShape?: BranchShape,
  forceLoopShape?: IrLoopShape,
): fc.Arbitrary<GeneratedContract> {
  return fc
  .tuple(
    fc.integer({ min: 0, max: 99 }).map((n) => `FuzzStateful${n}`),
    // At least one mutable bigint property
    fc.array(
      fc.tuple(
        fc.integer({ min: 0, max: 99 }).map((n) => `prop${n}`),
        fc.constant('bigint' as RuinarType),
        fc.boolean(), // readonly?
      ),
      { minLength: 1, maxLength: DEFAULT_CONFIG.maxProperties },
    ),
  )
  .chain(([name, propDefs]) => {
    const seen = new Set<string>();
    const properties: GeneratedProperty[] = [];
    let hasMutable = false;
    for (const [pName, pType, isReadonly] of propDefs) {
      const unique = seen.has(pName) ? `${pName}X` : pName;
      seen.add(unique);
      properties.push({ name: unique, type: pType, readonly: isReadonly });
      if (!isReadonly) hasMutable = true;
    }

    // Ensure at least one mutable property
    if (!hasMutable && properties.length > 0) {
      properties[0]!.readonly = false;
    }

    return fc
      .array(
        arbStatefulMethodIR(properties, DEFAULT_CONFIG, forceBranchShape, forceLoopShape),
        {
          minLength: 1,
          maxLength: DEFAULT_CONFIG.maxMethods,
        },
      )
      .map((methods): GeneratedContract => {
        const named = dedupeMethodNames(methods);
        ensureEveryMutablePropertyIsWritten(properties, named);
        return {
          name,
          parentClass: 'StatefulSmartContract',
          properties,
          methods: named,
        };
      });
  });
}

/**
 * Every property marked mutable must actually be written by some method.
 *
 * R-111. `readonly` is drawn by coin flip, independently of which properties the
 * method bodies go on to assign, so the generator could emit a property that is
 * mutable BY DECLARATION and written by nothing. On the `.runar.ts` surface that
 * is expressible — mutability is declared — and the property joins the
 * serialized state. On the `.runar.zig` surface it is NOT: that frontend INFERS
 * readonly for a stateful field with no default that no method assigns, so the
 * same logical contract renders to a Zig source with fewer state slots, and
 * `addOutput(sats, ...values)` then fails Zig's arity check with
 * "expects 2 argument(s): satoshis + 1 state value(s), got 4".
 *
 * That is the fuzzer artifact the READONLY PARITY note in `renderers.ts`
 * describes, in the direction that note does not cover — it handles
 * `readonly: true` reaching every renderer's marker, and this is
 * `readonly: false` failing to survive a surface that infers.
 *
 * It is also why the stateful IR gate excluded Zig. Rather than teach one
 * surface to express something another infers, the generator stops producing
 * the shape: an identity write (`this.p = this.p`) is appended for any mutable
 * property no method assigns. An identity write is a real `update_prop` — DCE
 * must keep it, since property writes are side-effecting in every tier — so the
 * property is mutable on every surface, by inference or by declaration.
 *
 * Inserted BEFORE any `add_output` in the chosen method: the intrinsic's
 * operands are the post-mutation values, which is the shape every checked-in
 * example uses and the one the renderers assume.
 */
function ensureEveryMutablePropertyIsWritten(
  properties: GeneratedProperty[],
  methods: GeneratedMethod[],
): void {
  if (methods.length === 0) return;

  const written = new Set<string>();
  const walk = (stmts: Stmt[]): void => {
    for (const st of stmts) {
      if (st.kind === 'assign' && st.isProperty) written.add(st.target);
      else if (st.kind === 'if') {
        walk(st.then);
        if (st.else_) walk(st.else_);
      } else if (st.kind === 'for') walk(st.body);
    }
  };
  for (const m of methods) walk(m.body);

  const unwritten = properties.filter((p) => !p.readonly && !written.has(p.name));
  if (unwritten.length === 0) return;

  const target = methods[0]!;
  const insertAt = target.body.findIndex((st) => st.kind === 'add_output');
  const identityWrites: Stmt[] = unwritten.map((p) => ({
    kind: 'assign',
    target: p.name,
    value: { kind: 'property_ref', name: p.name },
    isProperty: true,
  }));
  if (insertAt < 0) target.body.push(...identityWrites);
  else target.body.splice(insertAt, 0, ...identityWrites);
  target.mutatesState = true;
}

/**
 * Generate a random stateful GeneratedContract IR.
 */
export const arbGeneratedStatefulContract: fc.Arbitrary<GeneratedContract> =
  arbGeneratedStatefulContractOf();

/** The stateful generator with its branch / loop topology PINNED (tests only). */
export function arbGeneratedStatefulContractWithShape(
  branch?: BranchShape,
  loop?: IrLoopShape,
): fc.Arbitrary<GeneratedContract> {
  return arbGeneratedStatefulContractOf(branch, loop);
}

// ===========================================================================
// Tri-modal execution-oracle generator (issue #124)
//
// A dedicated arbitrary for the tri-modal source-vs-script oracle
// (`runTriModalExecution`). It is DELIBERATELY separate from
// `arbGeneratedContract` (which feeds the native cross-tier `--ir` path and
// must render byte-identically across all 7 tiers). This generator adds the
// three shapes that historically hid silent miscompiles and only became
// correctly compilable after #121 (loop start/step) + #130 (param shadow):
//
//   1. `for` loops with a NON-ZERO start counting up AND countdown loops.
//   2. `substr` / `cat` / `len` byte-ops over ByteString PARAMETERS.
//   3. post-loop parameter reads (a param referenced after a loop body).
//
// Since 2026-08 it also spans the loop-body TOPOLOGIES in `ExecLoopShape`:
// bodies carrying two locals with an intra-iteration cross-read (the confirmed
// fund-safety miscompile), its read-before-reassign control, and nested loops.
// See the `ExecLoopShape` doc comment for why a single-accumulator body was a
// REACHABILITY hole rather than bad luck.
//
// Every generated case is rendered to TypeScript ONLY (via `renderTypeScript`)
// and carries its own concrete constructor + method inputs, so fast-check
// PROPERTY mode shrinks both the contract structure and the failing inputs to
// a minimal repro. Cases are constructed to always be valid, in-range Rúnar
// (fixed-length ByteStrings + statically-safe substr bounds + additive,
// magnitude-bounded loop bodies) so the ONLY way the three engines disagree is
// a real compiler bug — never a harness artifact.
// ===========================================================================

/** Concrete witness/constructor value for an execution-oracle case. */
export type ExecArg = bigint | boolean | Uint8Array;

/** A fully-concrete tri-modal execution-oracle case (contract + inputs). */
export interface ExecCase {
  contract: GeneratedContract; // exactly one public method
  method: string;
  constructorArgs: Record<string, ExecArg>;
  args: ExecArg[]; // positional, in method-parameter order
  /**
   * The loop topology this case was drawn for, or `null` when it has no loop.
   * Reported on findings so a divergence names its construct family. It is a
   * LABEL, not a promise: the reachability test re-derives the shape from the
   * generated IR and fails if the two disagree.
   */
  loopShape: ExecLoopShape | null;
  /**
   * The branch topology this case was drawn for, or `null` when it has no
   * branch. Same LABEL contract as `loopShape`.
   */
  branchShape: ExecBranchShape | null;
}

/** Fixed ByteString length for all generated params/props — lets the byte-op
 *  generator compute statically-safe `substr` bounds. */
const EXEC_BYTES_LEN = 4;
/** |bigint inputs| bound — small enough that additive loop accumulation and a
 *  single multiply stay far inside Bitcoin script-number range. */
const EXEC_INT_MAG = 8n;

const EXEC_CMP_OPS = ['===', '!==', '<', '>', '<=', '>='] as const;

/** Reference an available bigint var (`local`, param, or `this.prop`). */
function bigintVarRef(name: string): Expr {
  return name.startsWith('this.')
    ? { kind: 'property_ref', name: name.slice(5) }
    : { kind: 'var_ref', name };
}

/** A small bigint atom: literal in [-4,4] or an available bigint var. */
function arbBigintAtom(bigintVars: string[]): fc.Arbitrary<Expr> {
  const options: fc.Arbitrary<Expr>[] = [
    fc.integer({ min: -4, max: 4 }).map((v): Expr => ({ kind: 'bigint_literal', value: BigInt(v) })),
  ];
  if (bigintVars.length > 0) {
    options.push(fc.constantFrom(...bigintVars).map(bigintVarRef));
  }
  return fc.oneof(...options);
}

/** Additive-only bigint expr (bounded magnitude) — safe inside loop bodies. */
function arbAdditiveExpr(bigintVars: string[], depth: number): fc.Arbitrary<Expr> {
  if (depth <= 0) return arbBigintAtom(bigintVars);
  return fc.oneof(
    arbBigintAtom(bigintVars),
    fc
      .tuple(
        arbAdditiveExpr(bigintVars, depth - 1),
        fc.constantFrom('+' as const, '-' as const),
        arbBigintAtom(bigintVars),
      )
      .map(([left, op, right]): Expr => ({ kind: 'binary', op, left, right })),
  );
}

/** Bounded bigint expr allowing one multiply — used only OUTSIDE loop bodies. */
function arbBoundedBigintExpr(bigintVars: string[], depth: number): fc.Arbitrary<Expr> {
  if (depth <= 0) return arbBigintAtom(bigintVars);
  return fc.oneof(
    arbBigintAtom(bigintVars),
    fc
      .tuple(
        arbAdditiveExpr(bigintVars, depth - 1),
        fc.constantFrom('+' as const, '-' as const, '*' as const),
        arbBigintAtom(bigintVars),
      )
      .map(([left, op, right]): Expr => ({ kind: 'binary', op, left, right })),
  );
}

/** A ByteString var with a statically-known MINIMUM byte length. */
interface BytesVar {
  ref: Expr;
  minLen: number;
}

/**
 * Whether `arbBytesExpr` may emit `split`.
 *
 * OFF, because the FIRST thing the arm did when switched on was find a
 * compiler defect it cannot work around. `split` pushes TWO stack-map slots
 * for ONE binding in `05-stack-lower.ts#lowerBuiltinCall`:
 *
 *     if (func === 'split') {
 *       this.stackMap.push(null);        // left part  <- orphan, never dropped
 *       this.stackMap.push(bindingName); // right part
 *     }
 *
 * The orphaned left half desyncs the model from the runtime stack, so a read
 * AFTER the split resolves to the wrong slot and lowering aborts. Minimal
 * repro, pinned by `conformance/split-stack-desync.test.ts`:
 *
 *     const b0: ByteString = split(data, 1n);
 *     assert(len(b0) >= 0n && len(data) >= 0n);
 *     // Value 't11' not found on stack (stack has 1 items: [])
 *
 * Drop the trailing `&& len(data) >= 0n` and it compiles; the same shape with
 * `substr` compiles, because substr NIPs its left half. So `split` is usable
 * only when nothing is read after it, which is why it had no fixture: the only
 * shape that compiles is the trivial one.
 *
 * That belongs to whoever owns `packages/runar-compiler/`, not to this file.
 * Flip this to `true` in the same change that fixes the lowering —
 * `conformance/split-stack-desync.test.ts` goes red when the defect is gone
 * and will tell you so.
 *
 * `split` is NOT uncovered in the meantime: `conformance/tests/byte-builtins`
 * compiles it on all seven tiers and
 * `conformance/byte_builtins_execution_test.go` spends it at index 0, at
 * index == len, on the empty string and out of range.
 */
const SPLIT_ARM_ENABLED = false;

/**
 * A ByteString expression built from the available ByteString vars, tracking a
 * conservative minimum length so `substr` and `split` bounds are always in
 * range on both the interpreter and the script engines (OP_SPLIT rejects
 * out-of-range).
 *
 * `int2str` is deliberately NOT here, and adding it would break the gate. The
 * Go renderer spells builtins `runar.` + PascalCase, which makes
 * `runar.Int2Str` — and go, rust, python and java all REJECT that spelling
 * ("unknown function 'int2Str'"): they camel-case the leading character
 * instead of consulting the alias map, and the builtin is registered as
 * `int2str`. Since `fuzz:ir:gate` compiles every case on all seven tiers,
 * emitting int2str would make four of them permanent outliers. `int2str` is
 * covered instead by the `byte-builtins` fixture and
 * `conformance/byte_builtins_execution_test.go`, where the surface spelling is
 * chosen by hand.
 */
function arbBytesExpr(
  bytesVars: BytesVar[],
  depth: number,
): fc.Arbitrary<{ expr: Expr; minLen: number }> {
  const atom = fc.constantFrom(...bytesVars).map((v) => ({ expr: v.ref, minLen: v.minLen }));
  if (depth <= 0) return atom;
  return fc.oneof(
    atom,
    // cat(a, b) — always valid; min length adds.
    fc
      .tuple(arbBytesExpr(bytesVars, depth - 1), arbBytesExpr(bytesVars, depth - 1))
      .map(([a, b]) => ({
        expr: { kind: 'call', fn: 'cat', args: [a.expr, b.expr] } as Expr,
        minLen: a.minLen + b.minLen,
      })),
    // substr(x, start, len) — bounds chosen inside [0, minLen(x)].
    arbBytesExpr(bytesVars, depth - 1).chain((base) =>
      fc.integer({ min: 0, max: base.minLen }).chain((start) =>
        fc.integer({ min: 0, max: base.minLen - start }).map((len) => ({
          expr: {
            kind: 'call',
            fn: 'substr',
            args: [
              base.expr,
              { kind: 'bigint_literal', value: BigInt(start) },
              { kind: 'bigint_literal', value: BigInt(len) },
            ],
          } as Expr,
          minLen: len,
        })),
      ),
    ),
    // split(x, idx) — binds the RIGHT half; `idx` is chosen inside
    // [0, minLen(x)] so OP_SPLIT is in range on every witness, exactly as the
    // substr arm above does. Both ends of that interval are reachable, which
    // is the point: an off-by-one in the OP_SPLIT lowering shows up at idx 0
    // or at idx == len and nowhere in between.
    //
    // NOTE the compiler binds the right half only — `runar-lang` declares
    // `split(): [ByteString, ByteString]` but no parser accepts array
    // destructuring, so the left half is unnameable. Do not "fix" this arm to
    // emit a tuple; nothing can compile one.
    //
    // DISABLED — see SPLIT_ARM_ENABLED below.
    ...(SPLIT_ARM_ENABLED
      ? [
        arbBytesExpr(bytesVars, depth - 1).chain((base) =>
          fc.integer({ min: 0, max: base.minLen }).map((idx) => ({
            expr: {
              kind: 'call',
              fn: 'split',
              args: [base.expr, { kind: 'bigint_literal', value: BigInt(idx) }],
            } as Expr,
            minLen: base.minLen - idx,
          })),
        ),
      ]
      : []),
    // reverseBytes(x) — length-preserving, valid on every input including the
    // empty string, so no bound is needed. The base is a depth-0 atom on
    // purpose: each call unrolls 520 OP_SPLIT/OP_CAT iterations (~5.5 KB of
    // script), and a nested `reverseBytes(reverseBytes(x))` would spend the
    // corpus's whole size budget proving the peephole pass can survive 1 MB of
    // one opcode rather than exercising the builtin.
    atom.map((base) => ({
      expr: { kind: 'call', fn: 'reverseBytes', args: [base.expr] } as Expr,
      minLen: base.minLen,
    })),
  );
}

// ---------------------------------------------------------------------------
// Loop-body SHAPES (the 2026-08 loop-carried-locals blind spot)
// ---------------------------------------------------------------------------

/**
 * WHY THESE EXIST
 * ---------------
 * Until 2026-08 this generator could emit exactly ONE loop-body shape: every
 * generated body statement targeted the SAME accumulator (`acc = acc <op>
 * term`), and the term was drawn from a variable list that never contained
 * `acc` itself. A loop body carrying TWO locals — one reassigned and then READ
 * by a DIFFERENT statement in the same iteration — was therefore not merely
 * unlikely, it was OUTSIDE THE GENERATOR'S REACHABLE SPACE: no seed, no time
 * budget and no number of runs could ever produce it.
 *
 * That is precisely the shape of the confirmed 2026-08-06 fund-safety
 * miscompile (`packages/runar-testing/src/__tests__/
 * loop-carried-local-read-after-reassign-vm.test.ts`): a bounded loop that
 * rebinds a carried local and reads it again in the same iteration compiled to
 * a script computing `step*N` instead of `step*N*(N+1)/2` — silently and
 * byte-identically in all seven tiers. Three bug-hunting waves missed it
 * because the reachable space was the gap, not the runtime.
 *
 * The family below is the fix for the SPACE. Each shape is a body topology, not
 * a value class; the accumulate terms, bounds, direction and surrounding
 * clauses still vary randomly around it. `arbExecCaseWithLoopShape` pins one
 * shape so a seeded unit test can PROVE each is produced rather than argue from
 * probability.
 *
 * Both nested shapes were defects when this family was written on 2026-08-06:
 * `nested-inner-cross-read` miscompiled silently (source `wacc = 30`, script
 * `24`, all seven tiers) and `nested-outer-read` failed to compile at all
 * ("Value 'acc' not found on stack"). Both are fixed; both stay in the corpus
 * as the regression guard.
 */
export type ExecLoopShape =
  /** Historical shape: ONE carried local, every body statement targets it. */
  | 'single-carrier'
  /** Two carried locals, neither reading the other — the accepting control. */
  | 'k2-independent'
  /** Two carried locals; `acc` is rebound, then READ by the next statement in
   *  the same iteration. The confirmed-miscompile shape. */
  | 'k2-cross-read'
  /** Two carried locals; `acc` is READ BEFORE it is rebound. The known-safe
   *  control — the generator must reach both so it can tell them apart. */
  | 'k2-read-before-reassign'
  /** NESTED loops with the cross-read in the INNER body, so at the outer level
   *  the carried local is bound only inside the nested loop. */
  | 'nested-inner-cross-read'
  /** NESTED loops where the carried local is rebound only in the INNER body and
   *  read at the OUTER level, after the inner loop closes. */
  | 'nested-outer-read';

/** Every loop shape the exec-oracle corpus must be able to reach. */
export const EXEC_LOOP_SHAPES: readonly ExecLoopShape[] = [
  'single-carrier',
  'k2-independent',
  'k2-cross-read',
  'k2-read-before-reassign',
  'nested-inner-cross-read',
  'nested-outer-read',
];

/** The primary accumulator, carried across every loop shape. */
const EXEC_ACC = 'acc';
/** The second carried local — present in every shape except `single-carrier`. */
const EXEC_WACC = 'wacc';

/** Mutable locals a shape needs declared BEFORE its loop, in declaration order. */
export function loopShapeCarriers(shape: ExecLoopShape): string[] {
  return shape === 'single-carrier' ? [EXEC_ACC] : [EXEC_ACC, EXEC_WACC];
}

// ---------------------------------------------------------------------------
// Branch topologies (2026-08 — the second REACHABILITY hole)
// ---------------------------------------------------------------------------

/**
 * Branch shapes for the exec-oracle method bodies.
 *
 * WHY THIS EXISTS — the same class of hole `ExecLoopShape` closed for loops.
 * `arbExecMethodBody` emitted ZERO `if` statements, so `--execute` and
 * `--tri-modal` — the only OTHER absolute oracles in the repo — had no
 * randomized branch coverage at all. Every branch-merge miscompilation the
 * project has shipped (PALMER-1, issue #149) was therefore outside their
 * reachable space by construction: no seed, no run count and no time budget
 * could have produced one.
 *
 * `nested-arm-sibling` is the issue-#149 shape and needs BOTH of its degrees of
 * freedom drawn together — see the `ArmStyle` comment in
 * `conformance/fuzzer/spend-shapes.ts` for the measurement that established
 * that either half alone finds nothing.
 */
export type ExecBranchShape =
  /** `if (c) { m0 = …; m1 = …; }` — single-armed, both merged locals are
   *  declared results and the fall-through path rebinds neither. */
  | 'flat-if'
  /** `if (c) { … } else { … }` — both arms rebind both merged locals. */
  | 'if-else'
  /**
   * The issue-#149 shape: an inner `if`/`else` NESTED inside the outer arm
   * declares results for only a PREFIX of the locals (`m0`), leaving `m1` live
   * and UNTOUCHED in the slot region the arm inherited — and the OUTER `if` has
   * NO else, so its two paths leave equal depth with different layout.
   */
  | 'nested-arm-sibling';

/** Every branch shape the exec-oracle corpus must be able to reach. */
export const EXEC_BRANCH_SHAPES: readonly ExecBranchShape[] = [
  'flat-if',
  'if-else',
  'nested-arm-sibling',
];

/** First merged local — a declared result of every branch shape. */
const EXEC_M0 = 'm0';
/** Second merged local. A declared result of `flat-if` / `if-else`; the LIVE
 *  UNTOUCHED sibling of the inner `if` under `nested-arm-sibling`. */
const EXEC_M1 = 'm1';
/** A local declared alongside the merged ones that NO shape ever rebinds, and
 *  that the terminal assert always reads. It keeps a live value in the branch
 *  region on every path, so a rotation that crosses it is observable. */
const EXEC_MSIB = 'msib';

/** Branch-region locals a shape declares, in declaration order. */
export function branchShapeLocals(_shape: ExecBranchShape): string[] {
  return [EXEC_M0, EXEC_M1, EXEC_MSIB];
}

/** The locals a shape's arms actually REBIND (its declared results). */
export function branchShapeMerged(shape: ExecBranchShape): string[] {
  return shape === 'nested-arm-sibling' ? [EXEC_M0] : [EXEC_M0, EXEC_M1];
}

/**
 * ORDER-SENSITIVE comparison ops only.
 *
 * `===` / `!==` are COMMUTATIVE, and that is exactly how the pre-existing
 * terminal assert was blind: its clauses are all of the form `a + b <cmp> rhs`,
 * which a pure slot SWAP of `a` and `b` leaves numerically unchanged. The
 * oracle then reports AGREEMENT on a script that read the wrong slots. Every
 * comparison in `arbBranchClause` is drawn from this list instead, so a
 * transposition of two branch locals changes the asserted value.
 */
const EXEC_ORDER_CMP_OPS = ['<', '>', '<=', '>='] as const;

interface LoopBounds {
  start: number;
  bound: number;
  op: '<' | '<=' | '>' | '>=';
  step: 1 | -1;
}

/** Bounds for a bounded loop: NON-ZERO start counting up, OR a countdown. */
function arbLoopBounds(maxCount: number): fc.Arbitrary<LoopBounds> {
  const up = fc
    .record({
      start: fc.integer({ min: 0, max: 4 }),
      count: fc.integer({ min: 1, max: maxCount }),
      op: fc.constantFrom('<' as const, '<=' as const),
    })
    .map(({ start, count, op }): LoopBounds => ({
      start,
      bound: op === '<' ? start + count : start + count - 1,
      op,
      step: 1,
    }));
  const down = fc
    .record({
      start: fc.integer({ min: 1, max: 8 }),
      countRaw: fc.integer({ min: 1, max: maxCount }),
      op: fc.constantFrom('>' as const, '>=' as const),
    })
    .map(({ start, countRaw, op }): LoopBounds => {
      const count = Math.min(countRaw, start); // keep 1 <= count <= start
      return {
        start,
        bound: op === '>' ? start - count : start - count + 1,
        op,
        step: -1,
      };
    });
  return fc.oneof(up, down);
}

/** `target = target <op> <term>` over a local. */
function accumulateStmt(target: string, op: '+' | '-', term: Expr): Stmt {
  return {
    kind: 'assign',
    target,
    value: { kind: 'binary', op, left: { kind: 'var_ref', name: target }, right: term },
    isProperty: false,
  };
}

/** `target = target <op> <otherLocal>` — the cross-read statement. */
function crossReadStmt(target: string, op: '+' | '-', source: string): Stmt {
  return accumulateStmt(target, op, { kind: 'var_ref', name: source });
}

/**
 * An accumulate term that always references a RUNTIME bigint (a parameter or a
 * property) when one is in scope.
 *
 * A bounded loop is UNROLLED at compile time, so a body built only from
 * literals and the loop counter is entirely constant-folded before stack
 * lowering ever sees it: the loop shape would be in the corpus and still never
 * reach the code under test. `runtimeVars` is the props/params list — never a
 * carrier, so the shape alone decides whether a carrier is cross-read.
 */
function arbAccumulateTerm(runtimeVars: string[], loopVars: string[]): fc.Arbitrary<Expr> {
  if (runtimeVars.length === 0) return arbAdditiveExpr(loopVars, 1);
  const runtimeRef = fc.constantFrom(...runtimeVars).map(bigintVarRef);
  return fc.oneof(
    runtimeRef,
    fc
      .tuple(runtimeRef, fc.constantFrom('+' as const, '-' as const), arbBigintAtom(loopVars))
      .map(([left, op, right]): Expr => ({ kind: 'binary', op, left, right })),
  );
}

/** The 1..2 self-accumulating statements of the historical single-carrier body. */
function arbSingleCarrierBody(runtimeVars: string[], loopVars: string[]): fc.Arbitrary<Stmt[]> {
  return fc.array(
    fc
      .tuple(fc.constantFrom('+' as const, '-' as const), arbAccumulateTerm(runtimeVars, loopVars))
      .map(([op, term]) => accumulateStmt(EXEC_ACC, op, term)),
    { minLength: 1, maxLength: 2 },
  );
}

/** The two-carrier body for a given topology. `loopVars` never contains a
 *  carrier, so only the shape itself decides whether a carrier is cross-read. */
function arbK2Body(
  shape: 'k2-independent' | 'k2-cross-read' | 'k2-read-before-reassign',
  runtimeVars: string[],
  loopVars: string[],
): fc.Arbitrary<Stmt[]> {
  return fc
    .tuple(
      fc.constantFrom('+' as const, '-' as const),
      arbAccumulateTerm(runtimeVars, loopVars),
      fc.constantFrom('+' as const, '-' as const),
      arbAccumulateTerm(runtimeVars, loopVars),
    )
    .map(([accOp, accTerm, waccOp, waccTerm]): Stmt[] => {
      const rebindAcc = accumulateStmt(EXEC_ACC, accOp, accTerm);
      switch (shape) {
        case 'k2-independent':
          return [rebindAcc, accumulateStmt(EXEC_WACC, waccOp, waccTerm)];
        case 'k2-cross-read':
          // acc is rebound, then read again in the SAME iteration.
          return [rebindAcc, crossReadStmt(EXEC_WACC, waccOp, EXEC_ACC)];
        case 'k2-read-before-reassign':
          // acc is read BEFORE its rebind — the accepting control.
          return [crossReadStmt(EXEC_WACC, waccOp, EXEC_ACC), rebindAcc];
      }
    });
}

/**
 * A bounded `for` loop of the requested body topology. `bigintVars` are the
 * props/params in scope (never a carrier), so the carriers appear in the body
 * only where the shape puts them.
 */
function arbForLoop(shape: ExecLoopShape, bigintVars: string[]): fc.Arbitrary<ForStmt> {
  const iterVar = 'k';
  if (shape === 'nested-inner-cross-read' || shape === 'nested-outer-read') {
    const innerVar = 'k2';
    const nestedVars = [...bigintVars, iterVar, innerVar];
    // Both counts are small: a bounded loop is UNROLLED, so the nested body is
    // emitted outer*inner times.
    return fc
      .tuple(
        arbLoopBounds(3),
        arbLoopBounds(3),
        shape === 'nested-inner-cross-read'
          ? arbK2Body('k2-cross-read', bigintVars, nestedVars)
          : fc
              .tuple(fc.constantFrom('+' as const, '-' as const), arbAccumulateTerm(bigintVars, nestedVars))
              .map(([op, term]): Stmt[] => [accumulateStmt(EXEC_ACC, op, term)]),
        fc.constantFrom('+' as const, '-' as const),
      )
      .map(([outer, inner, innerBody, outerOp]): ForStmt => {
        const innerLoop: Stmt = {
          kind: 'for',
          iterVar: innerVar,
          start: BigInt(inner.start),
          bound: BigInt(inner.bound),
          op: inner.op,
          step: inner.step,
          body: innerBody,
        };
        return {
          kind: 'for',
          iterVar,
          start: BigInt(outer.start),
          bound: BigInt(outer.bound),
          op: outer.op,
          step: outer.step,
          // `nested-outer-read`: `acc` is bound ONLY inside the inner loop and
          // read here, one scope out.
          body:
            shape === 'nested-outer-read'
              ? [innerLoop, crossReadStmt(EXEC_WACC, outerOp, EXEC_ACC)]
              : [innerLoop],
        };
      });
  }
  return arbLoopBounds(6).chain((bounds) => {
    const loopVars = [...bigintVars, iterVar];
    const body =
      shape === 'single-carrier'
        ? arbSingleCarrierBody(bigintVars, loopVars)
        : arbK2Body(shape, bigintVars, loopVars);
    return body.map((stmts): ForStmt => ({
      kind: 'for',
      iterVar,
      start: BigInt(bounds.start),
      bound: BigInt(bounds.bound),
      op: bounds.op,
      step: bounds.step,
      body: stmts,
    }));
  });
}

/**
 * A boolean clause that GUARANTEES a read of `param` — placed in the terminal
 * assert AFTER the loop, so every case with a loop exercises a post-loop
 * parameter read.
 */
function arbParamClause(
  param: GeneratedParam,
  bigintVars: string[],
  bytesVars: BytesVar[],
): fc.Arbitrary<Expr> {
  if (param.type === 'boolean') {
    return fc.oneof(
      fc.constant<Expr>({ kind: 'var_ref', name: param.name }),
      fc.constant<Expr>({ kind: 'unary', op: '!', operand: { kind: 'var_ref', name: param.name } }),
    );
  }
  if (param.type === 'ByteString') {
    const pv: BytesVar = { ref: { kind: 'var_ref', name: param.name }, minLen: EXEC_BYTES_LEN };
    // len(<expr using param>) <cmp> <literal in [0, 2*BYTES_LEN]>
    return fc
      .tuple(
        arbBytesExpr([pv, ...bytesVars], 2),
        fc.constantFrom(...EXEC_CMP_OPS),
        fc.integer({ min: 0, max: 2 * EXEC_BYTES_LEN }),
      )
      .map(([b, op, n]): Expr => ({
        kind: 'binary',
        op,
        left: { kind: 'call', fn: 'len', args: [b.expr] },
        right: { kind: 'bigint_literal', value: BigInt(n) },
      }));
  }
  // bigint param: (param <cmp> <bounded bigint expr>)
  return fc
    .tuple(fc.constantFrom(...EXEC_CMP_OPS), arbBoundedBigintExpr(bigintVars, 2))
    .map(([op, rhs]): Expr => ({
      kind: 'binary',
      op,
      left: { kind: 'var_ref', name: param.name },
      right: rhs,
    }));
}

/** An extra boolean clause over the accumulator / byte lengths (no guarantee
 *  of a param read — that is the param clause's job). */
function arbExtraClause(bigintVars: string[], bytesVars: BytesVar[]): fc.Arbitrary<Expr> {
  const numeric = fc
    .tuple(
      arbBoundedBigintExpr(bigintVars, 2),
      fc.constantFrom(...EXEC_CMP_OPS),
      arbBoundedBigintExpr(bigintVars, 2),
    )
    .map(([left, op, right]): Expr => ({ kind: 'binary', op, left, right }));
  if (bytesVars.length === 0) return numeric;
  const bytesEq = fc
    .tuple(arbBytesExpr(bytesVars, 2), arbBytesExpr(bytesVars, 2), fc.constantFrom('===' as const, '!==' as const))
    .map(([a, b, op]): Expr => ({ kind: 'binary', op, left: a.expr, right: b.expr }));
  return fc.oneof(numeric, bytesEq);
}

/**
 * A boolean clause that GUARANTEES a read of EVERY loop carrier after the
 * loop. Without it a body could accumulate into `wacc` and never look at it,
 * so a wrong `wacc` would not change the spend verdict and the tri-modal
 * oracle would see nothing. Conjoined into the terminal assert, so the carrier
 * values are what the script's accept/reject actually turns on.
 *
 * `bigintVars` INCLUDES the carriers, and that is load-bearing: this oracle
 * compares VERDICTS, so a carrier that is off by some iterations' worth of
 * accumulation is invisible unless the comparison's threshold falls between
 * the right and wrong values. Carrier-relative comparisons (`wacc <cmp> acc *
 * 2`) are the ones that do; an absolute threshold drawn from a fixed literal
 * range almost never does, because a carrier that accumulated over N
 * iterations is an order of magnitude away from it. Measured on a source-level
 * emulation of the confirmed miscompile (the intra-iteration read of `acc`
 * resolving to the dead pre-loop slot), 9.3% of generated `k2-cross-read`
 * cases flip their verdict with this comparator; adding a wide absolute
 * literal arm DROPPED that to 3.3% by diluting the carrier-relative draws.
 */
function arbCarrierClause(carriers: string[], bigintVars: string[]): fc.Arbitrary<Expr> {
  const rhs = arbBoundedBigintExpr(bigintVars, 1);
  return fc
    .tuple(
      ...carriers.map((c) =>
        fc
          .tuple(fc.constantFrom(...EXEC_CMP_OPS), rhs)
          .map(([op, right]): Expr => ({
            kind: 'binary',
            op,
            left: { kind: 'var_ref', name: c },
            right,
          })),
      ),
    )
    .map((clauses) =>
      (clauses as Expr[]).reduce((left, right): Expr => ({
        kind: 'binary',
        op: '&&',
        left,
        right,
      })),
    );
}

/** A local (never property) assignment statement. */
function localAssign(name: string, value: Expr): Stmt {
  return { kind: 'assign', target: name, value, isProperty: false };
}

/**
 * A branch condition that can go EITHER way at runtime. The left operand is
 * always a real variable reference, never a literal: a condition of two
 * literals is erased by the constant folder before stack lowering, which would
 * put the branch shape in the corpus and never in front of the code under test
 * (the same trap `arbExecStructure`'s "guarantee ONE runtime bigint" fix-up
 * documents for loop bodies).
 */
function arbBranchCond(bigintVars: string[]): fc.Arbitrary<Expr> {
  return fc
    .tuple(
      fc.constantFrom(...bigintVars),
      fc.constantFrom(...EXEC_CMP_OPS),
      arbAdditiveExpr(bigintVars, 1),
    )
    .map(([v, op, right]): Expr => ({ kind: 'binary', op, left: bigintVarRef(v), right }));
}

/**
 * The branch block itself. `m0`/`m1` are the merged locals, `msib` is declared
 * alongside them and rebound by nothing — see `ExecBranchShape`.
 */
function arbBranchBlock(shape: ExecBranchShape, bigintVars: string[]): fc.Arbitrary<IfStmt> {
  const arm = (): fc.Arbitrary<Expr> => arbAdditiveExpr(bigintVars, 1);
  const cond = (): fc.Arbitrary<Expr> => arbBranchCond(bigintVars);

  if (shape === 'flat-if') {
    return fc
      .tuple(cond(), arm(), arm())
      .map(([condition, a0, a1]): IfStmt => ({
        kind: 'if',
        condition,
        then: [localAssign(EXEC_M0, a0), localAssign(EXEC_M1, a1)],
      }));
  }
  if (shape === 'if-else') {
    return fc
      .tuple(cond(), arm(), arm(), arm(), arm())
      .map(([condition, a0, a1, b0, b1]): IfStmt => ({
        kind: 'if',
        condition,
        then: [localAssign(EXEC_M0, a0), localAssign(EXEC_M1, a1)],
        else_: [localAssign(EXEC_M0, b0), localAssign(EXEC_M1, b1)],
      }));
  }
  // 'nested-arm-sibling' — the issue-#149 shape. The inner `if` keeps a REAL
  // else (the confirmed #149 inner `if` had one); the OUTER `if` deliberately
  // has none, so its fall-through path preserves the pre-branch layout while
  // the taken path rotates it.
  return fc
    .tuple(cond(), cond(), arm(), arm())
    .map(([outer, inner, a0, b0]): IfStmt => ({
      kind: 'if',
      condition: outer,
      then: [
        {
          kind: 'if',
          condition: inner,
          then: [localAssign(EXEC_M0, a0)],
          else_: [localAssign(EXEC_M0, b0)],
        },
      ],
    }));
}

/**
 * The terminal clause that makes a branch-region slot rotation VISIBLE.
 *
 * Both conjuncts are ORDER-SENSITIVE between distinct branch locals, which the
 * rest of the terminal assert is not: `arbParamClause` / `arbExtraClause` /
 * `arbCarrierClause` all compare a COMMUTATIVE sum (`a + b <cmp> rhs`) against
 * a threshold, so a pure swap of `a` and `b` leaves the value — and therefore
 * the verdict — identical, and the oracle reports agreement on a script that
 * read the wrong slots.
 *
 *   `m0 <op> m1`                      inverts under ANY m0/m1 transposition
 *                                     with distinct values.
 *   `m0 * K + m1  <op>  msib + atom`  a mixed-radix combination (K >= 2) that
 *                                     no permutation of the three branch
 *                                     locals leaves fixed, and which reads
 *                                     `msib` so the sibling stays LIVE.
 */
function arbBranchClause(bigintVars: string[]): fc.Arbitrary<Expr> {
  const v = (name: string): Expr => ({ kind: 'var_ref', name });
  return fc
    .tuple(
      fc.constantFrom(...EXEC_ORDER_CMP_OPS),
      fc.constantFrom(...EXEC_ORDER_CMP_OPS),
      fc.integer({ min: 2, max: 8 }),
      arbBigintAtom(bigintVars),
    )
    .map(([opPair, opRadix, k, atom]): Expr => ({
      kind: 'binary',
      op: '&&',
      left: { kind: 'binary', op: opPair, left: v(EXEC_M0), right: v(EXEC_M1) },
      right: {
        kind: 'binary',
        op: opRadix,
        left: {
          kind: 'binary',
          op: '+',
          left: {
            kind: 'binary',
            op: '*',
            left: v(EXEC_M0),
            right: { kind: 'bigint_literal', value: BigInt(k) },
          },
          right: v(EXEC_M1),
        },
        right: { kind: 'binary', op: '+', left: v(EXEC_MSIB), right: atom },
      },
    }));
}

/**
 * Generate the body of the single exec-oracle method for the given
 * props/params. `forceLoopShape` pins the loop topology (and forces a loop to
 * be present) — used by `arbExecCaseWithLoopShape` so a seeded test can prove
 * each shape is produced instead of arguing from probability.
 * `forceBranchShape` does the same for the branch topology.
 */
function arbExecMethodBody(
  props: GeneratedProperty[],
  params: GeneratedParam[],
  forceLoopShape?: ExecLoopShape,
  forceBranchShape?: ExecBranchShape | 'none',
): fc.Arbitrary<{
  body: Stmt[];
  loopShape: ExecLoopShape | null;
  branchShape: ExecBranchShape | null;
}> {
  const bigintPropParamVars = [
    ...props.filter((p) => p.type === 'bigint').map((p) => `this.${p.name}`),
    ...params.filter((p) => p.type === 'bigint').map((p) => p.name),
  ];
  const bytesBase: BytesVar[] = [
    ...props
      .filter((p) => p.type === 'ByteString')
      .map((p): BytesVar => ({ ref: { kind: 'property_ref', name: p.name }, minLen: EXEC_BYTES_LEN })),
    ...params
      .filter((p) => p.type === 'ByteString')
      .map((p): BytesVar => ({ ref: { kind: 'var_ref', name: p.name }, minLen: EXEC_BYTES_LEN })),
  ];

  return fc
    .record({
      accInit: arbAdditiveExpr(bigintPropParamVars, 1),
      waccInit: arbAdditiveExpr(bigintPropParamVars, 1),
      includeLoop: forceLoopShape !== undefined ? fc.constant(true) : fc.boolean(),
      loop: (forceLoopShape !== undefined
        ? fc.constant(forceLoopShape)
        : fc.constantFrom(...EXEC_LOOP_SHAPES)
      ).chain((shape) =>
        arbForLoop(shape, bigintPropParamVars).map((stmt) => ({ shape, stmt })),
      ),
      includeBranch:
        forceBranchShape === 'none'
          ? fc.constant(false)
          : forceBranchShape !== undefined
            ? fc.constant(true)
            : fc.boolean(),
      branchShape:
        forceBranchShape !== undefined && forceBranchShape !== 'none'
          ? fc.constant(forceBranchShape)
          : fc.constantFrom(...EXEC_BRANCH_SHAPES),
      branchInits: fc.tuple(
        arbAdditiveExpr(bigintPropParamVars, 1),
        arbAdditiveExpr(bigintPropParamVars, 1),
        arbAdditiveExpr(bigintPropParamVars, 1),
      ),
      numByteDecls: bytesBase.length > 0 ? fc.integer({ min: 0, max: 2 }) : fc.constant(0),
      byteExprs: fc.array(arbBytesExpr(bytesBase.length > 0 ? bytesBase : [{ ref: { kind: 'bigint_literal', value: 0n }, minLen: 0 }], 2), {
        minLength: 0,
        maxLength: 2,
      }),
      paramIdx: fc.integer({ min: 0, max: Math.max(0, params.length - 1) }),
      useExtra: fc.boolean(),
      logicalOp: fc.constantFrom('&&' as const, '||' as const),
      extra: arbExtraClause(['acc', ...bigintPropParamVars], bytesBase),
    })
    .chain((cfg) => {
      const body: Stmt[] = [];
      // Carried locals (mutable so the loop can update them). `acc` is always
      // declared; `wacc` only for the multi-carrier shapes, so no shape leaves
      // a local that nothing in the method ever touches.
      const loopShape = cfg.includeLoop ? cfg.loop.shape : null;
      const carriers = loopShape === null ? [EXEC_ACC] : loopShapeCarriers(loopShape);
      body.push({
        kind: 'var_decl',
        name: EXEC_ACC,
        type: 'bigint',
        value: cfg.accInit,
        mutable: true,
      });
      if (carriers.includes(EXEC_WACC)) {
        body.push({
          kind: 'var_decl',
          name: EXEC_WACC,
          type: 'bigint',
          value: cfg.waccInit,
          mutable: true,
        });
      }
      // Branch-region locals, declared alongside the carriers so the branch
      // block below has an inherited slot region to rearrange. Only declared
      // when a branch is actually drawn — an untouched local would otherwise be
      // eliminated and put a shape in the corpus that never reaches codegen.
      const branchShape = cfg.includeBranch ? cfg.branchShape : null;
      const branchLocals = branchShape === null ? [] : branchShapeLocals(branchShape);
      branchLocals.forEach((name, i) => {
        body.push({
          kind: 'var_decl',
          name,
          type: 'bigint',
          value: cfg.branchInits[i]!,
          mutable: true,
        });
      });

      const bigintVars = [...carriers, ...branchLocals, ...bigintPropParamVars];

      if (cfg.includeLoop) body.push(cfg.loop.stmt);

      // Optional byte-op locals (only meaningful when ByteString vars exist).
      const bytesVars = [...bytesBase];
      if (bytesBase.length > 0) {
        const n = Math.min(cfg.numByteDecls, cfg.byteExprs.length);
        for (let i = 0; i < n; i++) {
          const name = `b${i}`;
          const be = cfg.byteExprs[i]!;
          body.push({ kind: 'var_decl', name, type: 'ByteString', value: be.expr, mutable: false });
          bytesVars.push({ ref: { kind: 'var_ref', name }, minLen: be.minLen });
        }
      }

      // Terminal assert: a guaranteed param read, optionally &&/|| an extra
      // clause, AND — whenever a loop ran — a guaranteed read of every carrier
      // so the loop's result decides the spend verdict.
      const param = params[Math.min(cfg.paramIdx, params.length - 1)]!;
      return fc
        .tuple(
          arbParamClause(param, bigintVars, bytesVars),
          arbCarrierClause(carriers, bigintVars),
          branchShape === null ? fc.constant(null) : arbBranchBlock(branchShape, bigintVars),
          branchShape === null ? fc.constant(null) : arbBranchClause(bigintVars),
        )
        .map(([clause, carrierClause, branchStmt, branchClause]): {
          body: Stmt[];
          loopShape: ExecLoopShape | null;
          branchShape: ExecBranchShape | null;
        } => {
          const base: Expr = cfg.useExtra
            ? { kind: 'binary', op: cfg.logicalOp, left: clause, right: cfg.extra }
            : clause;
          let condition: Expr = cfg.includeLoop
            ? { kind: 'binary', op: '&&', left: base, right: carrierClause }
            : base;
          // The branch block sits AFTER the loop, so the loop's carriers are
          // already settled and the branch rearranges a region that has live
          // neighbours above AND below it.
          const stmts = [...body];
          if (branchStmt !== null) {
            stmts.push(branchStmt);
            // Conjoined LAST: an order-sensitive read of the branch region is
            // what turns a slot rotation into a verdict change.
            condition = { kind: 'binary', op: '&&', left: condition, right: branchClause! };
          }
          return { body: [...stmts, { kind: 'assert', condition }], loopShape, branchShape };
        });
    });
}

/** A random value for a constructor prop / method param of the given type. */
function arbExecValue(type: RuinarType): fc.Arbitrary<ExecArg> {
  if (type === 'boolean') return fc.boolean();
  if (type === 'ByteString') {
    return fc.uint8Array({ minLength: EXEC_BYTES_LEN, maxLength: EXEC_BYTES_LEN });
  }
  // bigint (default)
  return fc.bigInt({ min: -EXEC_INT_MAG, max: EXEC_INT_MAG });
}

const EXEC_PROP_TYPES = ['bigint', 'ByteString'] as const;
const EXEC_PARAM_TYPES = ['bigint', 'boolean', 'ByteString'] as const;

interface ExecStructure {
  contract: GeneratedContract;
  method: GeneratedMethod;
  loopShape: ExecLoopShape | null;
  branchShape: ExecBranchShape | null;
}

/** Generate the structural shell (contract + its single method). */
function arbExecStructure(
  forceLoopShape?: ExecLoopShape,
  forceBranchShape?: ExecBranchShape | 'none',
): fc.Arbitrary<ExecStructure> {
  return fc
  .record({
    name: fc.integer({ min: 0, max: 9999 }).map((n) => `ExecFuzz${n}`),
    propDefs: fc.array(
      fc.tuple(fc.integer({ min: 0, max: 9 }), fc.constantFrom(...EXEC_PROP_TYPES)),
      { minLength: 0, maxLength: 2 },
    ),
    methodName: fc.integer({ min: 0, max: 9 }).map((n) => `run${n}`),
    paramDefs: fc.array(
      fc.tuple(fc.integer({ min: 0, max: 9 }), fc.constantFrom(...EXEC_PARAM_TYPES)),
      { minLength: 1, maxLength: 3 },
    ),
  })
  .chain((s) => {
    // De-dup property names.
    const propSeen = new Set<string>();
    const properties: GeneratedProperty[] = [];
    for (const [n, type] of s.propDefs) {
      let name = `prop${n}`;
      while (propSeen.has(name)) name += 'X';
      propSeen.add(name);
      properties.push({ name, type, readonly: true });
    }
    // De-dup parameter names.
    const paramSeen = new Set<string>();
    const params: GeneratedParam[] = [];
    for (const [n, type] of s.paramDefs) {
      let name = `param${n}`;
      while (paramSeen.has(name)) name += 'X';
      paramSeen.add(name);
      params.push({ name, type });
    }
    // Guarantee ONE runtime bigint. Bounded loops are unrolled, so a case with
    // no bigint prop and no bigint param has a loop body of pure literals that
    // the constant folder erases before stack lowering — the loop shape would
    // be in the corpus and never reach the code under test.
    const hasBigint =
      properties.some((p) => p.type === 'bigint') || params.some((p) => p.type === 'bigint');
    if (!hasBigint) params[0]!.type = 'bigint';
    return arbExecMethodBody(properties, params, forceLoopShape, forceBranchShape).map(
      ({ body, loopShape, branchShape }) => {
        const method: GeneratedMethod = {
          name: s.methodName,
          visibility: 'public',
          params,
          body,
          mutatesState: false,
        };
        const contract: GeneratedContract = {
          name: s.name,
          parentClass: 'SmartContract',
          properties,
          methods: [method],
        };
        return { contract, method, loopShape, branchShape };
      },
    );
  });
}

function arbExecCaseOf(
  forceLoopShape?: ExecLoopShape,
  forceBranchShape?: ExecBranchShape | 'none',
): fc.Arbitrary<ExecCase> {
  return arbExecStructure(forceLoopShape, forceBranchShape).chain(
    ({ contract, method, loopShape, branchShape }) => {
    const ctorEntries = contract.properties.map(
      (p) => [p.name, arbExecValue(p.type)] as const,
    );
    const ctorArb: fc.Arbitrary<Record<string, ExecArg>> =
      ctorEntries.length === 0
        ? fc.constant({})
        : fc.record(Object.fromEntries(ctorEntries) as Record<string, fc.Arbitrary<ExecArg>>);
    const argArbs = method.params.map((p) => arbExecValue(p.type));
    const argsArb: fc.Arbitrary<ExecArg[]> =
      argArbs.length === 0 ? fc.constant([]) : fc.tuple(...argArbs);
    return fc.tuple(ctorArb, argsArb).map(
      ([constructorArgs, args]): ExecCase => ({
        contract,
        method: method.name,
        constructorArgs,
        args,
        loopShape,
        branchShape,
      }),
    );
    },
  );
}

/**
 * A fully-concrete tri-modal execution-oracle case: a stateless contract with
 * loops + byte-ops + post-loop param reads, plus concrete constructor + method
 * inputs. fast-check property mode shrinks both the structure and the inputs to
 * a minimal repro on any tri-modal disagreement.
 */
export const arbExecCase: fc.Arbitrary<ExecCase> = arbExecCaseOf();

/**
 * The same generator with the loop topology PINNED. Only a test uses this: it
 * turns "every shape is reachable" from a probability argument into a
 * deterministic, per-shape assertion (the fast-check analogue of the
 * round-robin family draw in `conformance/fuzzer/spend-shapes.ts`).
 *
 * The branch block is SUPPRESSED here: this probe exists to assert facts about
 * a loop shape's carriers (that the declared mutable locals are EXACTLY that
 * shape's carriers, among others), and a branch block legitimately declares
 * more. Branch topologies get their own pinned probe in
 * `arbExecCaseWithBranchShape`, and the composite `arbExecCase` still draws
 * loops and branches together.
 */
export function arbExecCaseWithLoopShape(shape: ExecLoopShape): fc.Arbitrary<ExecCase> {
  return arbExecCaseOf(shape, 'none');
}

/**
 * The same generator with the BRANCH topology PINNED — the branch-shape
 * analogue of `arbExecCaseWithLoopShape`, and the reason the reachability of
 * `nested-arm-sibling` is a deterministic assertion rather than a probability
 * argument.
 */
export function arbExecCaseWithBranchShape(shape: ExecBranchShape): fc.Arbitrary<ExecCase> {
  return arbExecCaseOf(undefined, shape);
}
