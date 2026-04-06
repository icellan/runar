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

function arbIfStmtIR(
  bigintVars: string[],
  boolVars: string[],
): fc.Arbitrary<Stmt> {
  return fc.tuple(
    arbBoolExprIR(bigintVars, boolVars, 1),
    arbAssertStmtIR(bigintVars, boolVars),
    fc.option(arbAssertStmtIR(bigintVars, boolVars)),
  ).map(([condition, thenStmt, elseStmt]): Stmt => ({
    kind: 'if',
    condition,
    then: [thenStmt],
    else_: elseStmt ? [elseStmt] : undefined,
  }));
}

// ---------------------------------------------------------------------------
// IR method and contract generators
// ---------------------------------------------------------------------------

function arbMethodIR(
  properties: GeneratedProperty[],
  config: GeneratorConfig,
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

    return fc.tuple(
      fc.array(arbVarDeclStmtIR(bigintVars), { minLength: 0, maxLength: 2 }),
      fc.array(arbIfStmtIR(bigintVars, boolVars), { minLength: 0, maxLength: 1 }),
      fc.array(arbAssertStmtIR(bigintVars, boolVars), { minLength: 1, maxLength: 2 }),
    ).map(([decls, ifs, asserts]): GeneratedMethod => {
      const body: Stmt[] = [
        ...decls.map((d) => d.stmt),
        ...ifs,
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

    return fc.tuple(
      // State mutations
      fc.array(
        fc.tuple(
          fc.constantFrom(...mutableProps.filter((p) => p.type === 'bigint').map((p) => p.name)),
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
    ).map(([mutations, asserts]): GeneratedMethod => ({
      name,
      visibility: 'public',
      params,
      body: [...asserts, ...mutations],
      mutatesState: true,
    }));
  });
}

/**
 * Generate a random stateless GeneratedContract IR.
 */
export const arbGeneratedContract: fc.Arbitrary<GeneratedContract> = fc
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
      .array(arbMethodIR(properties, DEFAULT_CONFIG), {
        minLength: 1,
        maxLength: DEFAULT_CONFIG.maxMethods,
      })
      .map((methods): GeneratedContract => ({
        name,
        parentClass: 'SmartContract',
        properties,
        methods,
      }));
  });

/**
 * Generate a random stateful GeneratedContract IR.
 */
export const arbGeneratedStatefulContract: fc.Arbitrary<GeneratedContract> = fc
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
      .array(arbStatefulMethodIR(properties, DEFAULT_CONFIG), {
        minLength: 1,
        maxLength: DEFAULT_CONFIG.maxMethods,
      })
      .map((methods): GeneratedContract => ({
        name,
        parentClass: 'StatefulSmartContract',
        properties,
        methods,
      }));
  });
