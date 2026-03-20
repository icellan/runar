// ---------------------------------------------------------------------------
// codegen/common.ts — ABI analysis utilities for code generation
// ---------------------------------------------------------------------------

import type { ABIMethod, RunarArtifact } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Param classification
// ---------------------------------------------------------------------------

export interface ClassifiedParam {
  name: string;
  /** The ABI type string (e.g. "bigint", "Sig", "PubKey") */
  abiType: string;
  /** The TypeScript type to use in generated code */
  tsType: string;
  /** True if this param is auto-computed by the SDK (SigHashPreimage, _changePKH, _changeAmount) */
  hidden: boolean;
}

const TS_TYPE_MAP: Record<string, string> = {
  bigint: 'bigint',
  boolean: 'boolean',
  Sig: 'string | null',
  PubKey: 'string | null',
  ByteString: 'string',
  Addr: 'string',
  Ripemd160: 'string',
  Sha256: 'string',
  Point: 'string',
  SigHashPreimage: 'string | null',
};

/**
 * Map an ABI type to a TypeScript type string.
 * Unknown types fall back to `unknown`.
 */
export function mapTypeToTS(abiType: string): string {
  return TS_TYPE_MAP[abiType] ?? 'unknown';
}

/**
 * Classify a method's params into user-visible and hidden (auto-computed).
 *
 * Hidden params are:
 * - Sig: always auto-computed from the connected signer (two-pass signing)
 * - SigHashPreimage: auto-computed for stateful contracts
 * - _changePKH, _changeAmount: auto-injected by SDK for stateful contracts
 *
 * Hidden params don't appear in the generated method signature.
 * Of these, Sig params are included in the args array as `null` (the SDK
 * auto-computes them), while SigHashPreimage/_changePKH/_changeAmount are
 * entirely SDK-internal and excluded from the args array.
 */
export function classifyParams(method: ABIMethod, isStateful: boolean): ClassifiedParam[] {
  return method.params.map((p) => {
    const hidden =
      p.type === 'Sig' ||
      (isStateful && (
        p.type === 'SigHashPreimage' ||
        p.name === '_changePKH' ||
        p.name === '_changeAmount' ||
        p.name === '_newAmount'
      ));
    return {
      name: p.name,
      abiType: p.type,
      tsType: mapTypeToTS(p.type),
      hidden,
    };
  });
}

/**
 * Get only the user-visible params for a method.
 */
export function getUserParams(method: ABIMethod, isStateful: boolean): ClassifiedParam[] {
  return classifyParams(method, isStateful).filter((p) => !p.hidden);
}

/**
 * Get params that match the SDK's args array — all params except the ones
 * the SDK handles entirely internally (SigHashPreimage, _changePKH,
 * _changeAmount) for stateful contracts.
 *
 * Sig params ARE included (passed as null for auto-computation by the SDK).
 * This matches the SDK's `userParams` filtering in `call()`/`prepareCall()`.
 */
export function getSdkArgParams(method: ABIMethod, isStateful: boolean): ClassifiedParam[] {
  return classifyParams(method, isStateful).filter((p) => {
    if (!isStateful) return true;
    return p.abiType !== 'SigHashPreimage' && p.name !== '_changePKH' && p.name !== '_changeAmount' && p.name !== '_newAmount';
  });
}

// ---------------------------------------------------------------------------
// Terminal detection
// ---------------------------------------------------------------------------

/**
 * Determine if a method is terminal (no state continuation output).
 *
 * Uses the explicit `isTerminal` flag if present, falls back to checking
 * for the absence of `_changePKH` in the params.
 */
export function isTerminalMethod(method: ABIMethod, isStateful: boolean): boolean {
  if (!isStateful) return true; // stateless contracts are always terminal
  if (method.isTerminal !== undefined) return method.isTerminal;
  // Fallback for older artifacts without isTerminal
  return !method.params.some((p) => p.name === '_changePKH');
}

// ---------------------------------------------------------------------------
// Artifact analysis
// ---------------------------------------------------------------------------

export function isStatefulArtifact(artifact: RunarArtifact): boolean {
  return artifact.stateFields !== undefined && artifact.stateFields.length > 0;
}

export function getPublicMethods(artifact: RunarArtifact): ABIMethod[] {
  return artifact.abi.methods.filter((m) => m.isPublic);
}

/** Reserved method names on the generated wrapper class. */
const RESERVED_NAMES = new Set(['connect', 'deploy', 'contract']);

/**
 * Generate a safe method name, avoiding collisions with wrapper class methods.
 */
export function safeMethodName(name: string): string {
  if (RESERVED_NAMES.has(name)) return `call${name.charAt(0).toUpperCase()}${name.slice(1)}`;
  return name;
}

// ---------------------------------------------------------------------------
// Multi-language type maps
// ---------------------------------------------------------------------------

const GO_TYPE_MAP: Record<string, string> = {
  bigint: '*big.Int',
  boolean: 'bool',
  Sig: 'string',
  PubKey: 'string',
  ByteString: 'string',
  Addr: 'string',
  Ripemd160: 'string',
  Sha256: 'string',
  Point: 'string',
  SigHashPreimage: 'string',
};

const RUST_TYPE_MAP: Record<string, string> = {
  bigint: 'BigInt',
  boolean: 'bool',
  Sig: 'String',
  PubKey: 'String',
  ByteString: 'String',
  Addr: 'String',
  Ripemd160: 'String',
  Sha256: 'String',
  Point: 'String',
  SigHashPreimage: 'String',
};

const PYTHON_TYPE_MAP: Record<string, string> = {
  bigint: 'int',
  boolean: 'bool',
  Sig: 'str',
  PubKey: 'str',
  ByteString: 'str',
  Addr: 'str',
  Ripemd160: 'str',
  Sha256: 'str',
  Point: 'str',
  SigHashPreimage: 'str',
};

export function mapTypeToGo(abiType: string): string {
  return GO_TYPE_MAP[abiType] ?? 'interface{}';
}

export function mapTypeToRust(abiType: string): string {
  return RUST_TYPE_MAP[abiType] ?? 'SdkValue';
}

export function mapTypeToPython(abiType: string): string {
  return PYTHON_TYPE_MAP[abiType] ?? 'Any';
}

// ---------------------------------------------------------------------------
// Name conversion utilities
// ---------------------------------------------------------------------------

/** Convert camelCase to PascalCase: "releaseBySeller" → "ReleaseBySeller" */
export function toPascalCase(name: string): string {
  return name.charAt(0).toUpperCase() + name.slice(1);
}

/** Convert camelCase to snake_case: "releaseBySeller" → "release_by_seller" */
export function toSnakeCase(name: string): string {
  return name
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase();
}

// Go reserved names (PascalCase)
const GO_RESERVED = new Set(['Connect', 'Deploy', 'Contract', 'GetLockingScript']);

export function safeGoMethodName(name: string): string {
  const pascal = toPascalCase(name);
  if (GO_RESERVED.has(pascal)) return `Call${pascal}`;
  return pascal;
}

// Rust/Python reserved names (snake_case)
const SNAKE_RESERVED = new Set(['connect', 'deploy', 'contract', 'get_locking_script']);

export function safeRustMethodName(name: string): string {
  const snake = toSnakeCase(name);
  if (SNAKE_RESERVED.has(snake)) return `call_${snake}`;
  return snake;
}

export function safePythonMethodName(name: string): string {
  const snake = toSnakeCase(name);
  if (SNAKE_RESERVED.has(snake)) return `call_${snake}`;
  return snake;
}

// ---------------------------------------------------------------------------
// Rust SdkValue expression builder
// ---------------------------------------------------------------------------

/** Build the Rust expression to convert a typed param into SdkValue. */
export function rustSdkValueExpr(abiType: string, varName: string): string {
  if (abiType === 'bigint') return `SdkValue::BigInt(${varName})`;
  if (abiType === 'boolean') return `SdkValue::Bool(${varName})`;
  // Sig/PubKey/ByteString/Addr/etc. are all hex strings → SdkValue::Bytes
  return `SdkValue::Bytes(${varName})`;
}

// ---------------------------------------------------------------------------
// Codegen context builder
// ---------------------------------------------------------------------------

export type TargetLang = 'ts' | 'go' | 'rust' | 'python';

interface CodegenParam {
  name: string;
  type: string;
  abiType: string;
  isLast: boolean;
}

interface CodegenSigParam {
  name: string;
  argIndex: number;
  isLast: boolean;
}

interface CodegenMethod {
  originalName: string;
  name: string;
  capitalizedName: string;
  isTerminal: boolean;
  isStatefulMethod: boolean;
  hasSigParams: boolean;
  hasUserParams: boolean;
  userParams: CodegenParam[];
  sdkArgsExpr: string;
  sigParams: CodegenSigParam[];
  sigEntriesExpr: string;
  hasPrepareUserParams: boolean;
  prepareUserParams: CodegenParam[];
}

export interface CodegenContext {
  contractName: string;
  contractNameSnake: string;
  isStateful: boolean;
  hasStatefulMethods: boolean;
  hasTerminalMethods: boolean;
  hasConstructorParams: boolean;
  hasBigIntParams: boolean;
  constructorParams: CodegenParam[];
  constructorArgsExpr: string;
  methods: CodegenMethod[];
}

/**
 * Build a codegen context from an artifact for a given target language.
 * This context is consumed by Mustache templates.
 */
export function buildCodegenContext(artifact: RunarArtifact, lang: TargetLang): CodegenContext {
  const isStateful = isStatefulArtifact(artifact);
  const publicMethods = getPublicMethods(artifact);
  const mapType = lang === 'go' ? mapTypeToGo
    : lang === 'rust' ? mapTypeToRust
    : lang === 'python' ? mapTypeToPython
    : mapTypeToTS;

  const safeName = lang === 'go' ? safeGoMethodName
    : lang === 'rust' ? safeRustMethodName
    : lang === 'python' ? safePythonMethodName
    : safeMethodName;

  const nullExpr = lang === 'go' ? 'nil'
    : lang === 'rust' ? 'SdkValue::Auto'
    : lang === 'python' ? 'None'
    : 'null';

  // Constructor params
  const ctorParams = artifact.abi.constructor.params;
  const constructorParams: CodegenParam[] = ctorParams.map((p, i) => ({
    name: lang === 'go' ? toPascalCase(p.name) : (lang === 'rust' || lang === 'python') ? toSnakeCase(p.name) : p.name,
    type: mapType(p.type),
    abiType: p.type,
    isLast: i === ctorParams.length - 1,
  }));

  // Check if any params use BigInt
  let hasBigIntParams = ctorParams.some((p) => p.type === 'bigint');

  // Build constructor args expression
  let constructorArgsExpr: string;
  if (lang === 'rust') {
    constructorArgsExpr = constructorParams
      .map((p) => rustSdkValueExpr(p.abiType, `args.${p.name}`))
      .join(', ');
  } else {
    constructorArgsExpr = constructorParams.map((p) => p.name).join(', ');
  }

  // Methods
  const hasStatefulMethods = isStateful && publicMethods.some((m) => !isTerminalMethod(m, isStateful));
  const hasTerminalMethods = publicMethods.some((m) => isTerminalMethod(m, isStateful));

  const methods: CodegenMethod[] = publicMethods.map((method) => {
    const userParamsRaw = getUserParams(method, isStateful);
    const sdkArgsRaw = getSdkArgParams(method, isStateful);
    const terminal = isTerminalMethod(method, isStateful);
    const methodName = safeName(method.name);

    const userParams: CodegenParam[] = userParamsRaw.map((p, i) => ({
      name: lang === 'go' ? toPascalCase(p.name) : (lang === 'rust' || lang === 'python') ? toSnakeCase(p.name) : p.name,
      type: mapType(p.abiType),
      abiType: p.abiType,
      isLast: i === userParamsRaw.length - 1,
    }));

    if (userParamsRaw.some((p) => p.abiType === 'bigint')) {
      hasBigIntParams = true;
    }

    // SDK args expression
    let sdkArgsExpr: string;
    if (lang === 'rust') {
      sdkArgsExpr = sdkArgsRaw.map((p) => {
        if (p.hidden) return nullExpr;
        const paramName = toSnakeCase(p.name);
        return rustSdkValueExpr(p.abiType, paramName);
      }).join(', ');
    } else {
      sdkArgsExpr = sdkArgsRaw.map((p) => {
        if (p.hidden) return nullExpr;
        return lang === 'go' ? toPascalCase(p.name) : (lang === 'python') ? toSnakeCase(p.name) : p.name;
      }).join(', ');
    }

    // Sig params (for prepare/finalize)
    const sigParamsRaw = sdkArgsRaw.filter((p) => p.abiType === 'Sig');
    const sigParams: CodegenSigParam[] = sigParamsRaw.map((sp, i) => {
      const idx = sdkArgsRaw.findIndex((p) => p.name === sp.name);
      return {
        name: lang === 'go' ? toPascalCase(sp.name) : (lang === 'rust' || lang === 'python') ? toSnakeCase(sp.name) : sp.name,
        argIndex: idx,
        isLast: i === sigParamsRaw.length - 1,
      };
    });

    const sigEntriesExpr = sigParams.map((sp) => `${sp.argIndex}: ${sp.name}`).join(', ');

    // Prepare params (user params minus Sig)
    const prepareUserParams: CodegenParam[] = userParams
      .filter((p) => p.abiType !== 'Sig')
      .map((p, i, arr) => ({ ...p, isLast: i === arr.length - 1 }));

    const capitalizedName = lang === 'go'
      ? methodName
      : (lang === 'rust' || lang === 'python')
        ? toPascalCase(method.name)
        : method.name.charAt(0).toUpperCase() + method.name.slice(1);

    return {
      originalName: method.name,
      name: methodName,
      capitalizedName,
      isTerminal: terminal,
      isStatefulMethod: !terminal && isStateful,
      hasSigParams: sigParams.length > 0,
      hasUserParams: userParams.length > 0,
      userParams,
      sdkArgsExpr,
      sigParams,
      sigEntriesExpr,
      hasPrepareUserParams: prepareUserParams.length > 0,
      prepareUserParams,
    };
  });

  return {
    contractName: artifact.contractName,
    contractNameSnake: toSnakeCase(artifact.contractName),
    isStateful,
    hasStatefulMethods,
    hasTerminalMethods,
    hasConstructorParams: constructorParams.length > 0,
    hasBigIntParams,
    constructorParams,
    constructorArgsExpr,
    methods,
  };
}
