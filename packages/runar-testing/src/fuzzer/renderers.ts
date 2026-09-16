/**
 * Multi-format source code renderers for generated Rúnar contracts.
 *
 * Each renderer takes a GeneratedContract IR and produces valid source code
 * in the target language format.
 */

import type {
  GeneratedContract,
  GeneratedProperty as _GeneratedProperty,
  GeneratedParam as _GeneratedParam,
  GeneratedMethod as _GeneratedMethod,
  Expr,
  Stmt,
  ForStmt,
  RuinarType,
} from './contract-ir.js';
import {
  toSnakeCase,
  toPascalCase,
  collectUsedFunctions,
  collectUsedTypes,
} from './contract-ir.js';

// ---------------------------------------------------------------------------
// Loop rendering — the CROSS-TIER SUBSET
// ---------------------------------------------------------------------------
//
// Until 2026-08 the six non-TS renderers refused every `ForStmt`: loops were
// exec-oracle-only (issue #124, TypeScript-rendered), so the `--ir` cross-tier
// parity fuzzer had never compiled a single loop in any tier. A lowering fix
// that moved bytes identically across all seven tiers was therefore invisible
// to it. They now render loops — but only the form EVERY surface syntax can
// express losslessly, which is narrower than `ForStmt` itself:
//
//   * Rust DSL loops are `for i in start..end` (`parser_rustmacro.rs`) — a
//     half-open ascending range. There is no `.rev()` and no `..=`, so
//     countdowns and `<=` bounds have NO Rust surface form.
//   * Zig loops are `var i: i64 = S; while (i < N) : (i += 1)`, and the
//     `var` decl must IMMEDIATELY precede the `while` for `parse_zig.zig`'s
//     parseBlock to merge the two into one ForStmt.
//
// So the native renderers accept `step: 1` + `op: '<'` and reject anything
// else loudly, rather than emit per-language loop syntax whose 7-tier parity
// has never been demonstrated. The exec-oracle shapes that need a countdown or
// an inclusive bound are still TypeScript-only.
const FOR_STMT_UNSUPPORTED =
  'ForStmt form is exec-oracle-only (issue #124): the native cross-tier ' +
  'renderers express only ascending unit-step half-open loops ' +
  "(step: 1, op: '<'). Render this contract to TypeScript via " +
  'renderTypeScript instead.';

/** Throw unless `stmt` is in the cross-tier-renderable loop subset. */
function requireNativeLoopForm(stmt: ForStmt): void {
  if (stmt.step !== 1 || stmt.op !== '<') throw new Error(FOR_STMT_UNSUPPORTED);
}

// ---------------------------------------------------------------------------
// TypeScript renderer (.runar.ts)
// ---------------------------------------------------------------------------

function tsType(t: RuinarType): string {
  return t; // TypeScript uses the same type names
}

function tsExpr(expr: Expr): string {
  switch (expr.kind) {
    case 'bigint_literal': return `${expr.value}n`;
    case 'bool_literal': return String(expr.value);
    case 'bytestring_literal': return `toByteString('${expr.hex}')`;
    case 'var_ref': return expr.name;
    case 'property_ref': return `this.${expr.name}`;
    case 'binary': return `(${tsExpr(expr.left)} ${expr.op} ${tsExpr(expr.right)})`;
    case 'unary': return `${expr.op}(${tsExpr(expr.operand)})`;
    case 'call': return `${expr.fn}(${expr.args.map(tsExpr).join(', ')})`;
    case 'ternary': return `(${tsExpr(expr.condition)} ? ${tsExpr(expr.consequent)} : ${tsExpr(expr.alternate)})`;
  }
}

function tsStmt(stmt: Stmt, indent: string): string {
  switch (stmt.kind) {
    case 'var_decl': {
      const kw = stmt.mutable ? 'let' : 'const';
      return `${indent}${kw} ${stmt.name}: ${tsType(stmt.type)} = ${tsExpr(stmt.value)};`;
    }
    case 'assert':
      return `${indent}assert(${tsExpr(stmt.condition)});`;
    case 'assign':
      return stmt.isProperty
        ? `${indent}this.${stmt.target} = ${tsExpr(stmt.value)};`
        : `${indent}${stmt.target} = ${tsExpr(stmt.value)};`;
    case 'if': {
      const lines = [`${indent}if (${tsExpr(stmt.condition)}) {`];
      for (const s of stmt.then) lines.push(tsStmt(s, indent + '  '));
      if (stmt.else_ && stmt.else_.length > 0) {
        lines.push(`${indent}} else {`);
        for (const s of stmt.else_) lines.push(tsStmt(s, indent + '  '));
      }
      lines.push(`${indent}}`);
      return lines.join('\n');
    }
    case 'for': {
      const upd = stmt.step === 1 ? '++' : '--';
      const lines = [
        `${indent}for (let ${stmt.iterVar}: bigint = ${stmt.start}n; ` +
          `${stmt.iterVar} ${stmt.op} ${stmt.bound}n; ${stmt.iterVar}${upd}) {`,
      ];
      for (const s of stmt.body) lines.push(tsStmt(s, indent + '  '));
      lines.push(`${indent}}`);
      return lines.join('\n');
    }
    case 'add_output': {
      const args = [`${stmt.satoshis}n`, ...stmt.values.map(tsExpr)].join(', ');
      return `${indent}this.addOutput(${args});`;
    }
    case 'expr':
      return `${indent}${tsExpr(stmt.expr)};`;
  }
}

// ---------------------------------------------------------------------------
// READONLY PARITY — every renderer must carry `GeneratedProperty.readonly`
// ---------------------------------------------------------------------------
//
// A property's readonly-ness is not cosmetic: on a StatefulSmartContract it
// decides whether the property joins the serialized state or is baked into the
// code part, which changes the emitted script BYTES. Under `--render native`
// each tier compiles its OWN rendered source, so a renderer that drops the
// marker hands that tier a semantically DIFFERENT contract, and the resulting
// "cross-tier divergence" is a fuzzer artifact rather than a compiler bug.
//
// Until 2026-08 exactly that was true: renderPython, renderZig and renderRuby
// emitted every property as mutable. The three-way split it produced
// ({ts,go,rust,java} vs {python,ruby} vs {zig} — Zig differing again because
// `01-parse-zig.ts` INFERS readonly for stateful properties no method mutates)
// was invisible because the `--ir` PR gate ran without `--hex`. Each renderer
// now emits its format's marker whenever `prop.readonly` is set:
//
//   TypeScript  `readonly x: bigint`        Go      `X int64 \`runar:"readonly"\``
//   Rust        `#[readonly]`               Python  `x: Readonly[Bigint]`
//   Zig         `x: runar.Readonly(i64)`    Ruby    `prop :x, Bigint, readonly: true`
//   Java        `@Readonly long x`
//
// Stateless contracts mark every property readonly in every frontend anyway, so
// the marker is redundant (never wrong) there.
export function renderTypeScript(contract: GeneratedContract): string {
  const usedFns = collectUsedFunctions(contract);
  const usedTypes = collectUsedTypes(contract);

  // Build imports
  const valueImports: string[] = [contract.parentClass, 'assert'];
  if (usedFns.has('hash160')) valueImports.push('hash160');
  if (usedFns.has('sha256')) valueImports.push('sha256');
  if (usedFns.has('hash256')) valueImports.push('hash256');
  if (usedFns.has('ripemd160')) valueImports.push('ripemd160');
  if (usedFns.has('checkSig')) valueImports.push('checkSig');
  if (usedFns.has('len')) valueImports.push('len');
  if (usedFns.has('cat')) valueImports.push('cat');
  if (usedFns.has('substr')) valueImports.push('substr');
  if (usedFns.has('split')) valueImports.push('split');
  if (usedFns.has('reverseBytes')) valueImports.push('reverseBytes');
  if (usedFns.has('abs')) valueImports.push('abs');
  if (usedFns.has('min')) valueImports.push('min');
  if (usedFns.has('max')) valueImports.push('max');
  if (usedFns.has('within')) valueImports.push('within');
  if (usedFns.has('safediv')) valueImports.push('safediv');
  if (usedFns.has('safemod')) valueImports.push('safemod');
  if (usedTypes.has('ByteString') || contract.properties.some(p => p.initializer?.kind === 'bytestring_literal')) {
    valueImports.push('toByteString');
  }

  // Type imports
  const typeImports: string[] = [];
  for (const t of usedTypes) {
    if (t !== 'bigint' && t !== 'boolean') typeImports.push(t);
  }

  const lines: string[] = [];
  lines.push(`import { ${[...new Set(valueImports)].join(', ')} } from 'runar-lang';`);
  if (typeImports.length > 0) {
    lines.push(`import type { ${typeImports.join(', ')} } from 'runar-lang';`);
  }
  lines.push('');

  // Class declaration
  lines.push(`class ${contract.name} extends ${contract.parentClass} {`);

  // Properties
  for (const prop of contract.properties) {
    const prefix = prop.readonly ? 'readonly ' : '';
    const init = prop.initializer ? ` = ${tsExpr(prop.initializer)}` : '';
    lines.push(`  ${prefix}${prop.name}: ${tsType(prop.type)}${init};`);
  }
  lines.push('');

  // Constructor
  const ctorProps = contract.properties.filter((p) => !p.initializer);
  const ctorParams = ctorProps.map((p) => `${p.name}: ${tsType(p.type)}`).join(', ');
  const superArgs = contract.properties.map((p) => p.initializer ? tsExpr(p.initializer) : p.name).join(', ');
  lines.push(`  constructor(${ctorParams}) {`);
  lines.push(`    super(${superArgs});`);
  for (const p of ctorProps) {
    lines.push(`    this.${p.name} = ${p.name};`);
  }
  lines.push('  }');

  // Methods
  for (const method of contract.methods) {
    lines.push('');
    const params = method.params.map((p) => `${p.name}: ${tsType(p.type)}`).join(', ');
    lines.push(`  ${method.visibility} ${method.name}(${params}): void {`);
    for (const stmt of method.body) {
      lines.push(tsStmt(stmt, '    '));
    }
    lines.push('  }');
  }

  lines.push('}');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Go renderer (.runar.go)
// ---------------------------------------------------------------------------

function goType(t: RuinarType): string {
  switch (t) {
    case 'bigint': return 'runar.Int';
    case 'boolean': return 'runar.Bool';
    case 'ByteString': return 'runar.ByteString';
    case 'PubKey': return 'runar.PubKey';
    case 'Sig': return 'runar.Sig';
    case 'Addr': return 'runar.Addr';
    case 'Sha256': return 'runar.Sha256';
    case 'Ripemd160': return 'runar.Ripemd160';
  }
}

function goFnName(fn: string): string {
  return 'runar.' + toPascalCase(fn);
}

function goExpr(expr: Expr): string {
  switch (expr.kind) {
    case 'bigint_literal': return String(expr.value);
    case 'bool_literal': return String(expr.value);
    case 'bytestring_literal': return `runar.ToByteString("${expr.hex}")`;
    case 'var_ref': return expr.name;
    case 'property_ref': return `c.${toPascalCase(expr.name)}`;
    case 'binary': {
      const op = expr.op === '===' ? '==' : expr.op === '!==' ? '!=' : expr.op === '&&' ? '&&' : expr.op === '||' ? '||' : expr.op;
      return `(${goExpr(expr.left)} ${op} ${goExpr(expr.right)})`;
    }
    case 'unary': return `${expr.op}(${goExpr(expr.operand)})`;
    case 'call': return `${goFnName(expr.fn)}(${expr.args.map(goExpr).join(', ')})`;
    case 'ternary': {
      // Go has no ternary — use a helper or if/else.
      // For fuzzer simplicity, use inline func pattern
      return `func() ${goType('bigint')} { if ${goExpr(expr.condition)} { return ${goExpr(expr.consequent)} }; return ${goExpr(expr.alternate)} }()`;
    }
  }
}

function goStmt(stmt: Stmt, indent: string): string {
  switch (stmt.kind) {
    case 'var_decl':
      return `${indent}${stmt.name} := ${goExpr(stmt.value)}`;
    case 'assert':
      return `${indent}runar.Assert(${goExpr(stmt.condition)})`;
    case 'assign':
      return stmt.isProperty
        ? `${indent}c.${toPascalCase(stmt.target)} = ${goExpr(stmt.value)}`
        : `${indent}${stmt.target} = ${goExpr(stmt.value)}`;
    case 'if': {
      const lines = [`${indent}if ${goExpr(stmt.condition)} {`];
      for (const s of stmt.then) lines.push(goStmt(s, indent + '\t'));
      if (stmt.else_ && stmt.else_.length > 0) {
        lines.push(`${indent}} else {`);
        for (const s of stmt.else_) lines.push(goStmt(s, indent + '\t'));
      }
      lines.push(`${indent}}`);
      return lines.join('\n');
    }
    case 'for': {
      requireNativeLoopForm(stmt);
      const lines = [
        `${indent}for ${stmt.iterVar} := runar.Int(${stmt.start}); ` +
          `${stmt.iterVar} < ${stmt.bound}; ${stmt.iterVar}++ {`,
      ];
      for (const s of stmt.body) lines.push(goStmt(s, indent + '\t'));
      lines.push(`${indent}}`);
      return lines.join('\n');
    }
    case 'add_output': {
      const args = [String(stmt.satoshis), ...stmt.values.map(goExpr)].join(', ');
      return `${indent}c.AddOutput(${args})`;
    }
    case 'expr':
      return `${indent}${goExpr(stmt.expr)}`;
  }
}

export function renderGo(contract: GeneratedContract): string {
  const isStateful = contract.parentClass === 'StatefulSmartContract';
  const embed = isStateful ? 'runar.StatefulSmartContract' : 'runar.SmartContract';

  const lines: string[] = [];
  lines.push('package contract');
  lines.push('');
  lines.push('import "runar"');
  lines.push('');

  // Struct
  lines.push(`type ${contract.name} struct {`);
  lines.push(`\t${embed}`);
  for (const prop of contract.properties) {
    const tag = prop.readonly ? ' `runar:"readonly"`' : '';
    lines.push(`\t${toPascalCase(prop.name)} ${goType(prop.type)}${tag}`);
  }
  lines.push('}');

  // Methods
  for (const method of contract.methods) {
    lines.push('');
    const params = method.params.map((p) => `${p.name} ${goType(p.type)}`).join(', ');
    lines.push(`func (c *${contract.name}) ${toPascalCase(method.name)}(${params}) {`);
    for (const stmt of method.body) {
      lines.push(goStmt(stmt, '\t'));
    }
    lines.push('}');
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Rust renderer (.runar.rs)
// ---------------------------------------------------------------------------

function rsType(t: RuinarType): string {
  switch (t) {
    case 'bigint': return 'Int';
    case 'boolean': return 'bool';
    default: return t;
  }
}

function rsFnName(fn: string): string {
  return toSnakeCase(fn);
}

function rsExpr(expr: Expr): string {
  switch (expr.kind) {
    case 'bigint_literal': return String(expr.value);
    case 'bool_literal': return String(expr.value);
    case 'bytestring_literal': return `to_byte_string("${expr.hex}")`;
    case 'var_ref': return expr.name;
    case 'property_ref': return `self.${toSnakeCase(expr.name)}`;
    case 'binary': {
      const op = expr.op === '===' ? '==' : expr.op === '!==' ? '!=' : expr.op;
      return `(${rsExpr(expr.left)} ${op} ${rsExpr(expr.right)})`;
    }
    case 'unary': return `${expr.op}(${rsExpr(expr.operand)})`;
    case 'call': return `${rsFnName(expr.fn)}(${expr.args.map(rsExpr).join(', ')})`;
    case 'ternary':
      return `if ${rsExpr(expr.condition)} { ${rsExpr(expr.consequent)} } else { ${rsExpr(expr.alternate)} }`;
  }
}

function rsStmt(stmt: Stmt, indent: string): string {
  switch (stmt.kind) {
    case 'var_decl': {
      const kw = stmt.mutable ? 'let mut' : 'let';
      return `${indent}${kw} ${stmt.name} = ${rsExpr(stmt.value)};`;
    }
    case 'assert':
      return `${indent}assert!(${rsExpr(stmt.condition)});`;
    case 'assign':
      return stmt.isProperty
        ? `${indent}self.${toSnakeCase(stmt.target)} = ${rsExpr(stmt.value)};`
        : `${indent}${stmt.target} = ${rsExpr(stmt.value)};`;
    case 'if': {
      const lines = [`${indent}if ${rsExpr(stmt.condition)} {`];
      for (const s of stmt.then) lines.push(rsStmt(s, indent + '    '));
      if (stmt.else_ && stmt.else_.length > 0) {
        lines.push(`${indent}} else {`);
        for (const s of stmt.else_) lines.push(rsStmt(s, indent + '    '));
      }
      lines.push(`${indent}}`);
      return lines.join('\n');
    }
    case 'for': {
      requireNativeLoopForm(stmt);
      const lines = [`${indent}for ${stmt.iterVar} in ${stmt.start}..${stmt.bound} {`];
      for (const s of stmt.body) lines.push(rsStmt(s, indent + '    '));
      lines.push(`${indent}}`);
      return lines.join('\n');
    }
    case 'add_output': {
      const args = [String(stmt.satoshis), ...stmt.values.map(rsExpr)].join(', ');
      return `${indent}self.add_output(${args});`;
    }
    case 'expr':
      return `${indent}${rsExpr(stmt.expr)};`;
  }
}

export function renderRust(contract: GeneratedContract): string {
  const lines: string[] = [];
  lines.push('use runar::prelude::*;');
  lines.push('');

  // Struct
  lines.push('#[runar::contract]');
  lines.push(`struct ${contract.name} {`);
  for (const prop of contract.properties) {
    if (prop.readonly) lines.push('    #[readonly]');
    lines.push(`    ${toSnakeCase(prop.name)}: ${rsType(prop.type)},`);
  }
  lines.push('}');
  lines.push('');

  // Methods — bare `impl` block; `pub fn` marks public spending entry points.
  lines.push(`impl ${contract.name} {`);
  for (const method of contract.methods) {
    const selfParam = method.mutatesState ? '&mut self' : '&self';
    const params = method.params.map((p) => `${toSnakeCase(p.name)}: ${rsType(p.type)}`).join(', ');
    const allParams = params ? `${selfParam}, ${params}` : selfParam;

    const fnKeyword = method.visibility === 'public' ? 'pub fn' : 'fn';
    lines.push(`    ${fnKeyword} ${toSnakeCase(method.name)}(${allParams}) {`);
    for (const stmt of method.body) {
      lines.push(rsStmt(stmt, '        '));
    }
    lines.push('    }');
    lines.push('');
  }
  lines.push('}');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Python renderer (.runar.py)
// ---------------------------------------------------------------------------

function pyType(t: RuinarType): string {
  switch (t) {
    case 'bigint': return 'Bigint';
    case 'boolean': return 'bool';
    default: return t;
  }
}

function pyFnName(fn: string): string {
  return toSnakeCase(fn);
}

function pyExpr(expr: Expr): string {
  switch (expr.kind) {
    case 'bigint_literal': return String(expr.value);
    case 'bool_literal': return expr.value ? 'True' : 'False';
    case 'bytestring_literal': return `to_byte_string('${expr.hex}')`;
    case 'var_ref': return toSnakeCase(expr.name);
    case 'property_ref': return `self.${toSnakeCase(expr.name)}`;
    case 'binary': {
      let op = expr.op;
      if (op === '===') op = '==' as typeof op;
      else if (op === '!==') op = '!=' as typeof op;
      else if (op === '&&') op = 'and' as typeof op;
      else if (op === '||') op = 'or' as typeof op;
      else if (op === '/') op = '//' as typeof op;
      return `(${pyExpr(expr.left)} ${op} ${pyExpr(expr.right)})`;
    }
    case 'unary': {
      const op = expr.op === '!' ? 'not ' : expr.op;
      return `${op}(${pyExpr(expr.operand)})`;
    }
    case 'call': return `${pyFnName(expr.fn)}(${expr.args.map(pyExpr).join(', ')})`;
    case 'ternary':
      return `(${pyExpr(expr.consequent)} if ${pyExpr(expr.condition)} else ${pyExpr(expr.alternate)})`;
  }
}

function pyStmt(stmt: Stmt, indent: string): string {
  switch (stmt.kind) {
    case 'var_decl':
      return `${indent}${toSnakeCase(stmt.name)}: ${pyType(stmt.type)} = ${pyExpr(stmt.value)}`;
    case 'assert':
      return `${indent}assert_(${pyExpr(stmt.condition)})`;
    case 'assign':
      return stmt.isProperty
        ? `${indent}self.${toSnakeCase(stmt.target)} = ${pyExpr(stmt.value)}`
        : `${indent}${toSnakeCase(stmt.target)} = ${pyExpr(stmt.value)}`;
    case 'if': {
      const lines = [`${indent}if ${pyExpr(stmt.condition)}:`];
      for (const s of stmt.then) lines.push(pyStmt(s, indent + '    '));
      if (stmt.then.length === 0) lines.push(`${indent}    pass`);
      if (stmt.else_ && stmt.else_.length > 0) {
        lines.push(`${indent}else:`);
        for (const s of stmt.else_) lines.push(pyStmt(s, indent + '    '));
      }
      return lines.join('\n');
    }
    case 'for': {
      requireNativeLoopForm(stmt);
      const lines = [`${indent}for ${toSnakeCase(stmt.iterVar)} in range(${stmt.start}, ${stmt.bound}):`];
      for (const s of stmt.body) lines.push(pyStmt(s, indent + '    '));
      if (stmt.body.length === 0) lines.push(`${indent}    pass`);
      return lines.join('\n');
    }
    case 'add_output': {
      const args = [String(stmt.satoshis), ...stmt.values.map(pyExpr)].join(', ');
      return `${indent}self.add_output(${args})`;
    }
    case 'expr':
      return `${indent}${pyExpr(stmt.expr)}`;
  }
}

export function renderPython(contract: GeneratedContract): string {
  const usedFns = collectUsedFunctions(contract);
  const usedTypes = collectUsedTypes(contract);
  const isStateful = contract.parentClass === 'StatefulSmartContract';

  // Build imports
  const imports: string[] = [isStateful ? 'StatefulSmartContract' : 'SmartContract'];
  imports.push('assert_');
  if (usedFns.has('hash160')) imports.push('hash160');
  if (usedFns.has('sha256')) imports.push('sha256');
  if (usedFns.has('hash256')) imports.push('hash256');
  if (usedFns.has('checkSig')) imports.push('check_sig');
  if (usedFns.has('safediv')) imports.push('safediv');
  if (usedFns.has('safemod')) imports.push('safemod');
  if (usedFns.has('abs')) imports.push('abs');
  if (usedFns.has('min')) imports.push('min');
  if (usedFns.has('max')) imports.push('max');
  if (usedFns.has('within')) imports.push('within');
  if (usedFns.has('len')) imports.push('len');
  if (usedFns.has('cat')) imports.push('cat');
  if (usedFns.has('substr')) imports.push('substr');
  if (usedFns.has('split')) imports.push('split');
  if (usedFns.has('reverseBytes')) imports.push('reverse_bytes');
  imports.push('public');
  if (contract.properties.some((p) => p.readonly)) imports.push('Readonly');

  for (const t of usedTypes) {
    if (t !== 'boolean') imports.push(pyType(t));
  }

  const lines: string[] = [];
  lines.push(`from runar import ${[...new Set(imports)].join(', ')}`);
  lines.push('');

  const base = isStateful ? 'StatefulSmartContract' : 'SmartContract';
  lines.push(`class ${contract.name}(${base}):`);

  // Properties. `Readonly[T]` must be rendered whenever the IR marks the
  // property readonly — see the READONLY PARITY note above `renderTypeScript`.
  for (const prop of contract.properties) {
    const t = prop.readonly ? `Readonly[${pyType(prop.type)}]` : pyType(prop.type);
    lines.push(`    ${toSnakeCase(prop.name)}: ${t}`);
  }
  lines.push('');

  // Constructor
  const ctorProps = contract.properties.filter((p) => !p.initializer);
  const ctorParams = ctorProps.map((p) => `${toSnakeCase(p.name)}: ${pyType(p.type)}`).join(', ');
  const selfParams = ctorParams ? `self, ${ctorParams}` : 'self';
  lines.push(`    def __init__(${selfParams}):`);
  const superArgs = contract.properties.map((p) =>
    p.initializer ? pyExpr(p.initializer) : toSnakeCase(p.name)
  ).join(', ');
  lines.push(`        super().__init__(${superArgs})`);
  for (const p of ctorProps) {
    lines.push(`        self.${toSnakeCase(p.name)} = ${toSnakeCase(p.name)}`);
  }
  lines.push('');

  // Methods
  for (const method of contract.methods) {
    const params = method.params.map((p) => `${toSnakeCase(p.name)}: ${pyType(p.type)}`).join(', ');
    const allParams = params ? `self, ${params}` : 'self';

    lines.push('    @public');
    lines.push(`    def ${toSnakeCase(method.name)}(${allParams}):`);
    if (method.body.length === 0) {
      lines.push('        pass');
    } else {
      for (const stmt of method.body) {
        lines.push(pyStmt(stmt, '        '));
      }
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Zig renderer (.runar.zig)
// ---------------------------------------------------------------------------

function zigType(t: RuinarType): string {
  switch (t) {
    case 'bigint': return 'i64';
    case 'boolean': return 'bool';
    case 'ByteString': return 'runar.ByteString';
    case 'PubKey': return 'runar.PubKey';
    case 'Sig': return 'runar.Sig';
    case 'Addr': return 'runar.Addr';
    case 'Sha256': return 'runar.Sha256';
    case 'Ripemd160': return 'runar.Ripemd160';
  }
}

function zigExpr(expr: Expr): string {
  switch (expr.kind) {
    case 'bigint_literal': return String(expr.value);
    case 'bool_literal': return String(expr.value);
    case 'bytestring_literal': return `runar.toByteString("${expr.hex}")`;
    case 'var_ref': return expr.name;
    case 'property_ref': return `self.${expr.name}`;
    case 'binary': {
      const op = expr.op === '===' ? '==' : expr.op === '!==' ? '!=' : expr.op === '/' ? undefined : expr.op;
      if (op === undefined) {
        return `@divTrunc(${zigExpr(expr.left)}, ${zigExpr(expr.right)})`;
      }
      if (expr.op === '&&') return `(${zigExpr(expr.left)} and ${zigExpr(expr.right)})`;
      if (expr.op === '||') return `(${zigExpr(expr.left)} or ${zigExpr(expr.right)})`;
      return `(${zigExpr(expr.left)} ${op} ${zigExpr(expr.right)})`;
    }
    case 'unary': return `${expr.op === '!' ? '!' : '-'}(${zigExpr(expr.operand)})`;
    case 'call': return `runar.${expr.fn}(${expr.args.map(zigExpr).join(', ')})`;
    case 'ternary':
      return `if (${zigExpr(expr.condition)}) ${zigExpr(expr.consequent)} else ${zigExpr(expr.alternate)}`;
  }
}

function zigStmt(stmt: Stmt, indent: string): string {
  switch (stmt.kind) {
    case 'var_decl': {
      const kw = stmt.mutable ? 'var' : 'const';
      return `${indent}${kw} ${stmt.name} = ${zigExpr(stmt.value)};`;
    }
    case 'assert':
      return `${indent}runar.assert(${zigExpr(stmt.condition)});`;
    case 'assign':
      return stmt.isProperty
        ? `${indent}self.${stmt.target} = ${zigExpr(stmt.value)};`
        : `${indent}${stmt.target} = ${zigExpr(stmt.value)};`;
    case 'if': {
      const lines = [`${indent}if (${zigExpr(stmt.condition)}) {`];
      for (const s of stmt.then) lines.push(zigStmt(s, indent + '    '));
      if (stmt.else_ && stmt.else_.length > 0) {
        lines.push(`${indent}} else {`);
        for (const s of stmt.else_) lines.push(zigStmt(s, indent + '    '));
      }
      lines.push(`${indent}}`);
      return lines.join('\n');
    }
    case 'for': {
      requireNativeLoopForm(stmt);
      // `parse_zig.zig`'s parseBlock merges a `var <iter>` decl into the
      // FOLLOWING `while` only when the two are adjacent in the same block, so
      // the declaration is emitted here rather than hoisted.
      const lines = [
        `${indent}var ${stmt.iterVar}: i64 = ${stmt.start};`,
        `${indent}while (${stmt.iterVar} < ${stmt.bound}) : (${stmt.iterVar} += 1) {`,
      ];
      for (const s of stmt.body) lines.push(zigStmt(s, indent + '    '));
      lines.push(`${indent}}`);
      return lines.join('\n');
    }
    case 'add_output': {
      const args = [String(stmt.satoshis), ...stmt.values.map(zigExpr)].join(', ');
      return `${indent}self.addOutput(${args});`;
    }
    case 'expr':
      return `${indent}${zigExpr(stmt.expr)};`;
  }
}

export function renderZig(contract: GeneratedContract): string {
  const isStateful = contract.parentClass === 'StatefulSmartContract';
  const contractType = isStateful ? 'runar.StatefulSmartContract' : 'runar.SmartContract';

  const lines: string[] = [];
  lines.push('const runar = @import("runar");');
  lines.push('');

  lines.push(`pub const ${contract.name} = struct {`);
  lines.push(`    pub const Contract = ${contractType};`);
  lines.push('');

  // Fields. `runar.Readonly(T)` must be rendered whenever the IR marks the
  // property readonly — see the READONLY PARITY note above `renderTypeScript`.
  for (const prop of contract.properties) {
    const init = prop.initializer ? ` = ${zigExpr(prop.initializer)}` : '';
    const t = prop.readonly ? `runar.Readonly(${zigType(prop.type)})` : zigType(prop.type);
    lines.push(`    ${prop.name}: ${t}${init},`);
  }
  lines.push('');

  // Init function (constructor)
  const ctorProps = contract.properties.filter((p) => !p.initializer);
  const ctorParams = ctorProps.map((p) => `${p.name}: ${zigType(p.type)}`).join(', ');
  lines.push(`    pub fn init(${ctorParams}) ${contract.name} {`);
  const fieldInits = contract.properties.map((p) =>
    p.initializer ? `.${p.name} = ${zigExpr(p.initializer)}` : `.${p.name} = ${p.name}`
  ).join(', ');
  lines.push(`        return .{ ${fieldInits} };`);
  lines.push('    }');

  // Methods
  for (const method of contract.methods) {
    lines.push('');
    const selfType = method.mutatesState ? `*${contract.name}` : `*const ${contract.name}`;
    const params = method.params.map((p) => `${p.name}: ${zigType(p.type)}`).join(', ');
    const allParams = params ? `self: ${selfType}, ${params}` : `self: ${selfType}`;
    lines.push(`    pub fn ${method.name}(${allParams}) void {`);
    for (const stmt of method.body) {
      lines.push(zigStmt(stmt, '        '));
    }
    lines.push('    }');
  }

  lines.push('};');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Ruby renderer (.runar.rb)
// ---------------------------------------------------------------------------

function rbType(t: RuinarType): string {
  switch (t) {
    case 'bigint': return 'Bigint';
    case 'boolean': return 'Bool';
    default: return t;
  }
}

function rbExpr(expr: Expr): string {
  switch (expr.kind) {
    case 'bigint_literal': return String(expr.value);
    case 'bool_literal': return String(expr.value);
    case 'bytestring_literal': return `to_byte_string('${expr.hex}')`;
    case 'var_ref': return toSnakeCase(expr.name);
    case 'property_ref': return `@${toSnakeCase(expr.name)}`;
    case 'binary': {
      let op = expr.op;
      if (op === '===') op = '==' as typeof op;
      else if (op === '!==') op = '!=' as typeof op;
      return `(${rbExpr(expr.left)} ${op} ${rbExpr(expr.right)})`;
    }
    case 'unary': return `${expr.op}(${rbExpr(expr.operand)})`;
    case 'call': return `${toSnakeCase(expr.fn)}(${expr.args.map(rbExpr).join(', ')})`;
    case 'ternary':
      return `(${rbExpr(expr.condition)} ? ${rbExpr(expr.consequent)} : ${rbExpr(expr.alternate)})`;
  }
}

function rbStmt(stmt: Stmt, indent: string): string {
  switch (stmt.kind) {
    case 'var_decl':
      return `${indent}${toSnakeCase(stmt.name)} = ${rbExpr(stmt.value)}`;
    case 'assert':
      return `${indent}assert ${rbExpr(stmt.condition)}`;
    case 'assign':
      return stmt.isProperty
        ? `${indent}@${toSnakeCase(stmt.target)} = ${rbExpr(stmt.value)}`
        : `${indent}${toSnakeCase(stmt.target)} = ${rbExpr(stmt.value)}`;
    case 'if': {
      const lines = [`${indent}if ${rbExpr(stmt.condition)}`];
      for (const s of stmt.then) lines.push(rbStmt(s, indent + '  '));
      if (stmt.else_ && stmt.else_.length > 0) {
        lines.push(`${indent}else`);
        for (const s of stmt.else_) lines.push(rbStmt(s, indent + '  '));
      }
      lines.push(`${indent}end`);
      return lines.join('\n');
    }
    case 'for': {
      requireNativeLoopForm(stmt);
      // `...` is Ruby's EXCLUSIVE range — matches the half-open `<` bound.
      const lines = [`${indent}for ${toSnakeCase(stmt.iterVar)} in ${stmt.start}...${stmt.bound}`];
      for (const s of stmt.body) lines.push(rbStmt(s, indent + '  '));
      lines.push(`${indent}end`);
      return lines.join('\n');
    }
    case 'add_output': {
      // Ruby's surface form is a BARE call — `add_output(...)`, no `self.`
      // receiver (see examples/ruby/add-raw-output/RawOutputTest.runar.rb).
      const args = [String(stmt.satoshis), ...stmt.values.map(rbExpr)].join(', ');
      return `${indent}add_output(${args})`;
    }
    case 'expr':
      return `${indent}${rbExpr(stmt.expr)}`;
  }
}

export function renderRuby(contract: GeneratedContract): string {
  const isStateful = contract.parentClass === 'StatefulSmartContract';
  const base = isStateful ? 'Runar::StatefulSmartContract' : 'Runar::SmartContract';

  const lines: string[] = [];
  lines.push("require 'runar'");
  lines.push('');

  lines.push(`class ${contract.name} < ${base}`);

  // Properties. `readonly: true` must be rendered whenever the IR marks the
  // property readonly — see the READONLY PARITY note above `renderTypeScript`.
  for (const prop of contract.properties) {
    const ro = prop.readonly ? ', readonly: true' : '';
    lines.push(`  prop :${toSnakeCase(prop.name)}, ${rbType(prop.type)}${ro}`);
  }
  lines.push('');

  // Constructor
  const ctorProps = contract.properties.filter((p) => !p.initializer);
  const ctorParams = ctorProps.map((p) => toSnakeCase(p.name)).join(', ');
  lines.push(`  def initialize(${ctorParams})`);
  const superArgs = contract.properties.map((p) =>
    p.initializer ? rbExpr(p.initializer) : toSnakeCase(p.name)
  ).join(', ');
  lines.push(`    super(${superArgs})`);
  for (const p of ctorProps) {
    lines.push(`    @${toSnakeCase(p.name)} = ${toSnakeCase(p.name)}`);
  }
  lines.push('  end');

  // Methods
  for (const method of contract.methods) {
    lines.push('');
    const paramTypes = method.params.map((p) => `${toSnakeCase(p.name)}: ${rbType(p.type)}`).join(', ');
    lines.push(`  runar_public ${paramTypes}`);
    const paramNames = method.params.map((p) => toSnakeCase(p.name)).join(', ');
    lines.push(`  def ${toSnakeCase(method.name)}(${paramNames})`);
    for (const stmt of method.body) {
      lines.push(rbStmt(stmt, '    '));
    }
    lines.push('  end');
  }

  lines.push('end');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Java renderer (.runar.java)
// ---------------------------------------------------------------------------
//
// The Java compiler (compilers/java/) parses .runar.java via javac, so every
// contract we produce here must be syntactically valid Java on top of being
// valid Rúnar. The rules:
//
//   * Arithmetic on bigints goes through the Bigint-wrapper methods
//     (.plus/.minus/.times/.gt/.lt/.eq/...). javac does not accept native
//     `+`/`-`/`*` on reference types, and the parser lowers the wrapper calls
//     to the canonical arithmetic AST identically to `a + b` in TypeScript.
//   * Integer literals lower to BigInteger constants via Bigint.of(N);
//     small constants use Bigint.ZERO/ONE/TWO/TEN.
//   * Boolean operators (`&&`, `||`, `!`) and `==`/`!=` on `boolean` work
//     natively. `===`/`!==` (TypeScript strict equality) map to `==`/`!=`.
//   * Builtins are static-imported from `runar.lang.Builtins`.
//   * All fields in a `SmartContract` must be `@Readonly`; mutable fields
//     are only legal on `StatefulSmartContract` (the validator enforces
//     this, matching TS/Python behaviour).

function javaType(t: RuinarType): string {
  switch (t) {
    case 'bigint': return 'Bigint';
    case 'boolean': return 'boolean';
    case 'ByteString': return 'ByteString';
    case 'PubKey': return 'PubKey';
    case 'Sig': return 'Sig';
    case 'Addr': return 'Addr';
    case 'Sha256': return 'Sha256';
    case 'Ripemd160': return 'Ripemd160';
  }
}

/** Javac requires contract identifiers to be valid Java identifiers. */
function javaIdent(name: string): string {
  // The IR generator only produces alphanumerics, but guard anyway.
  return name.replace(/[^A-Za-z0-9_]/g, '_');
}

const JAVA_BIGINT_BIN_METHOD: Partial<Record<string, string>> = {
  '+': 'plus',
  '-': 'minus',
  '*': 'times',
  '/': 'div',
  '%': 'mod',
  '<': 'lt',
  '>': 'gt',
  '<=': 'le',
  '>=': 'ge',
  '===': 'eq',
  '!==': 'neq',
  // Shift/bitwise (C6): JavaParser.java's BIGINT_BINARY_METHODS table maps
  // these exact method names back to Expression.BinaryOp.SHL/SHR/BIT_AND/
  // BIT_OR/BIT_XOR.
  '<<': 'shl',
  '>>': 'shr',
  '&': 'and',
  '|': 'or',
  '^': 'xor',
};

/** Java has no `2n` literal; surface via Bigint.of(N). */
function javaBigintLiteral(value: bigint): string {
  if (value === 0n) return 'Bigint.ZERO';
  if (value === 1n) return 'Bigint.ONE';
  if (value === 2n) return 'Bigint.TWO';
  if (value === 10n) return 'Bigint.TEN';
  // TypeScript's `-N n` literal syntax parses as `UnaryExpr(NEG, BigIntLiteral N)`
  // rather than a single literal with value `-N`, so every other compiler emits
  // a `unary_op -` node around a positive constant. Match that shape exactly by
  // wrapping negatives in `.neg()` — otherwise `Bigint.of(-51L)` would be folded
  // into a single BigIntLiteral(-51) at parse time, diverging from the rest.
  if (value < 0n) return `Bigint.of(${(-value).toString()}L).neg()`;
  return `Bigint.of(${value.toString()}L)`;
}

/** True when `expr` has bigint type in the generated IR. */
function isBigintExpr(expr: Expr): boolean {
  switch (expr.kind) {
    case 'bigint_literal': return true;
    case 'bool_literal': return false;
    case 'bytestring_literal': return false;
    case 'var_ref': return true; // IR generator only emits bigint locals
    case 'property_ref': return true; // callers only use this for bigint props here
    case 'binary': {
      switch (expr.op) {
        case '+': case '-': case '*': case '/': case '%':
        case '<<': case '>>': case '&': case '|': case '^':
          return true;
        default:
          return false; // comparisons / logical ops → boolean
      }
    }
    case 'unary': return expr.op === '-';
    case 'call': {
      // The IR generator only emits bigint-returning builtins here (abs, min, max);
      // hash/check builtins that return non-bigint types aren't used.
      return true;
    }
    case 'ternary': return isBigintExpr(expr.consequent);
  }
}

function javaBigintExpr(expr: Expr, bigintVars: Set<string>, boolVars: Set<string>): string {
  switch (expr.kind) {
    case 'bigint_literal': return javaBigintLiteral(expr.value);
    case 'var_ref': return bigintVars.has(expr.name) ? expr.name : expr.name;
    case 'property_ref': return `this.${expr.name}`;
    case 'binary': {
      const method = JAVA_BIGINT_BIN_METHOD[expr.op];
      if (!method) {
        // Should not happen for bigint-typed expressions, but fall back.
        return `(${javaExpr(expr.left, bigintVars, boolVars)} ${expr.op} ${javaExpr(expr.right, bigintVars, boolVars)})`;
      }
      const left = javaBigintExpr(expr.left, bigintVars, boolVars);
      const right = javaBigintExpr(expr.right, bigintVars, boolVars);
      return `${left}.${method}(${right})`;
    }
    case 'unary':
      if (expr.op === '-') return `${javaBigintExpr(expr.operand, bigintVars, boolVars)}.neg()`;
      return `!(${javaExpr(expr.operand, bigintVars, boolVars)})`;
    case 'call': {
      const args = expr.args.map((a) => javaBigintExpr(a, bigintVars, boolVars)).join(', ');
      return `${expr.fn}(${args})`;
    }
    case 'ternary':
      return `(${javaBoolExpr(expr.condition, bigintVars, boolVars)} ? ${javaBigintExpr(expr.consequent, bigintVars, boolVars)} : ${javaBigintExpr(expr.alternate, bigintVars, boolVars)})`;
    case 'bool_literal': return expr.value ? 'true' : 'false';
    case 'bytestring_literal': return `ByteString.fromHex("${expr.hex}")`;
  }
}

function javaBoolExpr(expr: Expr, bigintVars: Set<string>, boolVars: Set<string>): string {
  switch (expr.kind) {
    case 'bool_literal': return expr.value ? 'true' : 'false';
    case 'var_ref': return expr.name;
    case 'property_ref': return `this.${expr.name}`;
    case 'binary': {
      const op = expr.op;
      if (op === '&&' || op === '||') {
        return `(${javaBoolExpr(expr.left, bigintVars, boolVars)} ${op} ${javaBoolExpr(expr.right, bigintVars, boolVars)})`;
      }
      // Comparisons: both sides are bigint → use Bigint wrapper method
      if (op === '===' || op === '!==' || op === '<' || op === '>' || op === '<=' || op === '>=') {
        const method = JAVA_BIGINT_BIN_METHOD[op];
        if (method) {
          return `${javaBigintExpr(expr.left, bigintVars, boolVars)}.${method}(${javaBigintExpr(expr.right, bigintVars, boolVars)})`;
        }
      }
      return `(${javaExpr(expr.left, bigintVars, boolVars)} ${op} ${javaExpr(expr.right, bigintVars, boolVars)})`;
    }
    case 'unary':
      if (expr.op === '!') return `!(${javaBoolExpr(expr.operand, bigintVars, boolVars)})`;
      return `(${javaBigintExpr(expr.operand, bigintVars, boolVars)}).neg()`;
    case 'ternary':
      return `(${javaBoolExpr(expr.condition, bigintVars, boolVars)} ? ${javaBoolExpr(expr.consequent, bigintVars, boolVars)} : ${javaBoolExpr(expr.alternate, bigintVars, boolVars)})`;
    case 'bigint_literal': return javaBigintLiteral(expr.value); // unusual but well-typed
    case 'call': {
      const args = expr.args.map((a) => javaExpr(a, bigintVars, boolVars)).join(', ');
      return `${expr.fn}(${args})`;
    }
    case 'bytestring_literal': return `ByteString.fromHex("${expr.hex}")`;
  }
}

function javaExpr(expr: Expr, bigintVars: Set<string>, boolVars: Set<string>): string {
  return isBigintExpr(expr)
    ? javaBigintExpr(expr, bigintVars, boolVars)
    : javaBoolExpr(expr, bigintVars, boolVars);
}

function javaStmt(
  stmt: Stmt,
  indent: string,
  bigintVars: Set<string>,
  boolVars: Set<string>,
): string {
  switch (stmt.kind) {
    case 'var_decl': {
      if (stmt.type === 'bigint') bigintVars.add(stmt.name);
      if (stmt.type === 'boolean') boolVars.add(stmt.name);
      const valueSrc = stmt.type === 'boolean'
        ? javaBoolExpr(stmt.value, bigintVars, boolVars)
        : javaBigintExpr(stmt.value, bigintVars, boolVars);
      return `${indent}${javaType(stmt.type)} ${stmt.name} = ${valueSrc};`;
    }
    case 'assert':
      return `${indent}assertThat(${javaBoolExpr(stmt.condition, bigintVars, boolVars)});`;
    case 'assign': {
      // IR generator only targets bigint properties for assigns today; guard anyway.
      const valueSrc = javaBigintExpr(stmt.value, bigintVars, boolVars);
      return stmt.isProperty
        ? `${indent}this.${stmt.target} = ${valueSrc};`
        : `${indent}${stmt.target} = ${valueSrc};`;
    }
    case 'if': {
      const lines = [`${indent}if (${javaBoolExpr(stmt.condition, bigintVars, boolVars)}) {`];
      for (const s of stmt.then) lines.push(javaStmt(s, indent + '    ', bigintVars, boolVars));
      if (stmt.else_ && stmt.else_.length > 0) {
        lines.push(`${indent}} else {`);
        for (const s of stmt.else_) lines.push(javaStmt(s, indent + '    ', bigintVars, boolVars));
      }
      lines.push(`${indent}}`);
      return lines.join('\n');
    }
    case 'for': {
      requireNativeLoopForm(stmt);
      // The loop variable is a bigint in scope for the whole body.
      bigintVars.add(stmt.iterVar);
      const lines = [
        `${indent}for (Bigint ${stmt.iterVar} = ${javaBigintLiteral(stmt.start)}; ` +
          `${stmt.iterVar}.lt(${javaBigintLiteral(stmt.bound)}); ` +
          `${stmt.iterVar} = ${stmt.iterVar}.plus(Bigint.ONE)) {`,
      ];
      for (const s of stmt.body) lines.push(javaStmt(s, indent + '    ', bigintVars, boolVars));
      lines.push(`${indent}}`);
      return lines.join('\n');
    }
    case 'add_output': {
      // The satoshi amount is a plain `long` in the Java surface, NOT a Bigint
      // wrapper (see examples/.../RawOutputTest.runar.java).
      const args = [
        `${stmt.satoshis}L`,
        ...stmt.values.map((v) => javaExpr(v, bigintVars, boolVars)),
      ].join(', ');
      return `${indent}this.addOutput(${args});`;
    }
    case 'expr':
      return `${indent}${javaExpr(stmt.expr, bigintVars, boolVars)};`;
  }
}

export function renderJava(contract: GeneratedContract): string {
  const usedFns = collectUsedFunctions(contract);
  const usedTypes = collectUsedTypes(contract);
  const isStateful = contract.parentClass === 'StatefulSmartContract';
  const contractName = javaIdent(contract.name);

  // Pre-seed locals from properties / method params in each method context.
  const propBigintNames = new Set(
    contract.properties.filter((p) => p.type === 'bigint').map((p) => p.name),
  );
  const propBoolNames = new Set(
    contract.properties.filter((p) => p.type === 'boolean').map((p) => p.name),
  );

  const lines: string[] = [];
  // Package name must be a valid dotted identifier — reuse the (lowercased)
  // contract name as a single package segment.
  lines.push(`package runar.fuzz.${contractName.toLowerCase()};`);
  lines.push('');

  // Imports. Keep the list small; javac is strict about unused imports? No,
  // only warnings. Emit everything we might reference to keep the renderer
  // simple.
  lines.push(`import runar.lang.${isStateful ? 'StatefulSmartContract' : 'SmartContract'};`);
  lines.push('import runar.lang.annotations.Public;');
  lines.push('import runar.lang.annotations.Readonly;');

  // Type imports — we need whichever non-primitive types are used.
  const typeImports = new Set<string>();
  for (const t of usedTypes) {
    if (t === 'boolean') continue;
    typeImports.add(javaType(t));
  }
  // Always import Bigint — used for literals / wrappers.
  typeImports.add('Bigint');
  const sortedTypes = [...typeImports].sort();
  for (const t of sortedTypes) {
    lines.push(`import runar.lang.types.${t};`);
  }

  // Static builtin imports.
  const staticImports = new Set<string>(['assertThat']);
  const knownBuiltins = [
    'abs', 'min', 'max', 'within', 'safediv', 'safemod', 'clamp', 'sign',
    'pow', 'mulDiv', 'percentOf', 'sqrt', 'gcd', 'log2',
    'hash160', 'sha256', 'hash256', 'ripemd160', 'checkSig', 'len', 'cat',
    'substr', 'split', 'reverseBytes',
  ];
  for (const fn of knownBuiltins) {
    if (usedFns.has(fn)) staticImports.add(fn);
  }
  const sortedStatic = [...staticImports].sort();
  for (const fn of sortedStatic) {
    lines.push(`import static runar.lang.Builtins.${fn};`);
  }
  lines.push('');

  // Class declaration.
  const base = isStateful ? 'StatefulSmartContract' : 'SmartContract';
  lines.push(`class ${contractName} extends ${base} {`);
  lines.push('');

  // Fields.
  for (const prop of contract.properties) {
    const readonly = prop.readonly ? '@Readonly ' : '';
    const init = prop.initializer ? ` = ${javaExpr(prop.initializer, propBigintNames, propBoolNames)}` : '';
    lines.push(`    ${readonly}${javaType(prop.type)} ${prop.name}${init};`);
  }
  lines.push('');

  // Constructor.
  const ctorProps = contract.properties.filter((p) => !p.initializer);
  const ctorParams = ctorProps.map((p) => `${javaType(p.type)} ${p.name}`).join(', ');
  const superArgs = contract.properties
    .map((p) => p.initializer ? javaExpr(p.initializer, propBigintNames, propBoolNames) : p.name)
    .join(', ');
  lines.push(`    ${contractName}(${ctorParams}) {`);
  lines.push(`        super(${superArgs});`);
  for (const p of ctorProps) {
    lines.push(`        this.${p.name} = ${p.name};`);
  }
  lines.push('    }');
  lines.push('');

  // Methods.
  for (const method of contract.methods) {
    const bigintVars = new Set<string>(propBigintNames);
    const boolVars = new Set<string>(propBoolNames);
    for (const p of method.params) {
      if (p.type === 'bigint') bigintVars.add(p.name);
      if (p.type === 'boolean') boolVars.add(p.name);
    }

    const params = method.params.map((p) => `${javaType(p.type)} ${p.name}`).join(', ');
    if (method.visibility === 'public') lines.push('    @Public');
    lines.push(`    void ${method.name}(${params}) {`);
    for (const stmt of method.body) {
      lines.push(javaStmt(stmt, '        ', bigintVars, boolVars));
    }
    lines.push('    }');
    lines.push('');
  }

  lines.push('}');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Format registry
// ---------------------------------------------------------------------------

export type RenderFormat = 'ts' | 'go' | 'rs' | 'py' | 'zig' | 'rb' | 'java';

export const RENDERERS: Record<RenderFormat, (contract: GeneratedContract) => string> = {
  ts: renderTypeScript,
  go: renderGo,
  rs: renderRust,
  py: renderPython,
  zig: renderZig,
  rb: renderRuby,
  java: renderJava,
};

export const FORMAT_EXTENSIONS: Record<RenderFormat, string> = {
  ts: '.runar.ts',
  go: '.runar.go',
  rs: '.runar.rs',
  py: '.runar.py',
  zig: '.runar.zig',
  rb: '.runar.rb',
  java: '.runar.java',
};
