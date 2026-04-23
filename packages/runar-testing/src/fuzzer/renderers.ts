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
  RuinarType,
} from './contract-ir.js';
import {
  toSnakeCase,
  toPascalCase,
  collectUsedFunctions,
  collectUsedTypes,
} from './contract-ir.js';

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
    case 'expr':
      return `${indent}${tsExpr(stmt.expr)};`;
  }
}

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

  // Methods
  lines.push(`#[runar::methods(${contract.name})]`);
  lines.push(`impl ${contract.name} {`);
  for (const method of contract.methods) {
    const selfParam = method.mutatesState ? '&mut self' : '&self';
    const params = method.params.map((p) => `${toSnakeCase(p.name)}: ${rsType(p.type)}`).join(', ');
    const allParams = params ? `${selfParam}, ${params}` : selfParam;

    if (method.visibility === 'public') lines.push('    #[public]');
    lines.push(`    fn ${toSnakeCase(method.name)}(${allParams}) {`);
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
  imports.push('public');

  for (const t of usedTypes) {
    if (t !== 'boolean') imports.push(pyType(t));
  }

  const lines: string[] = [];
  lines.push(`from runar import ${[...new Set(imports)].join(', ')}`);
  lines.push('');

  const base = isStateful ? 'StatefulSmartContract' : 'SmartContract';
  lines.push(`class ${contract.name}(${base}):`);

  // Properties
  for (const prop of contract.properties) {
    lines.push(`    ${toSnakeCase(prop.name)}: ${pyType(prop.type)}`);
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

  // Fields
  for (const prop of contract.properties) {
    const init = prop.initializer ? ` = ${zigExpr(prop.initializer)}` : '';
    lines.push(`    ${prop.name}: ${zigType(prop.type)}${init},`);
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

  // Properties
  for (const prop of contract.properties) {
    lines.push(`  prop :${toSnakeCase(prop.name)}, ${rbType(prop.type)}`);
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
// Format registry
// ---------------------------------------------------------------------------

export type RenderFormat = 'ts' | 'go' | 'rs' | 'py' | 'zig' | 'rb';

export const RENDERERS: Record<RenderFormat, (contract: GeneratedContract) => string> = {
  ts: renderTypeScript,
  go: renderGo,
  rs: renderRust,
  py: renderPython,
  zig: renderZig,
  rb: renderRuby,
};

export const FORMAT_EXTENSIONS: Record<RenderFormat, string> = {
  ts: '.runar.ts',
  go: '.runar.go',
  rs: '.runar.rs',
  py: '.runar.py',
  zig: '.runar.zig',
  rb: '.runar.rb',
};
