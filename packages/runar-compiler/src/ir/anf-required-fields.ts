/**
 * N-069 — presence and JSON type of the ANF IR's required fields, checked on
 * the raw parsed document before anything reads it as an `ANFProgram`.
 *
 * `--ir` input comes from outside the compiler. A public method whose `body`
 * was left out used to load as a method with zero bindings, and in two tiers
 * (Zig, Ruby) compiled to an anyone-can-spend locking script at exit 0; a
 * wrongly typed field surfaced as a raw runtime error (`bindings is not
 * iterable`) or, for a missing method `name`, was accepted outright.
 *
 * The required set is `anf-ir.schema.json`'s `required` keys, minus the ones
 * every loader deliberately defaults for older payloads (`loop.start`,
 * `loop.step`, `add_output.preimage`). Value-level rules (loop count range,
 * raw_script hex, builtin arity, unknown kinds) are checked elsewhere.
 *
 * The diagnostics are shared verbatim with the other six tiers (Java's F-084
 * loader is the origin) and pinned by
 * `conformance/negatives/ir-required-fields.test.ts`:
 *   IR validation: required field <path> is missing
 *   IR validation: <path> must be <a type>, got <json type>
 */

type Obj = Record<string, unknown>;

function jsonType(v: unknown): string {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'string') return 'string';
  if (typeof v === 'boolean') return 'boolean';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'object') return 'object';
  return 'number';
}

function fieldPath(path: string, key: string): string {
  return path === '' ? key : `${path}.${key}`;
}

function malformed(path: string, expected: string, got: unknown): Error {
  return new Error(`IR validation: ${path} must be ${expected}, got ${jsonType(got)}`);
}

/** Absence and a JSON null are both "missing". */
function req(obj: Obj, key: string, path: string): unknown {
  const v = obj[key];
  if (v === undefined || v === null) {
    throw new Error(`IR validation: required field ${fieldPath(path, key)} is missing`);
  }
  return v;
}

function reqString(obj: Obj, key: string, path: string): void {
  const v = req(obj, key, path);
  if (typeof v !== 'string') throw malformed(fieldPath(path, key), 'a string', v);
}

function reqBool(obj: Obj, key: string, path: string): void {
  const v = req(obj, key, path);
  if (typeof v !== 'boolean') throw malformed(fieldPath(path, key), 'a boolean', v);
}

function reqArray(obj: Obj, key: string, path: string): unknown[] {
  const v = req(obj, key, path);
  if (!Array.isArray(v)) throw malformed(fieldPath(path, key), 'an array', v);
  return v;
}

function asObject(v: unknown, path: string): Obj {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw malformed(path, 'an object', v);
  }
  return v as Obj;
}

function reqStringArray(obj: Obj, key: string, path: string): void {
  const lp = fieldPath(path, key);
  reqArray(obj, key, path).forEach((e, i) => {
    if (typeof e !== 'string') throw malformed(`${lp}[${i}]`, 'a string', e);
  });
}

function checkBindings(obj: Obj, key: string, path: string): void {
  const lp = fieldPath(path, key);
  reqArray(obj, key, path).forEach((b, i) => {
    const bp = `${lp}[${i}]`;
    const binding = asObject(b, bp);
    reqString(binding, 'name', bp);
    checkValue(asObject(binding.value, `${bp}.value`), `${bp}.value`);
  });
}

function checkValue(v: Obj, path: string): void {
  reqString(v, 'kind', path);
  switch (v.kind) {
    case 'load_param':
    case 'load_prop':
      reqString(v, 'name', path);
      break;
    case 'bin_op':
      reqString(v, 'op', path);
      reqString(v, 'left', path);
      reqString(v, 'right', path);
      break;
    case 'unary_op':
      reqString(v, 'op', path);
      reqString(v, 'operand', path);
      break;
    case 'call':
      reqString(v, 'func', path);
      reqStringArray(v, 'args', path);
      break;
    case 'method_call':
      reqString(v, 'object', path);
      reqString(v, 'method', path);
      reqStringArray(v, 'args', path);
      break;
    case 'if':
      reqString(v, 'cond', path);
      checkBindings(v, 'then', path);
      checkBindings(v, 'else', path);
      if ('results' in v) reqStringArray(v, 'results', path);
      break;
    case 'loop':
      checkBindings(v, 'body', path);
      reqString(v, 'iterVar', path);
      break;
    case 'assert':
      reqString(v, 'value', path);
      break;
    case 'update_prop':
      reqString(v, 'name', path);
      reqString(v, 'value', path);
      break;
    case 'check_preimage':
    case 'deserialize_state':
      reqString(v, 'preimage', path);
      break;
    case 'add_output':
      reqString(v, 'satoshis', path);
      reqStringArray(v, 'stateValues', path);
      break;
    case 'add_raw_output':
    case 'add_data_output':
      reqString(v, 'satoshis', path);
      reqString(v, 'scriptBytes', path);
      break;
    case 'array_literal':
      reqStringArray(v, 'elements', path);
      break;
    default:
      // load_const, get_state_script, raw_script: their fields are decoded and
      // checked by the value-level rules. Unknown kinds are refused elsewhere.
      break;
  }
}

/** Throw on the first required field that is missing or of the wrong JSON type. */
export function assertRequiredIrFields(root: unknown): void {
  const program = asObject(root, 'the IR document');
  reqString(program, 'contractName', '');
  reqArray(program, 'properties', '').forEach((p, i) => {
    const pp = `properties[${i}]`;
    const prop = asObject(p, pp);
    reqString(prop, 'name', pp);
    reqString(prop, 'type', pp);
    reqBool(prop, 'readonly', pp);
  });
  reqArray(program, 'methods', '').forEach((m, i) => {
    const mp = `methods[${i}]`;
    const method = asObject(m, mp);
    reqString(method, 'name', mp);
    reqBool(method, 'isPublic', mp);
    reqArray(method, 'params', mp).forEach((p, j) => {
      const pp = `${mp}.params[${j}]`;
      const param = asObject(p, pp);
      reqString(param, 'name', pp);
      reqString(param, 'type', pp);
    });
    checkBindings(method, 'body', mp);
  });
}
