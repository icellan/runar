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

/** N-208: an OPTIONAL string field. Absent or JSON null is legal; a present
 * value of any other type is refused rather than silently read as the
 * field's "not set" behaviour (see the three callers below). */
function optStr(obj: Obj, key: string, path: string): void {
  const v = obj[key];
  if (v === undefined || v === null) return;
  if (typeof v !== 'string') throw malformed(fieldPath(path, key), 'a string', v);
}

/** N-208: an OPTIONAL boolean field, same absent/null rule as `optStr`. */
function optBool(obj: Obj, key: string, path: string): void {
  const v = obj[key];
  if (v === undefined || v === null) return;
  if (typeof v !== 'boolean') throw malformed(fieldPath(path, key), 'a boolean', v);
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
      // N-208: a non-string `result_type` (e.g. a number) used to read the
      // same as a genuinely absent field, silently discarding the "bytes"
      // hint and lowering the comparison as numeric instead of
      // byte-equality -- a different script with no diagnostic.
      optStr(v, 'result_type', path);
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
      // N-208: a non-bool `isAutoInjectedStateCheck` (e.g. the string
      // "true") used to compare unequal to `true` and silently become
      // `false` -- the off-chain SDK interpreters that skip THIS assert
      // based on the marker would then stop skipping it, with no
      // diagnostic.
      optBool(v, 'isAutoInjectedStateCheck', path);
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
      // N-208: `preimage` is deliberately NOT required here (see the module
      // docstring -- it is one of the fields every loader defaults for
      // older payloads), but a PRESENT value of the wrong type used to be
      // accepted unchecked and fed into ref-collection, where a non-string
      // ref can never match a real binding name.
      optStr(v, 'preimage', path);
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

/**
 * F-038 / F-065: the two OPTIONAL program/method keys the artifact copies into
 * the fields the SDK signs by. Absent (or null) is legal — IR written before
 * they existed — but a present value must be one the source path can produce:
 * an unknown parentClass or a FORKID-less sigHashType would otherwise reach
 * the artifact and steer the SDK into a spend the script rejects. Shared
 * verbatim with the other six tiers.
 */
const PARENT_CLASSES = ['SmartContract', 'StatefulSmartContract', 'UnsafeSmartContract'];
const SIGHASH_TYPES = [0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3];

function optParentClass(obj: Obj): void {
  const v = obj.parentClass;
  if (v === undefined || v === null) return;
  if (typeof v !== 'string') throw malformed('parentClass', 'a string', v);
  if (!PARENT_CLASSES.includes(v)) {
    throw new Error(
      `IR validation: parentClass must be one of ${PARENT_CLASSES.join(', ')}, got ${v}`,
    );
  }
}

function optSigHashType(obj: Obj, path: string): void {
  const v = obj.sigHashType;
  if (v === undefined || v === null) return;
  const lp = fieldPath(path, 'sigHashType');
  if (typeof v !== 'number') throw malformed(lp, 'an integer', v);
  if (!SIGHASH_TYPES.includes(v)) {
    throw new Error(`IR validation: ${lp} must be one of ${SIGHASH_TYPES.join(', ')}, got ${v}`);
  }
}

/**
 * N-059 / F-102 (F-068 in Go): a `check_preimage` binding's optional
 * `sighashFlag`, at every nesting depth. Codegen appends `sighashFlag & 0xff`
 * to the OP_PUSH_TX binding, so an out-of-set value was truncated to a byte no
 * BSV spend can satisfy (999999 -> 0x3F, FORKID clear) and an explicit 0
 * emitted a 0x00 byte. Absent (or null) means the default ALL|FORKID. In a
 * public method the flag must also equal the method's `sigHashType` (default
 * 0x41): the artifact tells the SDK to sign under `sigHashType`, the script
 * derives its sighash under the flag, and a divergence is unspendable. Both
 * diagnostics are shared verbatim with the other six tiers.
 */
const SIGHASH_DEFAULT = 0x41;

function checkSighashFlags(
  obj: Obj,
  key: string,
  path: string,
  method: string,
  isPublic: boolean,
  declared: number,
): void {
  const lp = fieldPath(path, key);
  (obj[key] as Obj[]).forEach((binding, i) => {
    const vp = `${lp}[${i}].value`;
    const v = binding.value as Obj;
    if (v.kind === 'if') {
      checkSighashFlags(v, 'then', vp, method, isPublic, declared);
      checkSighashFlags(v, 'else', vp, method, isPublic, declared);
    } else if (v.kind === 'loop') {
      checkSighashFlags(v, 'body', vp, method, isPublic, declared);
    } else if (v.kind === 'check_preimage') {
      let flag = SIGHASH_DEFAULT;
      if (v.sighashFlag !== undefined && v.sighashFlag !== null) {
        if (typeof v.sighashFlag !== 'number') {
          throw malformed(fieldPath(vp, 'sighashFlag'), 'an integer', v.sighashFlag);
        }
        flag = v.sighashFlag;
        if (!SIGHASH_TYPES.includes(flag)) {
          throw new Error(
            `IR validation: method ${method} binding ${binding.name as string} check_preimage has sighashFlag ${flag}; ` +
              'sighashFlag must be one of {0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3} (ALL/NONE/SINGLE with FORKID, ' +
              'optionally ANYONECANPAY). Any other value is truncated to a sighash byte no BSV spend can satisfy.',
          );
        }
      }
      if (isPublic && flag !== declared) {
        throw new Error(
          `IR validation: method ${method} binding ${binding.name as string} check_preimage has sighashFlag ${flag} ` +
            `but the method declares sigHashType ${declared}; a public method's check_preimage must bind ` +
            'the sighash type its ABI declares, or the SDK signs a preimage the script rejects.',
        );
      }
    }
  });
}

/** Throw on the first required field that is missing or of the wrong JSON type. */
export function assertRequiredIrFields(root: unknown): void {
  const program = asObject(root, 'the IR document');
  reqString(program, 'contractName', '');
  optParentClass(program);
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
    optSigHashType(method, mp);
    reqArray(method, 'params', mp).forEach((p, j) => {
      const pp = `${mp}.params[${j}]`;
      const param = asObject(p, pp);
      reqString(param, 'name', pp);
      reqString(param, 'type', pp);
    });
    checkBindings(method, 'body', mp);
    const declared = typeof method.sigHashType === 'number' ? method.sigHashType : SIGHASH_DEFAULT;
    checkSighashFlags(method, 'body', mp, method.name as string, method.isPublic as boolean, declared);
  });
  assertIrIdentifiers(program);
  assertNoOutputHelperCalls(program);
}

/**
 * N-094: a `method_call` to a PRIVATE method that emits outputs is refused at
 * load time. The frontends always inline an output-emitting private helper, so
 * such a call only arrives through hand-written `--ir`; stack lowering cannot
 * resolve the helper's `add_output` outside its caller's frame and used to
 * fail deep inside ("value '_codePart' not found on stack"). Runs after the
 * type walk, so every field read here has the right JSON type. Shared verbatim
 * with the other six tiers and pinned by
 * `conformance/negatives/n094-ir-output-helper-call-parity.test.ts`:
 *   IR validation: private method '<m>' emits outputs and must be inlined;
 *   --ir method_call to it is not supported
 */
const OUTPUT_KINDS = ['add_output', 'add_raw_output', 'add_data_output'];

function emitsOutputs(bindings: Obj[]): boolean {
  return bindings.some((b) => {
    const v = b.value as Obj;
    if (OUTPUT_KINDS.includes(v.kind as string)) return true;
    if (v.kind === 'if') return emitsOutputs(v.then as Obj[]) || emitsOutputs(v.else as Obj[]);
    if (v.kind === 'loop') return emitsOutputs(v.body as Obj[]);
    return false;
  });
}

function refuseOutputHelperCalls(bindings: Obj[], helpers: Set<string>): void {
  for (const b of bindings) {
    const v = b.value as Obj;
    if (v.kind === 'method_call' && helpers.has(v.method as string)) {
      throw new Error(
        `IR validation: private method '${v.method as string}' emits outputs and must be inlined; ` +
          '--ir method_call to it is not supported',
      );
    }
    if (v.kind === 'if') {
      refuseOutputHelperCalls(v.then as Obj[], helpers);
      refuseOutputHelperCalls(v.else as Obj[], helpers);
    } else if (v.kind === 'loop') {
      refuseOutputHelperCalls(v.body as Obj[], helpers);
    }
  }
}

function assertNoOutputHelperCalls(program: Obj): void {
  const methods = program.methods as Obj[];
  const helpers = new Set<string>();
  for (const m of methods) {
    if (m.isPublic === false && emitsOutputs(m.body as Obj[])) helpers.add(m.name as string);
  }
  if (helpers.size === 0) return;
  for (const m of methods) refuseOutputHelperCalls(m.body as Obj[], helpers);
}

/**
 * N-207: the declared identifiers are non-empty, and a method's parameter
 * names are distinct. Runs after the type walk above, so every field read
 * here is a string. `""` is a string, so N-069 alone let an empty name
 * through; and duplicate param names alias ONE stack slot — every
 * `load_param` resolves to the last declared one, so `assert(p0 === p1)`
 * over two params of the same name compiled to an always-true script.
 * Diagnostics shared verbatim with the other six tiers and pinned by
 * `conformance/negatives/ir-identifiers.test.ts`:
 *   IR validation: <path> must be a non-empty string
 *   IR validation: <path>.name '<name>' duplicates <earlier path>.name
 */
function nonEmpty(obj: Obj, key: string, path: string): void {
  if (obj[key] === '') {
    throw new Error(`IR validation: ${fieldPath(path, key)} must be a non-empty string`);
  }
}

/**
 * N-408: a binding's name is non-empty, at every nesting level (a method body,
 * an `if` arm, a `loop` body). The path is the one `checkBindings` walks:
 * `methods[0].body[1].value.then[0].name`. Shared with the other six tiers.
 */
function nonEmptyBindingNames(obj: Obj, key: string, path: string): void {
  const lp = fieldPath(path, key);
  (obj[key] as Obj[]).forEach((b, i) => {
    const bp = `${lp}[${i}]`;
    nonEmpty(b, 'name', bp);
    const value = b.value as Obj;
    const vp = `${bp}.value`;
    nonEmpty(value, 'kind', vp);
    if (value.kind === 'if') {
      nonEmptyBindingNames(value, 'then', vp);
      nonEmptyBindingNames(value, 'else', vp);
    } else if (value.kind === 'loop') {
      nonEmptyBindingNames(value, 'body', vp);
    }
  });
}

function assertIrIdentifiers(program: Obj): void {
  nonEmpty(program, 'contractName', '');
  (program.properties as Obj[]).forEach((prop, i) => {
    nonEmpty(prop, 'name', `properties[${i}]`);
    nonEmpty(prop, 'type', `properties[${i}]`);
  });
  (program.methods as Obj[]).forEach((method, i) => {
    const mp = `methods[${i}]`;
    nonEmpty(method, 'name', mp);
    const seen = new Map<string, number>();
    (method.params as Obj[]).forEach((param, j) => {
      const pp = `${mp}.params[${j}]`;
      nonEmpty(param, 'name', pp);
      nonEmpty(param, 'type', pp);
      const name = param.name as string;
      const first = seen.get(name);
      if (first !== undefined) {
        throw new Error(
          `IR validation: ${pp}.name '${name}' duplicates ${mp}.params[${first}].name`,
        );
      }
      seen.set(name, j);
    });
    nonEmptyBindingNames(method, 'body', mp);
  });
}
