/**
 * N-205 (b) — F-286's verifyRabinSig key-provenance rule, and N-205 (a)'s rule
 * for writes to a key property, re-asserted on `--ir` input.
 *
 * `--ir` skips 02-validate, so a hand-written ANF program could bind
 * verifyRabinSig's modulus to a `load_param` (the spender picks n = 1 and
 * forges any message), or write a `load_param` into the mutable key property
 * (`update_prop` / its `add_output` slot) and forge one spend later.
 *
 * The rule is F-286's trust relation, expressed on ANF, so every program the
 * frontend accepts still loads after an `--emit-ir` round trip. A ref is
 * trusted when EVERY binding of that name in the method is:
 *   - `load_prop`;
 *   - `load_const` holding an integer;
 *   - `load_const "@ref:<x>"` with `<x>` trusted (a local alias);
 *   - `load_param` of a PRIVATE method whose every `method_call` site (at
 *     least one) passes a trusted ref in that position (least fixed point);
 *   - an `if` with no `results`, both arms non-empty and each arm's LAST
 *     binding trusted (the phi ANF lowering emits for an if/else property
 *     write).
 * Bindings are resolved over the whole method, flattened in pre-order (a
 * binding, then its `then`, `else`, `body`); a name with no binding, or one
 * reached again while it is being resolved, is untrusted.
 * KEY properties are the `load_prop` names a verifyRabinSig 4th argument can
 * come from (through aliases, `if` arms and private-helper call sites; every
 * method, constructor included), closed under "a trusted value written into a
 * key property comes from it". Writes are, outside the constructor only,
 * `update_prop` and `add_output.stateValues[i]`, which writes the i-th
 * non-readonly property in `properties` order. Then, method by method in
 * program order, the first refusal wins:
 *   1. every verifyRabinSig call (flatten order) whose 4th argument is untrusted;
 *   2. every write (flatten order) of a MUTABLE key property whose value is
 *      untrusted.
 * Refusals, shared verbatim by all seven tiers:
 *   IR validation: method '<m>': <RABIN_PUBKEY_PROVENANCE_MESSAGE>
 *   IR validation: method '<m>': <rabinKeyWriteMessage(prop)>
 */

import type { ANFBinding, ANFMethod, ANFProgram, ANFValue } from './anf-ir.js';
import { RABIN_PUBKEY_PROVENANCE_MESSAGE, rabinKeyWriteMessage } from '../passes/02-validate.js';

function flatten(bindings: readonly ANFBinding[], out: ANFBinding[]): void {
  for (const b of bindings) {
    out.push(b);
    const v = b.value as { then?: ANFBinding[]; else?: ANFBinding[]; body?: ANFBinding[] };
    for (const nested of [v.then, v.else, v.body]) if (nested) flatten(nested, out);
  }
}

export function assertRabinKeyProvenance(program: ANFProgram): void {
  const flat = new Map<ANFMethod, ANFBinding[]>();
  const byName = new Map<ANFMethod, Map<string, ANFValue[]>>();
  for (const m of program.methods) {
    const list: ANFBinding[] = [];
    flatten(m.body, list);
    flat.set(m, list);
    const names = new Map<string, ANFValue[]>();
    for (const b of list) {
      const vs = names.get(b.name) ?? [];
      vs.push(b.value);
      names.set(b.name, vs);
    }
    byName.set(m, names);
  }

  const isPrivate = (m: ANFMethod) => !m.isPublic && m.name !== 'constructor';
  const privates = new Map<string, ANFMethod>();
  for (const m of program.methods) if (isPrivate(m)) privates.set(m.name, m);

  const callSites = new Map<string, { args: string[]; method: ANFMethod }[]>();
  for (const name of privates.keys()) callSites.set(name, []);
  for (const m of program.methods) {
    for (const b of flat.get(m)!) {
      const v = b.value;
      if (v.kind === 'method_call' && privates.has(v.method)) callSites.get(v.method)!.push({ args: v.args, method: m });
    }
  }

  const trustedParams = new Map<string, Set<number>>();
  for (const name of privates.keys()) trustedParams.set(name, new Set());

  const isTrusted = (ref: string, m: ANFMethod, visiting: Set<string>): boolean => {
    const values = byName.get(m)!.get(ref);
    if (values === undefined || visiting.has(ref)) return false;
    visiting.add(ref);
    const ok = values.every((v) => {
      switch (v.kind) {
        case 'load_prop':
          return true;
        case 'load_const':
          if (typeof v.value === 'bigint') return true;
          return typeof v.value === 'string' && v.value.startsWith('@ref:') && isTrusted(v.value.slice(5), m, visiting);
        case 'load_param': {
          if (!isPrivate(m)) return false;
          const idx = m.params.findIndex((p) => p.name === v.name);
          return idx >= 0 && trustedParams.get(m.name)!.has(idx);
        }
        case 'if': {
          // A single-result `if` (the per-property phi ANF lowering emits for
          // an if/else that writes a property) is its taken arm's last binding.
          if (v.results !== undefined && v.results.length > 0) return false;
          const a = v.then[v.then.length - 1];
          const b = v.else[v.else.length - 1];
          return a !== undefined && b !== undefined && isTrusted(a.name, m, visiting) && isTrusted(b.name, m, visiting);
        }
        default:
          return false;
      }
    });
    visiting.delete(ref);
    return ok;
  };

  let changed = true;
  while (changed) {
    changed = false;
    for (const [name, m] of privates) {
      const sites = callSites.get(name)!;
      if (sites.length === 0) continue;
      const trusted = trustedParams.get(name)!;
      for (let i = 0; i < m.params.length; i++) {
        if (trusted.has(i)) continue;
        if (sites.every((s) => s.args[i] !== undefined && isTrusted(s.args[i]!, s.method, new Set()))) {
          trusted.add(i);
          changed = true;
        }
      }
    }
  }

  const sourcesOf = (ref: string, m: ANFMethod, out: Set<string>, visiting: Set<string>): void => {
    const key = `${m.name}\u0000${ref}`;
    if (visiting.has(key)) return;
    visiting.add(key);
    for (const v of byName.get(m)!.get(ref) ?? []) {
      if (v.kind === 'load_prop') {
        out.add(v.name);
      } else if (v.kind === 'load_const' && typeof v.value === 'string' && v.value.startsWith('@ref:')) {
        sourcesOf(v.value.slice(5), m, out, visiting);
      } else if (v.kind === 'if') {
        for (const arm of [v.then, v.else]) {
          const last = arm[arm.length - 1];
          if (last !== undefined) sourcesOf(last.name, m, out, visiting);
        }
      } else if (v.kind === 'load_param' && isPrivate(m)) {
        const idx = m.params.findIndex((p) => p.name === v.name);
        for (const site of callSites.get(m.name) ?? []) {
          const arg = site.args[idx];
          if (arg !== undefined) sourcesOf(arg, site.method, out, visiting);
        }
      }
    }
  };

  const keyProps = new Set<string>();
  for (const m of program.methods) {
    for (const b of flat.get(m)!) {
      const v = b.value;
      if (v.kind === 'call' && v.func === 'verifyRabinSig' && v.args.length >= 4) {
        sourcesOf(v.args[3]!, m, keyProps, new Set());
      }
    }
  }

  const mutableProps = program.properties.filter((p) => !p.readonly).map((p) => p.name);
  const writes: { prop: string; value: string; method: ANFMethod }[] = [];
  for (const m of program.methods) {
    if (m.name === 'constructor') continue;
    for (const b of flat.get(m)!) {
      const v = b.value;
      if (v.kind === 'update_prop') writes.push({ prop: v.name, value: v.value, method: m });
      if (v.kind === 'add_output') {
        v.stateValues.forEach((value, i) => {
          const prop = mutableProps[i];
          if (prop !== undefined) writes.push({ prop, value, method: m });
        });
      }
    }
  }

  let grew = true;
  while (grew) {
    const before = keyProps.size;
    for (const w of writes) {
      if (keyProps.has(w.prop) && isTrusted(w.value, w.method, new Set())) {
        sourcesOf(w.value, w.method, keyProps, new Set());
      }
    }
    grew = keyProps.size !== before;
  }

  const mutable = new Set(mutableProps);
  for (const m of program.methods) {
    for (const b of flat.get(m)!) {
      const v = b.value;
      if (v.kind === 'call' && v.func === 'verifyRabinSig' && v.args.length >= 4 && !isTrusted(v.args[3]!, m, new Set())) {
        throw new Error(`IR validation: method '${m.name}': ${RABIN_PUBKEY_PROVENANCE_MESSAGE}`);
      }
    }
    for (const w of writes) {
      if (w.method !== m || !keyProps.has(w.prop) || !mutable.has(w.prop)) continue;
      if (!isTrusted(w.value, m, new Set())) {
        throw new Error(`IR validation: method '${m.name}': ${rabinKeyWriteMessage(w.prop)}`);
      }
    }
  }
}
