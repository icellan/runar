/**
 * N-065 / N-060 — compiler-reserved names.
 *
 * Several passes mint names into the SAME namespace that user identifiers live
 * in, and every later pass resolves a name by string equality. A user name
 * spelled like a minted one therefore aliases two different values:
 *
 *     let t2: bigint = p; assert(p > 0n); if (c) { t2 = p; } assert(t2 + 1n === 1n);
 *
 * `0n` lowers to the ANF temp `t2`, so with `c = false` the final guard reads
 * the temp (0) instead of the local (p), and the script accepts p = 1, which
 * the source rejects (`@bsv/sdk` Spend, folding OFF — no optimizer involved).
 *
 * The fix is to reserve every name family a pass mints and refuse a program
 * that declares one, with ONE sentence shared verbatim by all seven tiers. No
 * program that compiled before and does not use such a name changes a byte.
 *
 * The minted families, by the pass that mints them (identical in all tiers):
 *
 *   04-anf-lower         t<digits>                ANF temps
 *                        __merge$<digits>         merged-local temps of an if
 *   03b-expand-arrays    <name>__<digits>         FixedArray slot names
 *                        __idx_<digits>, __val_<digits>   hoisted index/value temps
 *   05-stack-lower       _codePart                implicit continuation witness
 *                        __param_<name>           param slot shadowing a mutable property
 *                        __shadowed_<n>_<name>    caller slot shadowed by an inlined param
 *                        _pub_<digits>            Groth16 public-input slots (Go tier)
 *   auto-injected params _changePKH, _changeAmount, _newAmount, _serialisedOutputs,
 *                        _prevOutScript_<digits>, and txPreimage in a
 *                        StatefulSmartContract (a stateless contract declares its
 *                        own txPreimage parameter, so it stays legal there)
 *
 * NOT reserved, and why:
 *   - `<name>@<n>` / `<name>@local` (04-anf-lower alpha-renaming): `@` is not an
 *     identifier character in any of the nine surfaces.
 *   - EC-optimizer names (`<binding>_k`, `<binding>_k_<i>`, ...): F-086 allocates
 *     them against every name the method already uses, so they cannot collide.
 *   - codegen-module slot names (`_p2s<i>`, `fs<i>`, `xsig<i>`, ...): they live in
 *     the module's private stack tracker, never in the method's name map.
 *
 * `--ir` input is ANF, where the ANF-minted names are the normal spelling of a
 * binding, so the IR rule is narrower (see `irReservedName`).
 */

/** The diagnostic, shared verbatim by all seven tiers (source and --ir). */
export function reservedNameMessage(name: string): string {
  return `'${name}' is reserved for compiler-generated names and cannot be used as an identifier`;
}

const STACK_LOWERING_RESERVED: readonly RegExp[] = [
  /^_codePart$/,
  /^__param_/,
  /^__shadowed_/,
  /^_pub_[0-9]+$/,
];

const ANF_BINDING_RESERVED: readonly RegExp[] = [
  /^t[0-9]+$/,
  /^__merge\$[0-9]+$/,
];

const SOURCE_ONLY_RESERVED: readonly RegExp[] = [
  /^.+__[0-9]+$/,
  /^__idx_[0-9]+$/,
  /^__val_[0-9]+$/,
  /^_changePKH$/,
  /^_changeAmount$/,
  /^_newAmount$/,
  /^_serialisedOutputs$/,
  /^_prevOutScript_[0-9]+$/,
];

const matchesAny = (name: string, res: readonly RegExp[]): boolean => res.some((r) => r.test(name));

/**
 * True if a SOURCE program may not declare `name` (property, method, parameter,
 * local or loop variable), after the surface's name mapping.
 */
export function isReservedSourceName(name: string, stateful: boolean): boolean {
  return (
    matchesAny(name, STACK_LOWERING_RESERVED) ||
    matchesAny(name, ANF_BINDING_RESERVED) ||
    matchesAny(name, SOURCE_ONLY_RESERVED) ||
    (stateful && name === 'txPreimage')
  );
}

/**
 * `--ir` rule. `declaration` is true for a property, method, parameter or loop
 * variable name, and for the name a `load_param` / `load_prop` / `update_prop`
 * addresses; false for a binding name and for a binding reference.
 *
 * Every position refuses the names stack lowering mints, which exist in no
 * IR. A declaration also refuses the ANF binding families (`t<digits>`,
 * `__merge$<digits>`): the lowering that mints them never gives one to a
 * parameter, property, method or loop variable.
 */
export function isReservedIrName(name: string, declaration: boolean): boolean {
  return (
    matchesAny(name, STACK_LOWERING_RESERVED) ||
    (declaration && matchesAny(name, ANF_BINDING_RESERVED))
  );
}
