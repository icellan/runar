/**
 * D26: a block-height locktime gate must pin the locktime domain.
 *
 * Consensus reads an nLockTime below 500,000,000 as a block height and one at
 * or above it as a Unix timestamp. A script that asserts
 * `extractLocktime(p) >= H` for a height H is therefore passed by any
 * locktime >= 500,000,000: the transaction is final at once (the time is far
 * below the chain's median time) and the gate never held. The sequence guard
 * (#131, `extractSequence !== 0xffffffff`) does not help.
 *
 * A GATE is a lower-bound compare on a locktime read: `lt >= X`, `lt > X`,
 * `X <= lt`, `X < lt`, where `lt` is `extractLocktime(...)`, a local bound to
 * it, or a private helper's parameter that a call passes it (a DIRECT read).
 * `currentBlockHeight()` is NOT a read here: it asserts its own value
 * `< 500000000` at the call (04-anf-lower.ts), so it is a height by
 * construction. A local bound to both is still read fail-closed (DERIVED). It is not a gate
 * when X is a literal in the timestamp domain (`>= N` with N >= 500000000,
 * `> N` with N >= 499999999): a height-domain locktime can never pass that, so
 * it pins the domain itself, nor for the vacuous `>= 0n` that every locktime
 * passes. A value DERIVED from a read is read fail-closed:
 * any lower-bound compare on it is a gate, whatever X is, and no compare on it
 * is a pin. A value is derived when it comes out of an arithmetic, bitwise or
 * shift operator (`+ - * / % & | ^ << >>`, unary `-` `~`), a ternary arm or a
 * builtin call that takes a read, or out of a local (or helper parameter) of
 * which some binding is not a direct read (`let lt = extractLocktime(p); ...;
 * lt = 0n` makes every use of `lt` derived). Upper-bound and equality compares are not gates
 * (an upper bound fails on its own for a timestamp-domain locktime, and a
 * "not after" bound is the spender's choice anyway).
 *
 * A PIN is an asserted domain bound on a locktime read, in the shape of the
 * #131 sequence guard: the asserted condition itself or a conjunct of its
 * top-level `&&` chain (never under `!` or `||`), against a bigint literal:
 *   height:    `lt < N` (0 < N <= 500000000), `lt <= N` (0 <= N < 500000000)
 *   timestamp: `lt >= N` (N >= 500000000),    `lt > N` (N >= 499999999)
 * and the reversed spellings.
 *
 * The rule is PER PATH, with D18's path walk (continuation-rules.ts) and two
 * bits, gate seen / pin seen: every path through a public method (if arms
 * unioned, a loop body unioned with skipping it, a private helper composed with
 * its exit states) that carries a gate must also carry a pin, before or after
 * it. The --ir path re-derives the same rule from the ANF.
 *
 * Not seen (no gate, so no error): a locktime read that reaches the compare
 * through a private helper's return value.
 */
import type { ANFBinding, ANFMethod, ANFProgram, ANFValue } from '../ir/index.js';
import type { ContractNode, Expression, MethodNode, Statement } from '../ir/index.js';

/** D26: the shared error text. */
export function locktimeDomainMessage(method: string): string {
  return (
    `method '${method}' compares extractLocktime against a lower bound without pinning the locktime domain: ` +
    `consensus reads an nLockTime of 500000000 or more as a Unix timestamp, so on that path any such locktime ` +
    `passes a block-height gate at once. On every path that compares, assert(extractLocktime(preimage) < ` +
    `500000000n) for a block-height gate, or assert(extractLocktime(preimage) >= 500000000n) for a timestamp gate`
  );
}

/** The first nLockTime value consensus reads as a Unix timestamp. */
export const LOCKTIME_THRESHOLD = 500000000n;

/** Path-state bits: gate seen / pin seen. */
const G = 1;
const P = 2;
const unpinned = (states: Iterable<number>): boolean => [...states].some((x) => (x & G) !== 0 && (x & P) === 0);
const orAll = (states: Set<number>, bits: number): Set<number> => new Set([...states].map((x) => x | bits));
const compose = (a: Set<number>, b: Set<number>): Set<number> => {
  const out = new Set<number>();
  for (const x of a) for (const y of b) out.add(x | y);
  return out;
};

type Cmp = '<' | '<=' | '>' | '>=';
const FLIP: Record<Cmp, Cmp> = { '<': '>', '<=': '>=', '>': '<', '>=': '<=' };
const isCmp = (op: string): op is Cmp => op === '<' || op === '<=' || op === '>' || op === '>=';

/**
 * Classify `lt <op> other` (the locktime read on the left). `other` is the
 * literal's value, or null when it is not a bigint literal.
 */
function classify(op: Cmp, other: bigint | null): 'gate' | 'pin' | 'none' {
  if (op === '>=' || op === '>') {
    // `>= 0n` is vacuous (every locktime passes it): no gate. Only literal 0:
    // a negative bound is a negation in source but may be a literal in IR.
    if (op === '>=' && other === 0n) return 'none';
    const ts = other !== null && (op === '>=' ? other >= LOCKTIME_THRESHOLD : other >= LOCKTIME_THRESHOLD - 1n);
    return ts ? 'pin' : 'gate';
  }
  if (other === null) return 'none';
  const height = op === '<' ? other > 0n && other <= LOCKTIME_THRESHOLD : other >= 0n && other < LOCKTIME_THRESHOLD;
  return height ? 'pin' : 'none';
}

/** Taint level of a value: not a locktime read / a direct read / derived from one by arithmetic. */
const NONE = 0;
const DIRECT = 1;
const DERIVED = 2;
/** Binary / unary operators whose result derives from their operands (compares and logic do not). */
const PROPAGATE = new Set(['+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>']);
const PROPAGATE_UNARY = new Set(['-', '~']);

/**
 * Taint of a set of names from their bindings, deterministic and
 * order-blind. `tainted(b, T)`: binding b yields a locktime-derived value when
 * the names in T are tainted; `direct(b, D)`: binding b is a direct read when
 * the names in D are. Least fixpoint for the tainted set, then greatest
 * fixpoint (within it) for the names all of whose bindings are direct reads.
 */
function solveTaint<B>(
  binds: Array<[string, B]>,
  tainted: (b: B, t: Set<string>) => boolean,
  direct: (b: B, d: Set<string>) => boolean,
): Map<string, number> {
  const t = new Set<string>();
  for (let changed = true; changed; ) {
    changed = false;
    for (const [name, b] of binds) {
      if (!t.has(name) && tainted(b, t)) {
        t.add(name);
        changed = true;
      }
    }
  }
  const d = new Set(t);
  for (let changed = true; changed; ) {
    changed = false;
    for (const [name, b] of binds) {
      if (d.has(name) && !direct(b, d)) {
        d.delete(name);
        changed = true;
      }
    }
  }
  return new Map([...t].map((n) => [n, d.has(n) ? DIRECT : DERIVED]));
}

/**
 * Classify a compare given its operands' taint levels: each tainted side is
 * read as the left one. A direct read classifies against the other side's
 * literal; a derived value is a gate under any lower bound and never a pin.
 * A gate on either side wins over a pin.
 */
function classifyCompare<T>(
  op: string,
  left: T,
  right: T,
  level: (x: T) => number,
  literal: (x: T) => bigint | null,
): 'gate' | 'pin' | 'none' {
  if (!isCmp(op)) return 'none';
  const side = (lv: number, o: Cmp, other: T): 'gate' | 'pin' | 'none' => {
    if (lv === DIRECT) return classify(o, literal(other));
    if (lv === DERIVED) return o === '>=' || o === '>' ? 'gate' : 'none';
    return 'none';
  };
  const a = side(level(left), op, right);
  const b = side(level(right), FLIP[op], left);
  if (a === 'gate' || b === 'gate') return 'gate';
  return a === 'pin' || b === 'pin' ? 'pin' : 'none';
}

// ---------------------------------------------------------------------------
// Source path
// ---------------------------------------------------------------------------

/**
 * currentBlockHeight() asserts its own value is below 500000000, so a
 * lower-bound compare of it against a timestamp-domain literal
 * (`currentBlockHeight() >= N` with N >= 500000000, `> N` with
 * N >= 499999999, and the reversed spellings) can never be true: inside an
 * assert the output could never be spent. True iff `method` contains one,
 * anywhere (any statement, any branch). The compared operand is a direct
 * call, or a local every binding of which (declaration or assignment) is a
 * direct call; the bound must be a bigint literal.
 */
export function comparesCurrentBlockHeightToTimestamp(method: MethodNode): boolean {
  const lit = (x: Expression): bigint | null => (x.kind === 'bigint_literal' ? x.value : null);
  const isNode = (v: unknown): v is Expression =>
    typeof v === 'object' && v !== null && typeof (v as { kind?: unknown }).kind === 'string';
  // Locals bound only to currentBlockHeight().
  const binds = new Map<string, boolean>();
  const bind = (name: string, value: Expression): void => {
    binds.set(name, (binds.get(name) ?? true) && isCallTo(value, 'currentBlockHeight'));
  };
  const collect = (stmts: Statement[]): void => {
    for (const st of stmts) {
      if (st.kind === 'variable_decl') bind(st.name, st.init);
      else if (st.kind === 'assignment' && st.target.kind === 'identifier') bind(st.target.name, st.value);
      else if (st.kind === 'if_statement') {
        collect(st.then);
        if (st.else) collect(st.else);
      } else if (st.kind === 'for_statement') {
        collect([st.init]);
        collect(st.body);
      }
    }
  };
  collect(method.body);
  const isCbh = (e: Expression): boolean =>
    isCallTo(e, 'currentBlockHeight') || (e.kind === 'identifier' && binds.get(e.name) === true);
  const hit = (e: Expression): boolean => {
    if (e.kind === 'binary_expr' && isCmp(e.op)) {
      if (isCbh(e.left) && classify(e.op, lit(e.right)) === 'pin' && (e.op === '>=' || e.op === '>')) return true;
      const f = FLIP[e.op];
      if (isCbh(e.right) && classify(f, lit(e.left)) === 'pin' && (f === '>=' || f === '>')) return true;
    }
    return Object.values(e).some((v) => (Array.isArray(v) ? v.some((x) => isNode(x) && hit(x)) : isNode(v) && hit(v)));
  };
  return method.body.some((st) => hit(st as unknown as Expression));
}

/** The shared error text for {@link comparesCurrentBlockHeightToTimestamp}. */
export function currentBlockHeightTimestampMessage(method: string): string {
  return (
    `method '${method}' compares currentBlockHeight() against a Unix-timestamp bound: currentBlockHeight() asserts ` +
    `its value is below 500000000 (a block height), so this compare can never pass and an output gated on it ` +
    `could never be spent. Use extractLocktime(this.txPreimage) for a timestamp gate`
  );
}

const isCallTo = (e: Expression, name: string): boolean =>
  e.kind === 'call_expr' && e.callee.kind === 'identifier' && e.callee.name === name;

/**
 * Prefilter (no result of its own): true iff some method of the contract calls
 * extractLocktime (currentBlockHeight pins itself, see above). Without one there is no gate, and the
 * path walk, which recurses once per nested if and helper call, is skipped
 * (N-264 compiles call chains nested far past what that walk can recurse).
 */
export function contractReadsLocktime(contract: ContractNode): boolean {
  const seen = (e: Expression): boolean => {
    if (isCallTo(e, 'extractLocktime')) return true;
    return Object.values(e).some((v) =>
      Array.isArray(v) ? v.some((x) => isNode(x) && seen(x)) : isNode(v) && seen(v),
    );
  };
  const isNode = (v: unknown): v is Expression =>
    typeof v === 'object' && v !== null && typeof (v as { kind?: unknown }).kind === 'string';
  return contract.methods.some((m) => m.body.some((st) => seen(st as unknown as Expression)));
}

/** D26 (source path): true iff some path through public `method` carries an unpinned gate. */
export function hasUnpinnedLocktimeGate(contract: ContractNode, method: MethodNode): boolean {
  return unpinned(new SourceGates(contract).exits(method, new Map()));
}

class SourceGates {
  private readonly privates = new Map<string, MethodNode>();
  /** Helper exits, by helper name and the taint level of each argument. */
  private readonly helperExits = new Map<string, Set<number>>();
  private readonly inProgress = new Set<string>();
  /** Taint level of the locals and parameters of the method being walked. */
  private locals = new Map<string, number>();

  constructor(contract: ContractNode) {
    for (const m of contract.methods) if (m.visibility === 'private') this.privates.set(m.name, m);
  }

  exits(method: MethodNode, params: Map<string, number>): Set<number> {
    const saved = this.locals;
    this.locals = collectLocktimeLocals(method.body, params);
    const { live, returned } = this.stmts(method.body, new Set([0]));
    this.locals = saved;
    return new Set([...live, ...returned]);
  }

  private level = (e: Expression): number => exprLevel(e, this.locals);

  private compare(e: Expression): 'gate' | 'pin' | 'none' {
    if (e.kind !== 'binary_expr') return 'none';
    return classifyCompare(e.op, e.left, e.right, this.level, (x) => (x.kind === 'bigint_literal' ? x.value : null));
  }

  private assertedPin(e: Expression): boolean {
    if (this.compare(e) === 'pin') return true;
    if (e.kind === 'binary_expr' && e.op === '&&') return this.assertedPin(e.left) || this.assertedPin(e.right);
    return false;
  }

  private stmts(stmts: Statement[], states: Set<number>): { live: Set<number>; returned: Set<number> } {
    let live = states;
    const returned = new Set<number>();
    for (const st of stmts) {
      if (live.size === 0) break;
      const r = this.stmt(st, live);
      for (const x of r.returned) returned.add(x);
      live = r.live;
    }
    return { live, returned };
  }

  private stmt(st: Statement, states: Set<number>): { live: Set<number>; returned: Set<number> } {
    const none = new Set<number>();
    switch (st.kind) {
      case 'assignment':
        return { live: this.expr(st.value, this.expr(st.target, states)), returned: none };
      case 'expression_statement':
        return { live: this.expr(st.expression, states), returned: none };
      case 'variable_decl':
        return { live: this.expr(st.init, states), returned: none };
      case 'return_statement':
        return { live: none, returned: st.value ? this.expr(st.value, states) : states };
      case 'if_statement': {
        const c = this.expr(st.condition, states);
        const t = this.stmts(st.then, c);
        const e = st.else ? this.stmts(st.else, c) : { live: c, returned: none };
        return { live: new Set([...t.live, ...e.live]), returned: new Set([...t.returned, ...e.returned]) };
      }
      case 'for_statement': {
        const init = this.stmt(st.init, states);
        const c = this.expr(st.condition, init.live);
        const body = this.stmts(st.body, c);
        const upd = this.stmt(st.update, body.live);
        return {
          live: new Set([...c, ...upd.live]),
          returned: new Set([...init.returned, ...body.returned, ...upd.returned]),
        };
      }
      default:
        return { live: states, returned: none };
    }
  }

  private expr(e: Expression, states: Set<number>): Set<number> {
    switch (e.kind) {
      case 'call_expr': {
        let s = states;
        if (e.callee.kind !== 'identifier') s = this.expr(e.callee, s);
        for (const a of e.args) s = this.expr(a, s);
        if (isCallTo(e, 'assert') && e.args[0] !== undefined && this.assertedPin(e.args[0])) return orAll(s, P);
        const callee = e.callee;
        const name =
          callee.kind === 'property_access' || callee.kind === 'member_expr' ? callee.property : undefined;
        const helper = name !== undefined ? this.privates.get(name) : undefined;
        return helper ? compose(s, this.helper(helper, e.args.map(this.level))) : s;
      }
      case 'binary_expr': {
        const s = this.expr(e.right, this.expr(e.left, states));
        return this.compare(e) === 'gate' ? orAll(s, G) : s;
      }
      case 'unary_expr':
        return this.expr(e.operand, states);
      case 'ternary_expr': {
        const c = this.expr(e.condition, states);
        return new Set([...this.expr(e.consequent, c), ...this.expr(e.alternate, c)]);
      }
      case 'index_access':
        return this.expr(e.index, this.expr(e.object, states));
      case 'member_expr':
        return this.expr(e.object, states);
      case 'increment_expr':
      case 'decrement_expr':
        return this.expr(e.operand, states);
      case 'array_literal': {
        let s = states;
        for (const el of e.elements) s = this.expr(el, s);
        return s;
      }
      default:
        return states;
    }
  }

  private helper(m: MethodNode, argLevels: number[]): Set<number> {
    const params = new Map<string, number>();
    m.params.forEach((p, i) => {
      const lv = argLevels[i] ?? NONE;
      if (lv !== NONE) params.set(p.name, lv);
    });
    const key = `${m.name}|${m.params.map((p) => params.get(p.name) ?? NONE).join(',')}`;
    const cached = this.helperExits.get(key);
    if (cached) return cached;
    // Recursion is refused by the validator; a cycle contributes nothing.
    if (this.inProgress.has(m.name)) return new Set([0]);
    this.inProgress.add(m.name);
    const ex = this.exits(m, params);
    this.inProgress.delete(m.name);
    this.helperExits.set(key, ex);
    return ex;
  }
}

/** Taint level of a source expression, given the taint of the names in scope. */
function exprLevel(e: Expression, names: Map<string, number>): number {
  if (isCallTo(e, 'extractLocktime')) return DIRECT;
  const any = (...xs: Expression[]): number => (xs.some((x) => exprLevel(x, names) !== NONE) ? DERIVED : NONE);
  switch (e.kind) {
    case 'identifier':
      return names.get(e.name) ?? NONE;
    case 'binary_expr':
      return PROPAGATE.has(e.op) ? any(e.left, e.right) : NONE;
    case 'unary_expr':
      return PROPAGATE_UNARY.has(e.op) ? any(e.operand) : NONE;
    case 'ternary_expr':
      return any(e.consequent, e.alternate);
    case 'call_expr':
      // A builtin (identifier callee); a helper's return is not followed.
      return e.callee.kind === 'identifier' ? any(...e.args) : NONE;
    default:
      return NONE;
  }
}

/**
 * Taint of the method's locals and parameters, from every binding in the body
 * (declaration or assignment, anywhere) plus one binding per tainted parameter
 * (the level its call passes it). Order-blind on purpose: the ANF the --ir
 * path sees names a local's every binding the same.
 */
function collectLocktimeLocals(body: Statement[], params: Map<string, number>): Map<string, number> {
  type B = Expression | number;
  const binds: Array<[string, B]> = [...params].map(([n, lv]): [string, B] => [n, lv]);
  const visit = (stmts: Statement[]): void => {
    for (const st of stmts) {
      if (st.kind === 'variable_decl') binds.push([st.name, st.init]);
      else if (st.kind === 'assignment' && st.target.kind === 'identifier') binds.push([st.target.name, st.value]);
      else if (st.kind === 'if_statement') {
        visit(st.then);
        if (st.else) visit(st.else);
      } else if (st.kind === 'for_statement') {
        visit([st.init]);
        visit(st.body);
      }
    }
  };
  visit(body);
  const asMap = (set: Set<string>): Map<string, number> => new Map([...set].map((n) => [n, DIRECT]));
  return solveTaint<B>(
    binds,
    (b, t) => (typeof b === 'number' ? b !== NONE : exprLevel(b, asMap(t)) !== NONE),
    (b, d) =>
      typeof b === 'number'
        ? b === DIRECT
        : isCallTo(b, 'extractLocktime') || (b.kind === 'identifier' && d.has(b.name)),
  );
}

// ---------------------------------------------------------------------------
// --ir path
// ---------------------------------------------------------------------------

/**
 * D26 on the --ir path: compileFromANF skips validate, so the rule is
 * re-derived from the ANF of every public method (stateless and stateful): a
 * `bin_op` gate whose operand resolves (through `load_const "@ref:"` aliases)
 * to a `call extractLocktime`, and an `assert` whose value resolves to a pin
 * compare, or to the `&&` lowering (a value `if` whose `else` arm is the
 * constant `false`) of a chain with a pin conjunct.
 */
export function assertIrLocktimeDomain(program: ANFProgram): void {
  // Prefilter (as contractReadsLocktime): no extractLocktime call, no gate.
  const reads = (bs: ANFBinding[]): boolean =>
    bs.some((b) => {
      const v = b.value;
      if (v.kind === 'call') return v.func === 'extractLocktime';
      if (v.kind === 'if') return reads(v.then) || reads(v.else);
      if (v.kind === 'loop') return reads(v.body);
      return false;
    });
  if (!program.methods.some((m) => reads(m.body))) return;
  const privates = new Map(
    program.methods.filter((m) => !m.isPublic && m.name !== 'constructor').map((m) => [m.name, m]),
  );
  const exitsOf = new Map<string, Set<number>>();
  const inProgress = new Set<string>();
  const exits = (m: ANFMethod, argLevels: number[]): Set<number> => {
    const params = new Map<string, number>();
    m.params.forEach((p, i) => {
      const lv = argLevels[i] ?? NONE;
      if (lv !== NONE) params.set(p.name, lv);
    });
    const key = `${m.name}|${m.params.map((p) => params.get(p.name) ?? NONE).join(',')}`;
    const cached = exitsOf.get(key);
    if (cached) return cached;
    if (inProgress.has(m.name)) return new Set([0]);
    inProgress.add(m.name);
    const ex = new IrGates(m, params, (name, levels) => {
      const t = privates.get(name);
      return t ? exits(t, levels) : undefined;
    }).run(m.body, new Set([0]));
    inProgress.delete(m.name);
    exitsOf.set(key, ex);
    return ex;
  };
  for (const method of program.methods) {
    if (!method.isPublic || method.name === 'constructor') continue;
    if (unpinned(exits(method, []))) throw new Error(locktimeDomainMessage(method.name));
  }
}

class IrGates {
  /** Every binding of the method, by name (a name bound more than once keeps all its values). */
  private readonly defs = new Map<string, ANFValue[]>();

  constructor(
    method: ANFMethod,
    /** Taint level of the method's parameters (a helper's, from its call). */
    params: Map<string, number>,
    private readonly helperExits: (name: string, argLevels: number[]) => Set<number> | undefined,
  ) {
    const index = (bs: ANFBinding[]): void => {
      for (const b of bs) {
        const list = this.defs.get(b.name) ?? [];
        list.push(b.value);
        this.defs.set(b.name, list);
        const v = b.value;
        if (v.kind === 'if') {
          index(v.then);
          index(v.else);
        } else if (v.kind === 'loop') index(v.body);
      }
    };
    index(method.body);
    const binds: Array<[string, ANFValue]> = [];
    for (const [n, vs] of this.defs) for (const v of vs) binds.push([n, v]);
    const ref = (v: ANFValue): string | undefined =>
      v.kind === 'load_const' && typeof v.value === 'string' && v.value.startsWith('@ref:') ? v.value.slice(5) : undefined;
    const last = (arm: ANFBinding[]): string | undefined => arm[arm.length - 1]?.name;
    this.taint = solveTaint<ANFValue>(
      binds,
      (v, t) => {
        const r = ref(v);
        if (r !== undefined) return t.has(r);
        switch (v.kind) {
          case 'call':
            return v.func === 'extractLocktime' || v.args.some((a) => t.has(a));
          case 'load_param':
            return (params.get(v.name) ?? NONE) !== NONE;
          case 'bin_op':
            return PROPAGATE.has(v.op) && (t.has(v.left) || t.has(v.right));
          case 'unary_op':
            return PROPAGATE_UNARY.has(v.op) && t.has(v.operand);
          case 'if':
            return [last(v.then), last(v.else)].some((n) => n !== undefined && t.has(n));
          default:
            return false;
        }
      },
      (v, d) => {
        const r = ref(v);
        if (r !== undefined) return d.has(r);
        if (v.kind === 'call') return v.func === 'extractLocktime';
        if (v.kind === 'load_param') return params.get(v.name) === DIRECT;
        return false;
      },
    );
  }

  /** Taint level of every temp (solveTaint over the method's bindings). */
  private readonly taint: Map<string, number>;
  private level = (name: string): number => this.taint.get(name) ?? NONE;

  private literal = (name: string): bigint | null => {
    const vs = this.defs.get(name) ?? [];
    if (vs.length !== 1) return null;
    const v = vs[0]!;
    if (v.kind !== 'load_const') return null;
    if (typeof v.value === 'bigint') return v.value;
    if (typeof v.value === 'string' && v.value.startsWith('@ref:')) return this.literal(v.value.slice(5));
    return null;
  };

  private compare(v: ANFValue): 'gate' | 'pin' | 'none' {
    if (v.kind !== 'bin_op') return 'none';
    return classifyCompare(v.op, v.left, v.right, (x) => this.level(x), this.literal);
  }

  /** Does `assert(name)` imply a pin? */
  private assertedPin(name: string, seen = new Set<string>()): boolean {
    if (seen.has(name)) return false;
    seen.add(name);
    const vs = this.defs.get(name) ?? [];
    if (vs.length !== 1) return false;
    const v = vs[0]!;
    if (this.compare(v) === 'pin') return true;
    if (v.kind === 'load_const' && typeof v.value === 'string' && v.value.startsWith('@ref:')) {
      return this.assertedPin(v.value.slice(5), seen);
    }
    // `a && b` lowers to `if a then [..., b] else [false]`.
    if (v.kind === 'if' && isConstFalseArm(v.else) && v.then.length > 0) {
      return this.assertedPin(v.cond, seen) || this.assertedPin(v.then[v.then.length - 1]!.name, seen);
    }
    return false;
  }

  run(bs: ANFBinding[], states: Set<number>): Set<number> {
    let s = states;
    for (const b of bs) {
      const v = b.value;
      if (v.kind === 'bin_op') {
        if (this.compare(v) === 'gate') s = orAll(s, G);
      } else if (v.kind === 'assert') {
        if (this.assertedPin(v.value)) s = orAll(s, P);
      } else if (v.kind === 'method_call') {
        const ex = this.helperExits(v.method, v.args.map((a) => this.level(a)));
        if (ex) s = compose(s, ex);
      } else if (v.kind === 'if') {
        s = new Set([...this.run(v.then, s), ...this.run(v.else, s)]);
      } else if (v.kind === 'loop') {
        s = new Set([...s, ...this.run(v.body, s)]);
      }
    }
    return s;
  }
}

function isConstFalseArm(arm: ANFBinding[]): boolean {
  if (arm.length !== 1) return false;
  const v = arm[0]!.value;
  return v.kind === 'load_const' && v.value === false;
}
