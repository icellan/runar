//! ANF EC Optimizer (Pass 4.5) — algebraic simplification of EC operations.
//!
//! Runs on ANF IR BEFORE stack lowering. Each eliminated ecMul saves ~1500 bytes,
//! each eliminated ecAdd saves ~800 bytes. Always-on.
//!
//! Mirrors the TypeScript optimizer in `packages/runar-compiler/src/optimizer/anf-ec.ts`.

use std::collections::{HashMap, HashSet};

use num_bigint::BigInt;
use num_traits::Num;

use crate::ir::{parse_const_value, ANFBinding, ANFMethod, ANFProgram, ANFProperty, ANFValue, ConstValue};

// ---------------------------------------------------------------------------
// EC constants
// ---------------------------------------------------------------------------

/// secp256k1 group order. Every scalar a fusing rule folds is reduced modulo
/// `n` into `[0, n)`, matching `CURVE_N` in the TS optimizer, `curveN` in the
/// Go rules engine, and the same constant in the Python / Ruby / Java tiers.
fn curve_n() -> &'static BigInt {
    use std::sync::OnceLock;
    static N: OnceLock<BigInt> = OnceLock::new();
    N.get_or_init(|| {
        BigInt::from_str_radix(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        .expect("secp256k1 order is a valid hex literal")
    })
}

/// Reduce a folded scalar into `[0, n)`.
///
/// `num_bigint`'s `%` is a remainder (it keeps the dividend's sign), so the
/// extra `+ n` step is what matches the other tiers: TS spells it
/// `((x % N) + N) % N`, Go/Python/Ruby/Java get it for free from `big.Int.Mod`
/// / Python `%` / `Integer#%` / `BigInteger.mod`.
fn reduce_mod_n(v: BigInt) -> BigInt {
    let n = curve_n();
    let r = v % n;
    if r.sign() == num_bigint::Sign::Minus {
        r + n
    } else {
        r
    }
}

/// Point at infinity: 64 zero bytes as hex.
const INFINITY_HEX: &str = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// Generator point G as 64-byte hex (x || y, big-endian unsigned, no prefix).
const G_HEX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

// ---------------------------------------------------------------------------
// Value resolution helpers (uses owned ANFValue map for borrow-checker safety)
// ---------------------------------------------------------------------------

/// Binding name -> its value as already rewritten in the current pass, plus
/// the method's rebound names. `get` follows `@ref:` aliases (F-269, see
/// `canonical`), so every rule resolves through them.
struct ValueMap {
    values: HashMap<String, ANFValue>,
    rebound: HashSet<String>,
}

impl ValueMap {
    fn new(rebound: HashSet<String>) -> Self {
        ValueMap { values: HashMap::new(), rebound }
    }

    fn insert(&mut self, name: String, value: ANFValue) {
        self.values.insert(name, value);
    }

    /// N-201: the map an `if` arm or a loop body starts from (the TS
    /// `ValueMap.nestedScope`) — every binding visible at the `if`/`loop`,
    /// and nothing the nested scope binds flows back out. `hidden` is a
    /// loop's iteration variable, never resolved through an outer binding.
    fn nested_scope(&self, hidden: Option<&str>) -> ValueMap {
        let mut scope = ValueMap { values: self.values.clone(), rebound: self.rebound.clone() };
        if let Some(h) = hidden {
            scope.values.remove(h);
        }
        scope
    }

    /// F-269 (user decision R77): the binding `arg` ultimately names,
    /// following `load_const "@ref:<x>"` aliases — pass 04's
    /// `const y = <expr>` and the ones R1/R2/R3/R7 leave behind. The TS
    /// `canonicalName` in anf-ec.ts.
    ///
    /// `None` when `arg` has no position-independent identity: ANF re-emits a
    /// local's name when the source reassigns it (top level or in an if/loop
    /// arm), so a REBOUND name means different values at different sites. Two
    /// uses of one are not "the same $x", and nothing lifted out of an earlier
    /// binding may name one (F-269 attempt 2). An alias cycle (only
    /// hand-written `--ir`) is `None` too. A hop is never taken INTO a rebound
    /// name: the chain stops at the last name bound once, which is itself a
    /// fixed value, and its value is the opaque alias. Matching only —
    /// rewrites emit the literal names they matched.
    fn canonical(&self, arg: &str) -> Option<String> {
        if self.rebound.contains(arg) {
            return None;
        }
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(arg.to_string());
        let mut cur = arg.to_string();
        loop {
            let next = match self.values.get(&cur) {
                Some(ANFValue::LoadConst { value: serde_json::Value::String(s) })
                    if s.len() > 5 && s.starts_with("@ref:") => s[5..].to_string(),
                _ => return Some(cur),
            };
            if self.rebound.contains(&next) {
                return Some(cur);
            }
            if seen.contains(&next) {
                return None;
            }
            seen.insert(next.clone());
            cur = next;
        }
    }

    /// The value `name` resolves to, through aliases; `None` for a name with
    /// no fixed identity.
    fn get(&self, name: &str) -> Option<&ANFValue> {
        self.values.get(&self.canonical(name)?)
    }

    /// Do two arguments name the same binding, through aliases? (R8, R8r, R11.)
    /// Never for a name with no fixed identity.
    fn same(&self, a: &str, b: &str) -> bool {
        match (self.canonical(a), self.canonical(b)) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        }
    }

    /// F-269 attempt 2: may a name lifted out of an earlier binding be
    /// emitted at the current site? Only when it denotes one value (R7, R9).
    fn stable(&self, name: &str) -> bool {
        self.canonical(name).is_some()
    }
}

fn is_call_to<'a>(value: &'a ANFValue, func_name: &str) -> Option<&'a Vec<String>> {
    match value {
        ANFValue::Call { func, args } if func == func_name => Some(args),
        _ => None,
    }
}

fn is_const_int(value: &ANFValue, n: i128) -> bool {
    get_const_int(value).is_some_and(|v| v == BigInt::from(n))
}

/// Decode a `load_const` scalar to an arbitrary-precision integer.
///
/// Routed through `ir::parse_const_value` — the single definition of the
/// cross-tier `load_const` wire format — rather than `serde_json`'s
/// `as_i64` / `as_f64`. Those two see only JSON *numbers*, but any bigint
/// whose magnitude exceeds `Number.MAX_SAFE_INTEGER` is carried as a
/// JS-style decimal string (`"115792089...n"`), which is exactly the shape a
/// real secp256k1 scalar takes. Reading it as a number made every
/// scalar-fusing EC rule decline on precisely the inputs that matter, in
/// Rust alone (issue R-033 / CL-BUG-022).
fn get_const_int(value: &ANFValue) -> Option<BigInt> {
    match value {
        ANFValue::LoadConst { value: v } => match parse_const_value(v) {
            Some(ConstValue::Int(i)) => Some(i),
            _ => None,
        },
        _ => None,
    }
}

/// Exact-string match against a hex point constant.
///
/// Safe to leave as a raw string comparison: `parse_const_value` only treats
/// a JSON string as a decimal BigInt when it carries the trailing `n`
/// discriminator, and neither `INFINITY_HEX` (128 zeros) nor `G_HEX` does —
/// so a decimal-BigInt payload can never be mistaken for either point.
fn is_const_hex(value: &ANFValue, hex: &str) -> bool {
    match value {
        ANFValue::LoadConst { value: v } => v.as_str() == Some(hex),
        _ => false,
    }
}

fn is_infinity(value: &ANFValue) -> bool {
    is_const_hex(value, INFINITY_HEX)
}

fn is_generator_point(value: &ANFValue) -> bool {
    is_const_hex(value, G_HEX)
}

/// Check if a resolved arg represents the infinity point.
fn arg_is_infinity(arg_name: &str, value_map: &ValueMap) -> bool {
    let v = match value_map.get(arg_name) {
        Some(v) => v,
        None => return false,
    };
    if is_infinity(v) {
        return true;
    }
    // ecMulGen(0) = infinity
    if let Some(args) = is_call_to(v, "ecMulGen") {
        if args.len() == 1 {
            if let Some(scalar_val) = value_map.get(args[0].as_str()) {
                if is_const_int(scalar_val, 0) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if a resolved arg represents the generator point G.
fn arg_is_g(arg_name: &str, value_map: &ValueMap) -> bool {
    let v = match value_map.get(arg_name) {
        Some(v) => v,
        None => return false,
    };
    if is_generator_point(v) {
        return true;
    }
    // ecMulGen(1) = G
    if let Some(args) = is_call_to(v, "ecMulGen") {
        if args.len() == 1 {
            if let Some(scalar_val) = value_map.get(args[0].as_str()) {
                if is_const_int(scalar_val, 1) {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Rewrite helpers
// ---------------------------------------------------------------------------

fn make_load_const_hex(hex: &str) -> ANFValue {
    ANFValue::LoadConst {
        value: serde_json::Value::String(hex.to_string()),
    }
}

/// Re-encode a folded scalar in the shared `load_const` wire format: a bare
/// JSON number while it stays JS-safe, a `"...n"` decimal string once it does
/// not. `n as i64` used to be the encoder, which silently wrapped any product
/// past `i64::MAX`.
fn make_load_const_int(n: &BigInt) -> ANFValue {
    ANFValue::LoadConst {
        value: super::anf_lower::bigint_to_json(n),
    }
}

fn make_alias(target: &str) -> ANFValue {
    ANFValue::LoadConst {
        value: serde_json::Value::String(format!("@ref:{}", target)),
    }
}

// ---------------------------------------------------------------------------
// Rewrite engine
// ---------------------------------------------------------------------------

/// F-086: every name the method already uses — binding names at any depth
/// (if/loop arms included), loop iteration variables, params, and the
/// contract's properties. A scalar-fusing rewrite mints a new binding; ANF is
/// single-assignment and stack lowering resolves a name to its shallowest
/// slot, so a minted name that is already in use silently aliases the two
/// values. `--ir` input chooses these names freely.
fn collect_used_names(method: &ANFMethod, properties: &[ANFProperty]) -> HashSet<String> {
    fn walk(bindings: &[ANFBinding], used: &mut HashSet<String>) {
        for b in bindings {
            used.insert(b.name.clone());
            match &b.value {
                ANFValue::LoadParam { name } | ANFValue::LoadProp { name, .. } => {
                    used.insert(name.clone());
                }
                ANFValue::If { then, else_branch, .. } => {
                    walk(then, used);
                    walk(else_branch, used);
                }
                ANFValue::Loop { body, iter_var, .. } => {
                    used.insert(iter_var.clone());
                    walk(body, used);
                }
                _ => {}
            }
        }
    }
    let mut used: HashSet<String> = properties.iter().map(|p| p.name.clone()).collect();
    used.extend(method.params.iter().map(|p| p.name.clone()));
    walk(&method.body, &mut used);
    used
}

/// F-269: every name bound more than once in the method — binding names at
/// any depth (if/loop arms included) and loop iteration variables (the TS
/// `collectReboundNames`). `ValueMap::canonical` never resolves through one.
fn collect_rebound_names(method: &ANFMethod) -> HashSet<String> {
    fn bind(name: &str, seen: &mut HashSet<String>, rebound: &mut HashSet<String>) {
        if !seen.insert(name.to_string()) {
            rebound.insert(name.to_string());
        }
    }
    fn walk(bindings: &[ANFBinding], seen: &mut HashSet<String>, rebound: &mut HashSet<String>) {
        for b in bindings {
            bind(&b.name, seen, rebound);
            match &b.value {
                ANFValue::If { then, else_branch, .. } => {
                    walk(then, seen, rebound);
                    walk(else_branch, seen, rebound);
                }
                ANFValue::Loop { body, iter_var, .. } => {
                    bind(iter_var, seen, rebound);
                    walk(body, seen, rebound);
                }
                _ => {}
            }
        }
    }
    let mut seen = HashSet::new();
    let mut rebound = HashSet::new();
    walk(&method.body, &mut seen, &mut rebound);
    rebound
}

/// F-086: `base` when the method does not use it (every non-colliding program
/// keeps its historical name), else the first unused `base_<i>`. Reserves the
/// returned name.
fn fresh_name(base: String, used_names: &mut HashSet<String>) -> String {
    let mut name = base.clone();
    let mut i = 1;
    while used_names.contains(&name) {
        name = format!("{}_{}", base, i);
        i += 1;
    }
    used_names.insert(name.clone());
    name
}

/// secp256k1 field prime.
const FIELD_P_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

/// N-104 — the operand gate a rewrite must leave behind. Byte-for-byte the TS
/// reference (`emitAddOperandGate` / `emitMulOperandGate` in
/// packages/runar-compiler/src/optimizer/anf-ec.ts) and the "gate" entries in
/// optimizer/ec-rules.json:
///
///   ecAdd: assert(ecPointX(q) < p && ecPointY(q) < p)   width (CL-BUG-095) + canonicity (R-117)
///   ecMul: assert(q === O || ecOnCurve(q))               on-curve-or-O (R-157)
///
/// R1-R4 replace a builtin whose first act is to validate q; without this a
/// malformed or off-curve q was accepted by the default compile and aborted
/// under disableEcOptimizer. Built only from forms no rule matches, so the
/// fixed-point loop below cannot rewrite it on a later pass. Each gate ends in
/// an assert, which DCE keeps along with what it reads.
fn emit_operand_gate(of_mul: bool, base: &str, q: &str, out: &mut Vec<ANFBinding>, used_names: &mut HashSet<String>) {
    let mut add = |suffix: &str, value: ANFValue, out: &mut Vec<ANFBinding>| -> String {
        let name = fresh_name(format!("{}{}", base, suffix), used_names);
        out.push(ANFBinding { name: name.clone(), value, source_loc: None });
        name
    };
    let call = |func: &str, arg: &str| ANFValue::Call { func: func.to_string(), args: vec![arg.to_string()] };
    let bin = |op: &str, l: &str, r: &str, t: Option<&str>| ANFValue::BinOp {
        op: op.to_string(),
        left: l.to_string(),
        right: r.to_string(),
        result_type: t.map(|s| s.to_string()),
    };
    let ok = if !of_mul {
        let px = add("_px", call("ecPointX", q), out);
        let py = add("_py", call("ecPointY", q), out);
        let p = BigInt::from_str_radix(FIELD_P_HEX, 16).expect("field prime");
        let fp = add("_fp", make_load_const_int(&p), out);
        let x_ok = add("_pxok", bin("<", &px, &fp, None), out);
        let y_ok = add("_pyok", bin("<", &py, &fp, None), out);
        add("_ok", bin("&&", &x_ok, &y_ok, None), out)
    } else {
        let inf = add("_inf", make_load_const_hex(INFINITY_HEX), out);
        let is_inf = add("_isinf", bin("===", q, &inf, Some("bytes")), out);
        let on_curve = add("_oncurve", call("ecOnCurve", q), out);
        add("_ok", bin("||", &is_inf, &on_curve, None), out)
    };
    add("_gate", ANFValue::Assert { value: ok, is_auto_injected_state_check: false }, out);
}

/// N-251 — the gate R8/R8r (`ecAdd(q, ecNegate(q)) -> O` and its mirror) must
/// leave behind (user decision R96). Byte-for-byte the TS reference
/// (`emitNegCancelGate` in packages/runar-compiler/src/optimizer/anf-ec.ts):
///
///   assert(ecPointX(q) === 0 || ecPointY(q) !== 0)
///
/// The replaced ecAdd doubles exactly when y(q) = 0, and N-110 made the adder
/// abort on a doubling with px != 0 and py == 0; the px == 0 term keeps
/// O + O = O. Width and canonicity are checked by the inner ecNegate(q) call,
/// which is never dead-code-eliminated.
fn emit_neg_cancel_gate(base: &str, q: &str, out: &mut Vec<ANFBinding>, used_names: &mut HashSet<String>) {
    let mut add = |suffix: &str, value: ANFValue, out: &mut Vec<ANFBinding>| -> String {
        let name = fresh_name(format!("{}{}", base, suffix), used_names);
        out.push(ANFBinding { name: name.clone(), value, source_loc: None });
        name
    };
    let call = |func: &str, arg: &str| ANFValue::Call { func: func.to_string(), args: vec![arg.to_string()] };
    let bin = |op: &str, l: &str, r: &str| ANFValue::BinOp {
        op: op.to_string(),
        left: l.to_string(),
        right: r.to_string(),
        result_type: None,
    };
    let px = add("_px", call("ecPointX", q), out);
    let py = add("_py", call("ecPointY", q), out);
    let zero = add("_zero", make_load_const_int(&BigInt::from(0)), out);
    let x_zero = add("_pxz", bin("===", &px, &zero), out);
    let y_non_zero = add("_pynz", bin("!==", &py, &zero), out);
    let ok = add("_ok", bin("||", &x_zero, &y_non_zero), out);
    add("_gate", ANFValue::Assert { value: ok, is_auto_injected_state_check: false }, out);
}

/// Try to rewrite a single binding. Returns Some(new_value) if rewritten.
/// May push extra bindings (e.g., computed scalars) into `extra_bindings`.
fn try_rewrite(
    binding: &ANFBinding,
    value_map: &ValueMap,
    extra_bindings: &mut Vec<ANFBinding>,
    used_names: &mut HashSet<String>,
) -> Option<ANFValue> {
    let value = &binding.value;

    let (func, args) = match value {
        ANFValue::Call { func, args } => (func.as_str(), args),
        _ => return None,
    };

    match func {
        "ecMulGen" => {
            if args.len() != 1 {
                return None;
            }
            let scalar_val = value_map.get(args[0].as_str())?;

            // Rule 5: ecMulGen(0) -> INFINITY
            if is_const_int(scalar_val, 0) {
                return Some(make_load_const_hex(INFINITY_HEX));
            }

            // Rule 6: ecMulGen(1) -> G
            if is_const_int(scalar_val, 1) {
                return Some(make_load_const_hex(G_HEX));
            }

            None
        }

        "ecMul" => {
            if args.len() != 2 {
                return None;
            }
            let point_arg = &args[0];
            let scalar_arg = &args[1];
            let scalar_val = value_map.get(scalar_arg.as_str())?;

            // Rule 4: ecMul(x, 0) -> INFINITY, keeping ecMul's operand gate (N-104)
            if is_const_int(scalar_val, 0) {
                emit_operand_gate(true, &binding.name, point_arg, extra_bindings, used_names);
                return Some(make_load_const_hex(INFINITY_HEX));
            }

            // Rule 3: ecMul(x, 1) -> x (alias), keeping ecMul's operand gate (N-104)
            if is_const_int(scalar_val, 1) {
                emit_operand_gate(true, &binding.name, point_arg, extra_bindings, used_names);
                return Some(make_alias(point_arg));
            }

            // Rule 12: ecMul(G, k) -> ecMulGen(k)
            if arg_is_g(point_arg, value_map) {
                return Some(ANFValue::Call {
                    func: "ecMulGen".to_string(),
                    args: vec![scalar_arg.clone()],
                });
            }

            // Rule 9: ecMul(ecMul(p, k1), k2) -> ecMul(p, k1*k2)
            if let Some(point_val) = value_map.get(point_arg.as_str()) {
                if let Some(inner_args) = is_call_to(point_val, "ecMul") {
                    if inner_args.len() == 2 && value_map.stable(&inner_args[0]) {
                        let inner_point = inner_args[0].clone();
                        let inner_scalar = inner_args[1].clone();
                        if let Some(inner_scalar_val) = value_map.get(inner_scalar.as_str()) {
                            let k1 = get_const_int(inner_scalar_val);
                            let k2 = get_const_int(scalar_val);
                            if let (Some(k1), Some(k2)) = (k1, k2) {
                                let product = reduce_mod_n(k1 * k2);
                                let new_scalar_name = fresh_name(format!("{}_k", binding.name), used_names);
                                extra_bindings.push(ANFBinding {
                                    name: new_scalar_name.clone(),
                                    value: make_load_const_int(&product),
                                    source_loc: None,
                                });
                                return Some(ANFValue::Call {
                                    func: "ecMul".to_string(),
                                    args: vec![inner_point, new_scalar_name],
                                });
                            }
                        }
                    }
                }
            }

            None
        }

        "ecAdd" => {
            if args.len() != 2 {
                return None;
            }
            let left_arg = &args[0];
            let right_arg = &args[1];

            // Rule 1: ecAdd(x, INFINITY) -> x, keeping ecAdd's operand gate (N-104)
            if arg_is_infinity(right_arg, value_map) {
                emit_operand_gate(false, &binding.name, left_arg, extra_bindings, used_names);
                return Some(make_alias(left_arg));
            }

            // Rule 2: ecAdd(INFINITY, x) -> x, keeping ecAdd's operand gate (N-104)
            if arg_is_infinity(left_arg, value_map) {
                emit_operand_gate(false, &binding.name, right_arg, extra_bindings, used_names);
                return Some(make_alias(right_arg));
            }

            // Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY, keeping the adder's y = 0 abort (N-251)
            if let Some(right_val) = value_map.get(right_arg.as_str()) {
                if let Some(negate_args) = is_call_to(right_val, "ecNegate") {
                    if negate_args.len() == 1 && value_map.same(&negate_args[0], left_arg) {
                        emit_neg_cancel_gate(&binding.name, left_arg, extra_bindings, used_names);
                        return Some(make_load_const_hex(INFINITY_HEX));
                    }
                }
            }

            // Rule 8r (`ec-add-negate-cancel-reversed`): ecAdd(ecNegate(x), x) -> INFINITY
            //
            // The mirror of Rule 8. It has always been in optimizer/ec-rules.json
            // and the Go tier — whose rule engine executes that file directly —
            // performed it; the six hand-ported tiers implemented only the
            // forward direction, so the same ANF compiled to a 1808-byte script
            // in Go and a 26140-byte one everywhere else (R-034 / CL-BUG-028).
            //
            // Placed after Rule 8 and before Rules 10/11 to match the JSON's
            // rule order, which is the order the Go engine tries them in.
            // Name equality, not value equality, exactly as Rule 8 above
            // (through aliases, F-269). The gate reads the ecNegate operand —
            // the name the JSON's `$x` binds first, as the Go engine binds it.
            if let Some(left_val) = value_map.get(left_arg.as_str()) {
                if let Some(negate_args) = is_call_to(left_val, "ecNegate") {
                    if negate_args.len() == 1 && value_map.same(&negate_args[0], right_arg) {
                        emit_neg_cancel_gate(&binding.name, &negate_args[0], extra_bindings, used_names);
                        return Some(make_load_const_hex(INFINITY_HEX));
                    }
                }
            }

            // Rules 10 & 11 require looking up both sides
            let left_val = value_map.get(left_arg.as_str()).cloned();
            let right_val = value_map.get(right_arg.as_str()).cloned();

            if let (Some(ref lv), Some(ref rv)) = (&left_val, &right_val) {
                // Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) -> ecMulGen(k1+k2)
                if let (Some(left_args), Some(right_args)) =
                    (is_call_to(lv, "ecMulGen"), is_call_to(rv, "ecMulGen"))
                {
                    if left_args.len() == 1 && right_args.len() == 1 {
                        let k1_name = left_args[0].clone();
                        let k2_name = right_args[0].clone();
                        if let (Some(k1_val), Some(k2_val)) = (
                            value_map.get(k1_name.as_str()),
                            value_map.get(k2_name.as_str()),
                        ) {
                            let k1 = get_const_int(k1_val);
                            let k2 = get_const_int(k2_val);
                            if let (Some(k1), Some(k2)) = (k1, k2) {
                                let sum = reduce_mod_n(k1 + k2);
                                let new_scalar_name = fresh_name(format!("{}_k", binding.name), used_names);
                                extra_bindings.push(ANFBinding {
                                    name: new_scalar_name.clone(),
                                    value: make_load_const_int(&sum),
                                    source_loc: None,
                                });
                                return Some(ANFValue::Call {
                                    func: "ecMulGen".to_string(),
                                    args: vec![new_scalar_name],
                                });
                            }
                        }
                    }
                }

                // Rule 11: ecAdd(ecMul(p, k1), ecMul(p, k2)) -> ecMul(p, k1+k2)
                if let (Some(left_mul_args), Some(right_mul_args)) =
                    (is_call_to(lv, "ecMul"), is_call_to(rv, "ecMul"))
                {
                    if left_mul_args.len() == 2
                        && right_mul_args.len() == 2
                        && value_map.same(&left_mul_args[0], &right_mul_args[0])
                    {
                        let point_name = left_mul_args[0].clone();
                        let k1_name = left_mul_args[1].clone();
                        let k2_name = right_mul_args[1].clone();
                        if let (Some(k1_val), Some(k2_val)) = (
                            value_map.get(k1_name.as_str()),
                            value_map.get(k2_name.as_str()),
                        ) {
                            let k1 = get_const_int(k1_val);
                            let k2 = get_const_int(k2_val);
                            if let (Some(k1), Some(k2)) = (k1, k2) {
                                let sum = reduce_mod_n(k1 + k2);
                                let new_scalar_name = fresh_name(format!("{}_k", binding.name), used_names);
                                extra_bindings.push(ANFBinding {
                                    name: new_scalar_name.clone(),
                                    value: make_load_const_int(&sum),
                                    source_loc: None,
                                });
                                return Some(ANFValue::Call {
                                    func: "ecMul".to_string(),
                                    args: vec![point_name, new_scalar_name],
                                });
                            }
                        }
                    }
                }
            }

            None
        }

        "ecNegate" => {
            if args.len() != 1 {
                return None;
            }
            let inner_val = value_map.get(args[0].as_str())?;

            // Rule 7: ecNegate(ecNegate(x)) -> x
            if let Some(negate_args) = is_call_to(inner_val, "ecNegate") {
                // F-269 attempt 2: x is lifted out of the inner binding and
                // re-emitted here, so it must denote one value at both sites.
                if negate_args.len() == 1 && value_map.stable(&negate_args[0]) {
                    return Some(make_alias(&negate_args[0]));
                }
            }

            None
        }

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Dead binding elimination
// ---------------------------------------------------------------------------
//
// The DCE pass lives in its own discrete module now (`frontend::dce`).
// This re-export preserves the legacy intra-crate symbols so existing
// call sites in this file keep compiling unchanged.
use super::dce::eliminate_dead_bindings_method;

// ---------------------------------------------------------------------------
// Method optimizer
// ---------------------------------------------------------------------------

/// R-221: rewrite to a FIXPOINT, not once.
///
/// The peers loop — Go's `OptimizeEC` runs `for changed { ... }`, Python's
/// `_optimize_method` runs `while changed:`, and Ruby, Zig and Java do the same
/// — because one rule's output routinely enables another's. This tier applied
/// the rules in a single pass, so it stopped one rewrite short of the peers
/// whenever that happened.
///
/// Measured on `ecAdd(ecMulGen(N-7), ecMulGen(7n))`, fold-ON, the shipped
/// default. Rule 10 reduces the two scalars to `(N-7) + 7 mod N` = 0, and Rule 5
/// then reduces `ecMulGen(0)` to the infinity-point constant. Five tiers emitted
/// that constant; this one emitted `ecMulGen(0)` — an extra 256-step ladder, and
/// a script 849002 hex chars (~425 KB) larger than every peer's:
///
/// ```text
/// go python ruby java zig   1699920 hexchars   sha a609b3e20c
/// rust                      2548922 hexchars   sha f1ca9484f1
/// ```
///
/// A cross-tier byte divergence in the default mode, which is exactly what the
/// fold-ON parity gate exists to prevent; no conformance fixture happened to
/// carry a scalar pair that summed to 0 mod N.
fn optimize_method_ec(method: &ANFMethod, properties: &[ANFProperty]) -> (ANFMethod, bool) {
    let mut body = method.body.clone();
    let mut changed = false;
    let mut used_names = collect_used_names(method, properties);
    let rebound = collect_rebound_names(method);

    // Same cap-free shape as the Go tier: every rule strictly reduces the
    // number of EC calls or replaces a call with a constant, so the loop
    // terminates.
    loop {
        let (next, pass_changed) =
            optimize_method_ec_once(&body, &mut used_names, &ValueMap::new(rebound.clone()), None);
        body = next;
        if !pass_changed {
            break;
        }
        changed = true;
    }

    if !changed {
        return (method.clone(), false);
    }

    (ANFMethod {
        name: method.name.clone(),
        params: method.params.clone(),
        body,
        is_public: method.is_public,
        sighash_type: method.sighash_type,
    }, true)
}

/// One rewrite pass over a scope. Returns the new body and whether it changed.
///
/// N-201: the pass descends into `if` arms (then before else) and loop bodies
/// at the position of their binding, each with its own scope seeded from the
/// enclosing one (`ValueMap::nested_scope`), exactly as the TS
/// `optimizeBodyOnce`; it used to visit the top level only.
fn optimize_method_ec_once(
    body: &[ANFBinding],
    used_names: &mut HashSet<String>,
    outer: &ValueMap,
    hidden: Option<&str>,
) -> (Vec<ANFBinding>, bool) {
    let mut value_map = outer.nested_scope(hidden);
    let mut result: Vec<ANFBinding> = Vec::new();
    let mut changed = false;

    for binding in body {
        // Register binding value for lookups
        value_map.insert(binding.name.clone(), binding.value.clone());

        if matches!(binding.value, ANFValue::If { .. } | ANFValue::Loop { .. }) {
            let mut value = binding.value.clone();
            let nested_changed = match &mut value {
                ANFValue::If { then, else_branch, .. } => {
                    let (then_b, then_c) = optimize_method_ec_once(then, used_names, &value_map, None);
                    let (else_b, else_c) = optimize_method_ec_once(else_branch, used_names, &value_map, None);
                    *then = then_b;
                    *else_branch = else_b;
                    then_c || else_c
                }
                ANFValue::Loop { body: loop_body, iter_var, .. } => {
                    let hidden = iter_var.clone();
                    let (body_b, body_c) =
                        optimize_method_ec_once(loop_body, used_names, &value_map, Some(&hidden));
                    *loop_body = body_b;
                    body_c
                }
                _ => unreachable!(),
            };
            if nested_changed {
                value_map.insert(binding.name.clone(), value.clone());
                result.push(ANFBinding { name: binding.name.clone(), value, source_loc: binding.source_loc.clone() });
                changed = true;
            } else {
                result.push(binding.clone());
            }
            continue;
        }

        let mut extra_bindings = Vec::new();
        let rewritten = try_rewrite(binding, &value_map, &mut extra_bindings, used_names);

        if let Some(new_value) = rewritten {
            // Add any new helper bindings (e.g., computed scalars).
            // N-218: every helper a rewrite mints (the N-104/N-251 gate
            // bindings, the fused-scalar helper) takes the rewritten
            // binding's own source_loc, mirroring F-343 in the TS reference
            // (anf-ec.ts optimizeBodyOnce) — it exists only because of that
            // source expression, and stack lowering maps opcodes through
            // binding.source_loc.
            for extra in &extra_bindings {
                value_map.insert(extra.name.clone(), extra.value.clone());
                result.push(ANFBinding {
                    name: extra.name.clone(),
                    value: extra.value.clone(),
                    source_loc: binding.source_loc.clone(),
                });
            }
            // Update the value map with the rewritten value
            value_map.insert(binding.name.clone(), new_value.clone());
            result.push(ANFBinding {
                name: binding.name.clone(),
                value: new_value,
                source_loc: binding.source_loc.clone(),
            });
            changed = true;
        } else {
            result.push(binding.clone());
        }
    }

    (result, changed)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Optimize EC operations in an ANF program (Pass 4.5).
///
/// Applies algebraic simplification rules to EC function calls. Always-on (no
/// flag), runs before stack lowering. Dead-binding elimination runs ONLY when
/// some rewrite fired: if `any_changed` is false the program is returned
/// untouched, dead bindings included (F-219; same gate as TS `optimizeEC`).
pub fn optimize_ec(program: ANFProgram) -> ANFProgram {
    // N-201: the names each method references before any rewrite — the
    // candidate set of the nested prune below.
    let candidates: Vec<HashSet<String>> = program
        .methods
        .iter()
        .map(|m| {
            let mut refs = HashSet::new();
            for b in &m.body {
                super::dce::collect_refs_from_value(&b.value, &mut refs);
            }
            refs
        })
        .collect();
    let mut any_changed = false;
    let optimized_methods: Vec<ANFMethod> = program
        .methods
        .iter()
        .map(|m| {
            let (opt, changed) = optimize_method_ec(m, &program.properties);
            if changed {
                any_changed = true;
            }
            opt
        })
        .collect();

    if !any_changed {
        return program;
    }

    // Run dead binding elimination to clean up orphaned bindings
    // N-201: then prune the operands a rewrite inside an if arm or a loop
    // body orphaned there — the DCE above filters only the top level, and an
    // orphan left in an arm unbalances the arms (the N-446 hazard). Same
    // candidate rule as the constant folder's prune.
    let cleaned_methods: Vec<ANFMethod> = optimized_methods
        .iter()
        .map(eliminate_dead_bindings_method)
        .zip(candidates.iter())
        .map(|(m, refs)| {
            let mut m = super::dce::eliminate_dead_bindings_among(&m, refs);
            // N-113: drop the inner ecMul/ecMulGen calls a fusion orphaned
            // whose abort is still performed, then prune what that orphans.
            while let Some(next) = remove_gate_subsumed_ec_calls(&m, refs) {
                m = super::dce::eliminate_dead_bindings_among(&next, refs);
            }
            m
        })
        .collect();

    ANFProgram {
        contract_name: program.contract_name,
        properties: program.properties,
        methods: cleaned_methods,
        parent_class: program.parent_class,
    }
}

/// N-113 (the TS reference's anf-ec.ts `removeGateSubsumedEcCalls`): remove
/// dead scalar multiplications whose only effect, a possible abort, is
/// provably still performed. `None` when nothing was removed.
///
/// - `ecMulGen(<const k>)` cannot abort: its point is the fixed generator,
///   which passes ecMul's operand gate, and the ladder reduces any k.
/// - `ecMul(q, <const k>)` aborts exactly when its operand gate
///   `q === O || ecOnCurve(q)` fails (R-157). It may go when a WITNESS
///   performs the same gate: another `ecMul(q', _)`, q' the same binding as q
///   (F-269), not itself removable, in the same scope or an ENCLOSING one —
///   never a nested one, which runs only on some paths.
/// - `ecNegate` is never removed: R7, R8 and R8r rely on it as a gate.
///
/// Only a removal candidate goes (a name referenced before the EC pass ran —
/// the inner call a fusion orphaned), referenced nowhere in the method now,
/// not a private method's return value (F-108) and not one of its if's
/// `results`.
fn remove_gate_subsumed_ec_calls(method: &ANFMethod, candidates: &HashSet<String>) -> Option<ANFMethod> {
    let mut value_map = ValueMap::new(collect_rebound_names(method));
    let mut refs: HashSet<String> = HashSet::new();
    fn index(bindings: &[ANFBinding], vm: &mut ValueMap, refs: &mut HashSet<String>) {
        for b in bindings {
            vm.insert(b.name.clone(), b.value.clone());
            super::dce::collect_refs_from_value(&b.value, refs);
            match &b.value {
                ANFValue::If { then, else_branch, .. } => {
                    index(then, vm, refs);
                    index(else_branch, vm, refs);
                }
                ANFValue::Loop { body, .. } => index(body, vm, refs),
                _ => {}
            }
        }
    }
    index(&method.body, &mut value_map, &mut refs);
    let keep_last = method.name != "constructor" && !method.is_public;

    struct Ctx<'a> {
        vm: ValueMap,
        refs: HashSet<String>,
        cands: &'a HashSet<String>,
    }
    impl Ctx<'_> {
        fn is_const_scalar(&self, name: &str) -> bool {
            self.vm.get(name).and_then(get_const_int).is_some()
        }
        fn removable(&self, b: &ANFBinding, protect: &HashSet<String>, is_return: bool) -> bool {
            if is_return || !self.cands.contains(&b.name) || self.refs.contains(&b.name) || protect.contains(&b.name) {
                return false;
            }
            match &b.value {
                ANFValue::Call { func, args } if func == "ecMulGen" => {
                    args.len() == 1 && self.is_const_scalar(&args[0])
                }
                ANFValue::Call { func, args } if func == "ecMul" => {
                    args.len() == 2 && self.is_const_scalar(&args[1]) && self.vm.stable(&args[0])
                }
                _ => false,
            }
        }
        fn filter(
            &self,
            bindings: &[ANFBinding],
            outer: &[String],
            protect: &HashSet<String>,
            top_level: bool,
            keep_last: bool,
        ) -> Option<Vec<ANFBinding>> {
            let n = bindings.len();
            let is_cand: Vec<bool> = bindings
                .iter()
                .enumerate()
                .map(|(i, b)| self.removable(b, protect, top_level && keep_last && i + 1 == n))
                .collect();
            let mut witnesses: Vec<String> = outer.to_vec();
            for (i, b) in bindings.iter().enumerate() {
                if let ANFValue::Call { func, args } = &b.value {
                    if !is_cand[i] && func == "ecMul" && args.len() == 2 {
                        if let Some(c) = self.vm.canonical(&args[0]) {
                            witnesses.push(c);
                        }
                    }
                }
            }
            let mut changed = false;
            let mut out: Vec<ANFBinding> = Vec::with_capacity(n);
            for (i, b) in bindings.iter().enumerate() {
                if is_cand[i] {
                    if let ANFValue::Call { func, args } = &b.value {
                        let gated = func == "ecMulGen"
                            || self.vm.canonical(&args[0]).is_some_and(|c| witnesses.contains(&c));
                        if gated {
                            changed = true;
                            continue;
                        }
                    }
                }
                match &b.value {
                    ANFValue::If { cond, then, else_branch, results } => {
                        let rs: HashSet<String> = results.iter().cloned().collect();
                        let t = self.filter(then, &witnesses, &rs, false, keep_last);
                        let e = self.filter(else_branch, &witnesses, &rs, false, keep_last);
                        if t.is_some() || e.is_some() {
                            changed = true;
                            let mut nb = b.clone();
                            nb.value = ANFValue::If {
                                cond: cond.clone(),
                                then: t.unwrap_or_else(|| then.clone()),
                                else_branch: e.unwrap_or_else(|| else_branch.clone()),
                                results: results.clone(),
                            };
                            out.push(nb);
                            continue;
                        }
                    }
                    ANFValue::Loop { body, .. } => {
                        if let Some(nbody) = self.filter(body, &witnesses, &HashSet::new(), false, keep_last) {
                            changed = true;
                            let mut nb = b.clone();
                            if let ANFValue::Loop { body: ref mut bb, .. } = nb.value {
                                *bb = nbody;
                            }
                            out.push(nb);
                            continue;
                        }
                    }
                    _ => {}
                }
                out.push(b.clone());
            }
            if changed { Some(out) } else { None }
        }
    }

    let ctx = Ctx { vm: value_map, refs, cands: candidates };
    let body = ctx.filter(&method.body, &[], &HashSet::new(), true, keep_last)?;
    let mut m = method.clone();
    m.body = body;
    Some(m)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFProperty, ANFValue};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_program(bindings: Vec<ANFBinding>) -> ANFProgram {
        ANFProgram {
            contract_name: "Test".to_string(),
            parent_class: String::new(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "test".to_string(),
                params: vec![],
                body: bindings,
                is_public: true,
                sighash_type: None,
            }],
        }
    }

    fn load_const_hex(name: &str, hex: &str) -> ANFBinding {
        ANFBinding {
            name: name.to_string(),
            value: ANFValue::LoadConst {
                value: serde_json::Value::String(hex.to_string()),
            },
            source_loc: None,
        }
    }

    fn load_const_int(name: &str, n: i64) -> ANFBinding {
        ANFBinding {
            name: name.to_string(),
            value: ANFValue::LoadConst {
                value: serde_json::json!(n),
            },
            source_loc: None,
        }
    }

    fn call_binding(name: &str, func: &str, args: Vec<&str>) -> ANFBinding {
        ANFBinding {
            name: name.to_string(),
            value: ANFValue::Call {
                func: func.to_string(),
                args: args.into_iter().map(|s| s.to_string()).collect(),
            },
            source_loc: None,
        }
    }

    fn assert_binding(name: &str, value_ref: &str) -> ANFBinding {
        ANFBinding {
            name: name.to_string(),
            value: ANFValue::Assert {
                value: value_ref.to_string(),
                is_auto_injected_state_check: false,
            },
            source_loc: None,
        }
    }

    fn find_binding<'a>(bindings: &'a [ANFBinding], name: &str) -> Option<&'a ANFBinding> {
        bindings.iter().find(|b| b.name == name)
    }

    fn get_method_body(program: &ANFProgram) -> &[ANFBinding] {
        &program.methods[0].body
    }

    fn infinity_hex() -> String {
        INFINITY_HEX.to_string()
    }

    fn g_hex() -> String {
        G_HEX.to_string()
    }

    fn some_point() -> String {
        "ab".repeat(64)
    }

    // -----------------------------------------------------------------------
    // Pass-through behavior (no EC ops)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pass_through_no_ec_ops() {
        let bindings = vec![
            load_const_int("t0", 42),
            load_const_int("t1", 10),
            ANFBinding {
                name: "t2".to_string(),
                value: ANFValue::BinOp {
                    op: "+".to_string(),
                    left: "t0".to_string(),
                    right: "t1".to_string(),
                    result_type: None,
                },
                source_loc: None,
            },
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);

        let body = get_method_body(&result);
        assert_eq!(body.len(), 4, "expected 4 bindings, got {}", body.len());
        assert_eq!(body[0].name, "t0");
        assert_eq!(body[1].name, "t1");
        assert_eq!(body[2].name, "t2");
        assert_eq!(body[3].name, "t3");
    }

    #[test]
    fn test_pass_through_empty_method() {
        let program = make_program(vec![]);
        let result = optimize_ec(program);
        assert_eq!(get_method_body(&result).len(), 0);
    }

    // -----------------------------------------------------------------------
    // Rule 1: ecAdd(x, INFINITY) -> alias to x
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule1_ec_add_x_infinity() {
        let bindings = vec![
            load_const_hex("t0", &some_point()),
            load_const_hex("t1", &infinity_hex()),
            call_binding("t2", "ecAdd", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::LoadConst { value } => {
                let name = value.as_str().unwrap();
                assert_eq!(name, "@ref:t0", "expected @ref:t0, got {name}");
            }
            other => panic!("expected LoadConst, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 2: ecAdd(INFINITY, x) -> alias to x
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule2_ec_add_infinity_x() {
        let bindings = vec![
            load_const_hex("t0", &infinity_hex()),
            load_const_hex("t1", &"cd".repeat(64)),
            call_binding("t2", "ecAdd", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::LoadConst { value } => {
                let name = value.as_str().unwrap();
                assert_eq!(name, "@ref:t1", "expected @ref:t1, got {name}");
            }
            other => panic!("expected LoadConst, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 3: ecMul(x, 1) -> alias to x
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule3_ec_mul_by_one() {
        let bindings = vec![
            load_const_hex("t0", &some_point()),
            load_const_int("t1", 1),
            call_binding("t2", "ecMul", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::LoadConst { value } => {
                let name = value.as_str().unwrap();
                assert_eq!(name, "@ref:t0", "expected @ref:t0, got {name}");
            }
            other => panic!("expected LoadConst, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 4: ecMul(x, 0) -> INFINITY
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule4_ec_mul_by_zero() {
        let bindings = vec![
            load_const_hex("t0", &some_point()),
            load_const_int("t1", 0),
            call_binding("t2", "ecMul", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::LoadConst { value } => {
                assert_eq!(
                    value.as_str(),
                    Some(INFINITY_HEX),
                    "expected INFINITY, got {value}"
                );
            }
            other => panic!("expected LoadConst(INFINITY), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 5: ecMulGen(0) -> INFINITY
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule5_ec_mulgen_zero() {
        let bindings = vec![
            load_const_int("t0", 0),
            call_binding("t1", "ecMulGen", vec!["t0"]),
            assert_binding("t2", "t1"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t1 = find_binding(body, "t1").expect("expected binding t1");
        match &t1.value {
            ANFValue::LoadConst { value } => {
                assert_eq!(
                    value.as_str(),
                    Some(INFINITY_HEX),
                    "expected INFINITY, got {value}"
                );
            }
            other => panic!("expected LoadConst(INFINITY), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 6: ecMulGen(1) -> G
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule6_ec_mulgen_one() {
        let bindings = vec![
            load_const_int("t0", 1),
            call_binding("t1", "ecMulGen", vec!["t0"]),
            assert_binding("t2", "t1"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t1 = find_binding(body, "t1").expect("expected binding t1");
        match &t1.value {
            ANFValue::LoadConst { value } => {
                assert_eq!(
                    value.as_str(),
                    Some(G_HEX),
                    "expected G, got {value}"
                );
            }
            other => panic!("expected LoadConst(G), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 7: ecNegate(ecNegate(x)) -> alias to x
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule7_double_negate() {
        let bindings = vec![
            load_const_hex("t0", &some_point()),
            call_binding("t1", "ecNegate", vec!["t0"]),
            call_binding("t2", "ecNegate", vec!["t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::LoadConst { value } => {
                let name = value.as_str().unwrap();
                assert_eq!(name, "@ref:t0", "expected @ref:t0, got {name}");
            }
            other => panic!("expected LoadConst, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule8_add_negate() {
        let bindings = vec![
            load_const_hex("t0", &some_point()),
            call_binding("t1", "ecNegate", vec!["t0"]),
            call_binding("t2", "ecAdd", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::LoadConst { value } => {
                assert_eq!(
                    value.as_str(),
                    Some(INFINITY_HEX),
                    "expected INFINITY, got {value}"
                );
            }
            other => panic!("expected LoadConst(INFINITY), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 8r (ec-add-negate-cancel-reversed): ecAdd(ecNegate(x), x) -> INFINITY
    //
    // The operand order rule 8 above does NOT cover. optimizer/ec-rules.json
    // declares both directions with no "supported" tag; only the Go tier
    // implemented this one (R-034 / CL-BUG-028).
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule8r_add_negate_reversed() {
        let bindings = vec![
            load_const_hex("t0", &some_point()),
            call_binding("t1", "ecNegate", vec!["t0"]),
            call_binding("t2", "ecAdd", vec!["t1", "t0"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::LoadConst { value } => {
                assert_eq!(
                    value.as_str(),
                    Some(INFINITY_HEX),
                    "expected INFINITY, got {value}"
                );
            }
            other => panic!("expected LoadConst(INFINITY), got {other:?}"),
        }
    }

    /// CONTROL: distinct points must NOT cancel — folding this would be a
    /// wrong answer, not a faster one.
    #[test]
    fn test_rule8r_control_distinct_points_do_not_fold() {
        let bindings = vec![
            load_const_hex("p", &some_point()),
            load_const_hex("q", &g_hex()),
            call_binding("neg", "ecNegate", vec!["q"]),
            call_binding("t0", "ecAdd", vec!["neg", "p"]),
            assert_binding("t1", "t0"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);
        let t0 = find_binding(body, "t0").expect("expected binding t0");
        match &t0.value {
            ANFValue::Call { func, .. } => assert_eq!(func, "ecAdd"),
            other => panic!("expected the ecAdd to survive, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 12: ecMul(G, k) -> ecMulGen(k)
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule12_mul_g_to_mulgen() {
        let bindings = vec![
            load_const_hex("t0", &g_hex()),
            load_const_int("t1", 42),
            call_binding("t2", "ecMul", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::Call { func, args } => {
                assert_eq!(func, "ecMulGen", "expected ecMulGen, got {func}");
                assert_eq!(args, &["t1"], "expected args [t1], got {args:?}");
            }
            other => panic!("expected Call(ecMulGen), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Dead binding elimination
    // -----------------------------------------------------------------------

    #[test]
    fn test_dead_binding_removed() {
        // ecAdd(t0, INFINITY) rewrites t2 to @ref:t0.
        // t1 (INFINITY constant) is then unreferenced and should be removed.
        let bindings = vec![
            load_const_hex("t0", &some_point()),
            load_const_hex("t1", &infinity_hex()),
            call_binding("t2", "ecAdd", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let names: Vec<&str> = body.iter().map(|b| b.name.as_str()).collect();
        assert!(
            !names.contains(&"t1"),
            "expected dead binding t1 (INFINITY) to be eliminated, but it is still present"
        );
    }

    // -----------------------------------------------------------------------
    // Non-EC builtins pass through unchanged
    // -----------------------------------------------------------------------

    #[test]
    fn test_non_ec_call_unchanged() {
        // hash160 is not an EC intrinsic — it must survive the optimizer intact.
        let bindings = vec![
            load_const_hex("t0", &"ab".repeat(33)),
            ANFBinding {
                name: "t1".to_string(),
                value: ANFValue::Call {
                    func: "hash160".to_string(),
                    args: vec!["t0".to_string()],
                },
                source_loc: None,
            },
            assert_binding("t2", "t1"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t1 = find_binding(body, "t1").expect("expected hash160 binding t1 to be present");
        match &t1.value {
            ANFValue::Call { func, args } => {
                assert_eq!(func, "hash160", "expected hash160 call preserved, got {func}");
                assert_eq!(args, &["t0"], "expected args [t0], got {args:?}");
            }
            other => panic!("expected Call(hash160), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Side-effect bindings survive dead-binding elimination
    // -----------------------------------------------------------------------

    #[test]
    fn test_side_effect_bindings_preserved() {
        // An assert binding whose result is never referenced must not be
        // eliminated by dead-binding elimination, because it has a side effect.
        let bindings = vec![
            load_const_int("t0", 1),
            // assert is a side effect — must not be eliminated even if unreferenced
            assert_binding("t1", "t0"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let names: Vec<&str> = body.iter().map(|b| b.name.as_str()).collect();
        assert!(
            names.contains(&"t1"),
            "expected assert binding t1 to be preserved as side effect, but it was eliminated. bindings: {names:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Program structure preserved
    // -----------------------------------------------------------------------

    #[test]
    fn test_contract_name_preserved() {
        let program = ANFProgram {
            contract_name: "MyContract".to_string(),
            parent_class: String::new(),
            properties: vec![ANFProperty {
                name: "x".to_string(),
                prop_type: "bigint".to_string(),
                readonly: true,
                initial_value: None,
                synthetic_array_chain: None,
            }],
            methods: vec![ANFMethod {
                name: "doStuff".to_string(),
                params: vec![ANFParam {
                    name: "y".to_string(),
                    param_type: "bigint".to_string(),
                }],
                body: vec![
                    load_const_int("t0", 1),
                    assert_binding("t1", "t0"),
                ],
                is_public: true,
                sighash_type: None,
            }],
        };

        let result = optimize_ec(program);

        assert_eq!(result.contract_name, "MyContract");
        assert_eq!(result.properties.len(), 1);
        assert_eq!(result.properties[0].name, "x");
        assert_eq!(result.methods.len(), 1);
        assert_eq!(result.methods[0].name, "doStuff");
    }

    #[test]
    fn test_multiple_methods_all_optimized() {
        let program = ANFProgram {
            contract_name: "Test".to_string(),
            parent_class: String::new(),
            properties: vec![],
            methods: vec![
                ANFMethod {
                    name: "method1".to_string(),
                    params: vec![],
                    body: vec![
                        load_const_int("t0", 0),
                        call_binding("t1", "ecMulGen", vec!["t0"]),
                        assert_binding("t2", "t1"),
                    ],
                    is_public: true,
                    sighash_type: None,
                },
                ANFMethod {
                    name: "method2".to_string(),
                    params: vec![],
                    body: vec![
                        load_const_int("t0", 1),
                        call_binding("t1", "ecMulGen", vec!["t0"]),
                        assert_binding("t2", "t1"),
                    ],
                    is_public: true,
                    sighash_type: None,
                },
            ],
        };

        let result = optimize_ec(program);

        assert_eq!(result.methods.len(), 2);

        // method1: ecMulGen(0) -> INFINITY
        let body1 = &result.methods[0].body;
        let t1m1 = find_binding(body1, "t1").expect("expected t1 in method1");
        match &t1m1.value {
            ANFValue::LoadConst { value } => {
                assert_eq!(value.as_str(), Some(INFINITY_HEX), "method1 t1: expected INFINITY");
            }
            other => panic!("method1 t1: expected LoadConst(INFINITY), got {other:?}"),
        }

        // method2: ecMulGen(1) -> G
        let body2 = &result.methods[1].body;
        let t1m2 = find_binding(body2, "t1").expect("expected t1 in method2");
        match &t1m2.value {
            ANFValue::LoadConst { value } => {
                assert_eq!(value.as_str(), Some(G_HEX), "method2 t1: expected G");
            }
            other => panic!("method2 t1: expected LoadConst(G), got {other:?}"),
        }
    }
}

/// N-104: the EC identity rewrites R1-R4 must leave the replaced builtin's
/// operand validation in place of the call. Pins the exact gate bindings —
/// names, kinds, operands, order — that every tier emits (the "gate" entries in
/// optimizer/ec-rules.json), so the seven tiers stay ANF- and hex-identical.
/// Proves this tier emits the gate; the gate's script semantics are executed on
/// the real Spend engine by
/// packages/runar-testing/src/__tests__/n104-ec-optimizer-operand-gate.test.ts.
#[cfg(test)]
mod n104_tests {
    use super::*;

    const FIELD_P_DEC: &str =
        "115792089237316195423570985008687907853269984665640564039457584007908834671663";

    fn bnd(name: &str, value: ANFValue) -> ANFBinding {
        ANFBinding { name: name.to_string(), value, source_loc: None }
    }

    fn describe(b: &ANFBinding) -> String {
        let d = match &b.value {
            ANFValue::LoadParam { name } => format!("load_param {name}"),
            ANFValue::LoadConst { value } => match value {
                serde_json::Value::String(s) if s == INFINITY_HEX => "const INFINITY".to_string(),
                serde_json::Value::String(s) if s.starts_with("@ref:") => format!("ref {}", &s[5..]),
                serde_json::Value::String(s) => format!("const {}", s.trim_end_matches('n')),
                other => format!("const {other}"),
            },
            ANFValue::Call { func, args } => format!("call {func} {}", args.join(" ")),
            ANFValue::BinOp { op, left, right, result_type } => match result_type {
                Some(t) => format!("bin_op {op} {left} {right} {t}"),
                None => format!("bin_op {op} {left} {right}"),
            },
            ANFValue::Assert { value, .. } => format!("assert {value}"),
            _ => "other".to_string(),
        };
        format!("{} = {}", b.name, d)
    }

    fn program(scalar_or_inf: ANFBinding, call: ANFValue) -> ANFProgram {
        ANFProgram {
            contract_name: "Test".to_string(),
            parent_class: String::new(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "test".to_string(),
                params: vec![],
                body: vec![
                    bnd("p", ANFValue::LoadParam { name: "pt".to_string() }),
                    scalar_or_inf,
                    bnd("t", call),
                    bnd("a", ANFValue::Assert { value: "t".to_string(), is_auto_injected_state_check: false }),
                ],
                is_public: true,
                sighash_type: None,
            }],
        }
    }

    fn call(func: &str, args: &[&str]) -> ANFValue {
        ANFValue::Call { func: func.to_string(), args: args.iter().map(|s| s.to_string()).collect() }
    }

    fn add_gate() -> Vec<String> {
        vec![
            "t_px = call ecPointX p".to_string(),
            "t_py = call ecPointY p".to_string(),
            format!("t_fp = const {FIELD_P_DEC}"),
            "t_pxok = bin_op < t_px t_fp".to_string(),
            "t_pyok = bin_op < t_py t_fp".to_string(),
            "t_ok = bin_op && t_pxok t_pyok".to_string(),
            "t_gate = assert t_ok".to_string(),
        ]
    }

    fn mul_gate() -> Vec<String> {
        vec![
            "t_inf = const INFINITY".to_string(),
            "t_isinf = bin_op === p t_inf bytes".to_string(),
            "t_oncurve = call ecOnCurve p".to_string(),
            "t_ok = bin_op || t_isinf t_oncurve".to_string(),
            "t_gate = assert t_ok".to_string(),
        ]
    }

    fn expect(gate: Vec<String>, result: &str) -> Vec<String> {
        let mut v = vec!["p = load_param pt".to_string()];
        v.extend(gate);
        v.push(format!("t = {result}"));
        v.push("a = assert t".to_string());
        v
    }

    fn run(p: ANFProgram) -> Vec<String> {
        optimize_ec(p).methods[0].body.iter().map(describe).collect()
    }

    fn inf() -> ANFBinding {
        bnd("inf", ANFValue::LoadConst { value: serde_json::Value::String(INFINITY_HEX.to_string()) })
    }

    fn int(name: &str, n: i64) -> ANFBinding {
        bnd(name, ANFValue::LoadConst { value: serde_json::json!(n) })
    }

    #[test]
    fn n104_ec_add_identity_right_keeps_gate() {
        assert_eq!(run(program(inf(), call("ecAdd", &["p", "inf"]))), expect(add_gate(), "ref p"));
    }

    #[test]
    fn n104_ec_add_identity_left_keeps_gate() {
        assert_eq!(run(program(inf(), call("ecAdd", &["inf", "p"]))), expect(add_gate(), "ref p"));
    }

    #[test]
    fn n104_ec_mul_one_keeps_gate() {
        assert_eq!(run(program(int("one", 1), call("ecMul", &["p", "one"]))), expect(mul_gate(), "ref p"));
    }

    #[test]
    fn n104_ec_mul_zero_keeps_gate() {
        assert_eq!(run(program(int("zero", 0), call("ecMul", &["p", "zero"]))), expect(mul_gate(), "const INFINITY"));
    }

    /// N-251: R8/R8r keep the adder's y = 0 doubling abort (N-110) as
    /// assert(ecPointX(q) === 0 || ecPointY(q) !== 0), ahead of the INFINITY
    /// binding (user decision R96). Pins the gate ANF only; its script
    /// semantics are executed on the real Spend engine, in both optimizer
    /// modes, by packages/runar-testing/src/__tests__/n251-ec-negate-cancel-y0.test.ts.
    fn neg_cancel_expect() -> Vec<String> {
        vec![
            "p = load_param pt".to_string(),
            "n = call ecNegate p".to_string(),
            "t_px = call ecPointX p".to_string(),
            "t_py = call ecPointY p".to_string(),
            "t_zero = const 0".to_string(),
            "t_pxz = bin_op === t_px t_zero".to_string(),
            "t_pynz = bin_op !== t_py t_zero".to_string(),
            "t_ok = bin_op || t_pxz t_pynz".to_string(),
            "t_gate = assert t_ok".to_string(),
            "t = const INFINITY".to_string(),
            "a = assert t".to_string(),
        ]
    }

    #[test]
    fn n251_ec_add_negate_cancel_keeps_y_zero_abort() {
        let neg = bnd("n", call("ecNegate", &["p"]));
        assert_eq!(run(program(neg, call("ecAdd", &["p", "n"]))), neg_cancel_expect());
    }

    #[test]
    fn n251_ec_add_negate_cancel_reversed_keeps_y_zero_abort() {
        let neg = bnd("n", call("ecNegate", &["p"]));
        assert_eq!(run(program(neg, call("ecAdd", &["n", "p"]))), neg_cancel_expect());
    }
}

/// N-218: port of F-343 to this tier. The TS reference's `optimizeBodyOnce`
/// (packages/runar-compiler/src/optimizer/anf-ec.ts) keeps the rewritten
/// binding's source location on every helper binding a rule mints — the
/// N-104 operand gate, the N-251 neg-cancel gate, and the fused-scalar
/// helper — because stack lowering maps opcodes through `binding.source_loc`.
/// Before this fix, `optimize_method_ec_once` pushed every helper with
/// `source_loc: None` regardless of the rewritten binding's own location, so
/// none of a rewritten EC call's gate opcodes reached the source map.
///
/// Proves: a located ecMul(p, 0) rewrite's mul gate (5 bindings), a located
/// ecAdd(p, ecNegate(p)) rewrite's neg-cancel gate (7 bindings), and a located
/// nested-ecMul fusion's `_k` helper all carry the rewritten binding's
/// `source_loc`; an unlocated rewrite mints unlocated helpers.
///
/// Does not prove: exact file/line/column assignment upstream in the ANF
/// lowerer, or end-to-end script-map behavior (covered by the TS test
/// f343-ec-optimizer-source-loc.test.ts and by conformance, which strips
/// `sourceLoc` as debug-only and so cannot regress from this change).
#[cfg(test)]
mod n218_tests {
    use super::*;
    use crate::ir::SourceLocation;

    fn loc() -> SourceLocation {
        SourceLocation { file: "T.runar.ts".to_string(), line: 7, column: 4 }
    }

    fn same_loc(a: &Option<SourceLocation>, b: &SourceLocation) -> bool {
        matches!(a, Some(l) if l.file == b.file && l.line == b.line && l.column == b.column)
    }

    fn located_call(name: &str, func: &str, args: &[&str]) -> ANFBinding {
        ANFBinding {
            name: name.to_string(),
            value: ANFValue::Call {
                func: func.to_string(),
                args: args.iter().map(|s| s.to_string()).collect(),
            },
            source_loc: Some(loc()),
        }
    }

    fn unlocated(name: &str, value: ANFValue) -> ANFBinding {
        ANFBinding { name: name.to_string(), value, source_loc: None }
    }

    fn find<'a>(body: &'a [ANFBinding], name: &str) -> &'a ANFBinding {
        body.iter().find(|b| b.name == name).unwrap_or_else(|| panic!("missing binding {name}"))
    }

    fn program_with(body: Vec<ANFBinding>) -> ANFProgram {
        ANFProgram {
            contract_name: "Test".to_string(),
            parent_class: String::new(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "test".to_string(),
                params: vec![],
                body,
                is_public: true,
                sighash_type: None,
            }],
        }
    }

    #[test]
    fn rule4_mul_gate_carries_source_loc() {
        let body = vec![
            unlocated("p", ANFValue::LoadParam { name: "pt".to_string() }),
            unlocated("zero", ANFValue::LoadConst { value: serde_json::json!(0) }),
            located_call("t", "ecMul", &["p", "zero"]),
            unlocated("a", ANFValue::Assert { value: "t".to_string(), is_auto_injected_state_check: false }),
        ];
        let result = optimize_ec(program_with(body));
        let out = &result.methods[0].body;
        for name in ["t_inf", "t_isinf", "t_oncurve", "t_ok", "t_gate"] {
            let b = find(out, name);
            assert!(same_loc(&b.source_loc, &loc()), "{name}: source_loc = {:?}, want {:?}", b.source_loc, loc());
        }
        let t = find(out, "t");
        assert!(same_loc(&t.source_loc, &loc()), "t: source_loc = {:?}, want {:?}", t.source_loc, loc());
    }

    #[test]
    fn rule8_neg_cancel_gate_carries_source_loc() {
        let body = vec![
            unlocated("p", ANFValue::LoadParam { name: "pt".to_string() }),
            unlocated("n", ANFValue::Call { func: "ecNegate".to_string(), args: vec!["p".to_string()] }),
            located_call("t", "ecAdd", &["p", "n"]),
            unlocated("a", ANFValue::Assert { value: "t".to_string(), is_auto_injected_state_check: false }),
        ];
        let result = optimize_ec(program_with(body));
        let out = &result.methods[0].body;
        for name in ["t_px", "t_py", "t_zero", "t_pxz", "t_pynz", "t_ok", "t_gate"] {
            let b = find(out, name);
            assert!(same_loc(&b.source_loc, &loc()), "{name}: source_loc = {:?}, want {:?}", b.source_loc, loc());
        }
    }

    #[test]
    fn rule9_fused_scalar_helper_carries_source_loc() {
        let body = vec![
            unlocated("p", ANFValue::LoadParam { name: "pt".to_string() }),
            unlocated("k1", ANFValue::LoadConst { value: serde_json::json!(3) }),
            unlocated("k2", ANFValue::LoadConst { value: serde_json::json!(5) }),
            unlocated("inner", ANFValue::Call { func: "ecMul".to_string(), args: vec!["p".to_string(), "k1".to_string()] }),
            located_call("outer", "ecMul", &["inner", "k2"]),
            unlocated("a", ANFValue::Assert { value: "outer".to_string(), is_auto_injected_state_check: false }),
        ];
        let result = optimize_ec(program_with(body));
        let out = &result.methods[0].body;
        let helper = find(out, "outer_k");
        assert!(same_loc(&helper.source_loc, &loc()), "outer_k: source_loc = {:?}, want {:?}", helper.source_loc, loc());
        let outer = find(out, "outer");
        assert!(same_loc(&outer.source_loc, &loc()), "outer: source_loc = {:?}, want {:?}", outer.source_loc, loc());
    }

    #[test]
    fn unlocated_rewrite_mints_unlocated_helpers() {
        let body = vec![
            unlocated("p", ANFValue::LoadParam { name: "pt".to_string() }),
            unlocated("zero", ANFValue::LoadConst { value: serde_json::json!(0) }),
            unlocated("t", ANFValue::Call { func: "ecMul".to_string(), args: vec!["p".to_string(), "zero".to_string()] }),
            unlocated("a", ANFValue::Assert { value: "t".to_string(), is_auto_injected_state_check: false }),
        ];
        let result = optimize_ec(program_with(body));
        for b in &result.methods[0].body {
            assert!(b.source_loc.is_none(), "{}: expected no source_loc, got {:?}", b.name, b.source_loc);
        }
    }
}
