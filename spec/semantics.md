# Rúnar Operational Semantics

**Version:** 0.1.0
**Status:** Draft

This document defines the operational semantics of Rúnar programs. It specifies how Rúnar expressions and statements evaluate, how they relate to Bitcoin Script execution, and the formal rules governing contract behavior.

---

## 1. Overview

Rúnar programs execute in two distinct contexts:

1. **Locking Script Context**: The compiled contract is placed in a transaction output. It encodes the spending conditions.
2. **Unlocking Script Context**: When spending the UTXO, an unlocking script (scriptSig) provides arguments to the public method being invoked.

The Bitcoin Script VM concatenates the unlocking script and locking script, then executes them on a shared stack. A transaction is valid if and only if execution terminates with a non-empty stack whose top element is truthy (non-zero, non-empty).

---

## 2. Evaluation Model

### 2.1 Environments

An **environment** `env` is a finite map from identifiers to values:

```
env : Identifier -> Value
```

A **value** is one of:
- `VInt(n)` -- a bigint value
- `VBool(b)` -- a boolean value
- `VBytes(bs)` -- a byte string value
- `VArray(vs)` -- a fixed array of values

A **store** `sigma` maps property names to values (the contract state):

```
sigma : PropertyName -> Value
```

### 2.2 Configurations

A **configuration** is a tuple `<S, env, sigma>` where:
- `S` is a statement or expression to evaluate
- `env` is the local variable environment
- `sigma` is the contract state (properties)

---

## 3. Expression Evaluation (Small-Step)

We write `<e, env, sigma> --> <e', env', sigma'>` for a single evaluation step, and `<e, env, sigma> -->* <v, env', sigma'>` for multi-step evaluation to a value.

### 3.1 Literals

```
<42n, env, sigma>  -->  VInt(42)

<true, env, sigma>  -->  VBool(true)

<false, env, sigma>  -->  VBool(false)

<toByteString('ab'), env, sigma>  -->  VBytes(0xAB)
```

### 3.2 Variable Lookup

```
    env(x) = v
    ─────────────────────
    <x, env, sigma>  -->  v
```

### 3.3 Property Access

```
    sigma(p) = v
    ──────────────────────────────
    <this.p, env, sigma>  -->  v
```

### 3.4 Binary Operators

Evaluation proceeds left-to-right:

```
    <e1, env, sigma> --> <e1', env, sigma>
    ────────────────────────────────────────────
    <e1 op e2, env, sigma> --> <e1' op e2, env, sigma>

    <e2, env, sigma> --> <e2', env, sigma>
    ────────────────────────────────────────────────────
    <v1 op e2, env, sigma> --> <v1 op e2', env, sigma>
```

When both operands are values:

```
    v1 = VInt(n1)    v2 = VInt(n2)
    ──────────────────────────────────────
    <VInt(n1) + VInt(n2), env, sigma>  -->  VInt(n1 + n2)
    <VInt(n1) - VInt(n2), env, sigma>  -->  VInt(n1 - n2)
    <VInt(n1) * VInt(n2), env, sigma>  -->  VInt(n1 * n2)
    <VInt(n1) / VInt(n2), env, sigma>  -->  VInt(n1 / n2)    /* truncating division */
    <VInt(n1) % VInt(n2), env, sigma>  -->  VInt(n1 % n2)

    v1 = VBytes(b1)    v2 = VBytes(b2)
    ──────────────────────────────────────
    <VBytes(b1) + VBytes(b2), env, sigma>  -->  VBytes(b1 || b2)    /* concatenation */
```

### 3.5 Comparison Operators

```
    v1 = VInt(n1)    v2 = VInt(n2)
    ──────────────────────────────────────
    <VInt(n1) <  VInt(n2), env, sigma>  -->  VBool(n1 <  n2)
    <VInt(n1) <= VInt(n2), env, sigma>  -->  VBool(n1 <= n2)
    <VInt(n1) >  VInt(n2), env, sigma>  -->  VBool(n1 >  n2)
    <VInt(n1) >= VInt(n2), env, sigma>  -->  VBool(n1 >= n2)
```

### 3.6 Equality Operators

```
    v1 : T    v2 : T
    ──────────────────────────────────────
    <v1 === v2, env, sigma>  -->  VBool(v1 = v2)
    <v1 !== v2, env, sigma>  -->  VBool(v1 ≠ v2)
```

Note: `==` and `===` have identical semantics in Rúnar (no type coercion). The compiler accepts both but recommends `===`.

### 3.7 Logical Operators

Eager evaluation (both operands are always evaluated):

```
    <e1, env, sigma> -->* VBool(b1)    <e2, env, sigma> -->* VBool(b2)
    ────────────────────────────────────────────────────────────────────
    <e1 && e2, env, sigma>  -->  VBool(b1 ∧ b2)

    <e1, env, sigma> -->* VBool(b1)    <e2, env, sigma> -->* VBool(b2)
    ────────────────────────────────────────────────────────────────────
    <e1 || e2, env, sigma>  -->  VBool(b1 ∨ b2)
```

`&&` compiles to `OP_BOOLAND` and `||` compiles to `OP_BOOLOR`. Unlike TypeScript's short-circuit semantics, both operands are evaluated unconditionally. This is safe in Rúnar because all expressions are pure (no side effects beyond `assert`).

### 3.8 Unary Operators

```
    <e, env, sigma> -->* VBool(b)
    ─────────────────────────────────
    <!e, env, sigma>  -->  VBool(!b)

    <e, env, sigma> -->* VInt(n)
    ────────────────────────────────
    <-e, env, sigma>  -->  VInt(-n)
```

### 3.9 Ternary Operator

```
    <e_cond, env, sigma> -->* VBool(true)
    <e_then, env, sigma> -->* v
    ──────────────────────────────────────────────────────
    <e_cond ? e_then : e_else, env, sigma>  -->  v

    <e_cond, env, sigma> -->* VBool(false)
    <e_else, env, sigma> -->* v
    ──────────────────────────────────────────────────────
    <e_cond ? e_then : e_else, env, sigma>  -->  v
```

### 3.10 Array Index Access

```
    <e_arr, env, sigma> -->* VArray(vs)
    <e_idx, env, sigma> -->* VInt(i)
    0 <= i < len(vs)
    ──────────────────────────────────────
    <e_arr[e_idx], env, sigma>  -->  vs[i]
```

### 3.11 Function Calls

Built-in functions evaluate their arguments left-to-right, then apply the built-in:

```
    <e1, env, sigma> -->* v1    ...    <en, env, sigma> -->* vn
    f is a built-in function
    result = apply_builtin(f, [v1, ..., vn])
    ────────────────────────────────────────────────
    <f(e1, ..., en), env, sigma>  -->  result
```

### 3.12 Method Calls (Private)

Private method calls are semantically inlined:

```
    method m has params [p1, ..., pn] and body S
    <e1, env, sigma> -->* v1    ...    <en, env, sigma> -->* vn
    env' = env[p1 -> v1, ..., pn -> vn]
    <S, env', sigma> -->* (v_return, sigma')
    ──────────────────────────────────────────────
    <this.m(e1, ..., en), env, sigma>  -->  (v_return, sigma')
```

---

## 4. Statement Evaluation

We write `<S, env, sigma> ==> <env', sigma'>` for statement evaluation.

### 4.1 Variable Declaration

```
    <e, env, sigma> -->* v
    ────────────────────────────────────────────
    <const x = e, env, sigma>  ==>  <env[x -> v], sigma>

    <e, env, sigma> -->* v
    ────────────────────────────────────────────
    <let x = e, env, sigma>  ==>  <env[x -> v], sigma>
```

### 4.2 Assignment

```
    <e, env, sigma> -->* v
    env(x) exists and x was declared with 'let'
    ──────────────────────────────────────────────
    <x = e, env, sigma>  ==>  <env[x -> v], sigma>

    <e, env, sigma> -->* v
    p is a mutable property
    ──────────────────────────────────────────────
    <this.p = e, env, sigma>  ==>  <env, sigma[p -> v]>

    <e, env, sigma> -->* v
    p is a readonly property
    ──────────────────────────────────────────────
    <this.p = e, env, sigma>  ==>  ERROR: cannot assign to readonly property
```

### 4.3 If Statement

```
    <e_cond, env, sigma> -->* VBool(true)
    <S_then, env, sigma> ==> <env', sigma'>
    ──────────────────────────────────────────────
    <if (e_cond) S_then else S_else, env, sigma>  ==>  <env', sigma'>

    <e_cond, env, sigma> -->* VBool(false)
    <S_else, env, sigma> ==> <env', sigma'>
    ──────────────────────────────────────────────
    <if (e_cond) S_then else S_else, env, sigma>  ==>  <env', sigma'>
```

If there is no `else` clause and the condition is false, the environment and store are unchanged.

### 4.4 For Loop (Bounded, Unrolled)

For loops are unrolled at compile time. The semantics describe the unrolled version:

```
    bound = evaluate_const(e_bound)
    init = evaluate_const(e_init)
    iterations = [init, init+1, ..., bound-1]   /* for i < bound, ++ */

    <S_body[i := iterations[0]], env, sigma> ==> <env_1, sigma_1>
    <S_body[i := iterations[1]], env_1, sigma_1> ==> <env_2, sigma_2>
    ...
    <S_body[i := iterations[k]], env_k, sigma_k> ==> <env_final, sigma_final>
    ──────────────────────────────────────────────────────────────────────────────
    <for (let i = e_init; i < e_bound; i++) S_body, env, sigma>
        ==>  <env_final, sigma_final>
```

The loop variable `i` is substituted with the concrete iteration value in each unrolled copy of the body. This means the loop variable is effectively a compile-time constant within each iteration.

### 4.5 Expression Statement

```
    <e, env, sigma> -->* v    (v is discarded)
    ──────────────────────────────────────────
    <e;, env, sigma>  ==>  <env, sigma>
```

### 4.6 Return Statement

```
    <e, env, sigma> -->* v
    ──────────────────────────────────────
    <return e, env, sigma>  ==>  (v, sigma)
```

### 4.7 Statement Sequences

```
    <S1, env, sigma> ==> <env', sigma'>
    <S2, env', sigma'> ==> <env'', sigma''>
    ──────────────────────────────────────────
    <S1; S2, env, sigma>  ==>  <env'', sigma''>
```

---

## 5. Assert Semantics

The `assert` built-in is central to Rúnar. Every public method must end with an `assert` call (or a sequence of asserts).

### 5.1 Basic Assert

```
    <e, env, sigma> -->* VBool(true)
    ──────────────────────────────────────
    <assert(e), env, sigma>  ==>  <env, sigma>

    <e, env, sigma> -->* VBool(false)
    ──────────────────────────────────────
    <assert(e), env, sigma>  ==>  SCRIPT_FAILURE
```

`SCRIPT_FAILURE` means the Bitcoin Script execution fails, the stack top is falsy, and the transaction is **invalid**.

### 5.2 Assert with Message

```
    <assert(e, "msg"), env, sigma>
```

The message string is for developer diagnostics only. It is stripped during compilation and does not appear in the Bitcoin Script.

### 5.3 Compilation

`assert(condition)` compiles to:

```
<condition_code>
OP_VERIFY
```

If `assert` is the **final** statement in the public method, `OP_VERIFY` may be omitted -- the condition value is left on the stack as the script's success/failure indicator.

---

## 6. Method Dispatch Semantics

### 6.1 Single Public Method

When a contract has a single public method, the locking script is simply the compiled body of that method. The unlocking script pushes the method's parameters onto the stack.

```
Unlocking Script: <param_n> ... <param_2> <param_1>
Locking Script:   <compiled_method_body>
```

### 6.2 Multiple Public Methods

When a contract has multiple public methods, the compiler generates a **dispatch table**. The unlocking script includes an additional value indicating which method to invoke.

```
Unlocking Script: <method_params...> <method_index>
Locking Script:
    OP_DUP <0> OP_NUMEQUAL
    OP_IF
        OP_DROP
        <method_0_body>
    OP_ELSE
        OP_DUP <1> OP_NUMEQUAL
        OP_IF
            OP_DROP
            <method_1_body>
        OP_ELSE
            ...
        OP_ENDIF
    OP_ENDIF
```

The method index is a `bigint` starting from `0n`. The order of methods in the dispatch table follows their declaration order in the source.

### 6.3 Private Method Inlining

Private methods do not exist at runtime. They are inlined at every call site:

```typescript
// Source:
private square(x: bigint): bigint {
    return x * x;
}

public verify(n: bigint): void {
    assert(this.square(n) < 100n);
}

// After inlining:
public verify(n: bigint): void {
    assert(n * n < 100n);
}
```

Note: The inlined code uses temporary variables in ANF to avoid duplicating expressions with side effects.

---

## 7. State Transition Semantics

Stateful contracts use the **OP_PUSH_TX** pattern to carry state across transactions. This section formalizes the state transition model.

### 7.1 State Representation

A stateful contract's locking script has the form:

```
<state_data> <locking_code>
```

Where `<state_data>` is the serialized mutable properties followed by `OP_DROP` instructions to remove them from the stack before `<locking_code>` executes (the code reads them via the preimage instead).

More precisely:

```
<prop_n> <prop_n-1> ... <prop_1> OP_DROP ... OP_DROP <code_part>
```

### 7.2 State Transition Rule

```
    sigma_old = {p1: v1, ..., pn: vn}     /* current state */
    <method_body, env, sigma_old> ==> <env', sigma_new>
    sigma_new = {p1: v1', ..., pn: vn'}   /* new state */

    new_locking_script = serialize_state(sigma_new) ++ code_part
    preimage contains output with new_locking_script
    checkPreimage(preimage) succeeds
    ──────────────────────────────────────────────────────────────
    State transition from sigma_old to sigma_new is valid
```

### 7.3 checkPreimage

`this.checkPreimage(preimage)` verifies that the sighash preimage matches the current transaction. This is the mechanism by which the contract can inspect its own outputs and ensure the new state is correctly propagated.

```
    preimage is a valid sighash preimage for the current transaction
    the output script in the preimage matches the expected new locking script
    ──────────────────────────────────────────────────────────────────────────
    <this.checkPreimage(preimage), env, sigma>  -->  VBool(true)

    otherwise
    ──────────────────────────────────────────────────────────────────────────
    <this.checkPreimage(preimage), env, sigma>  -->  VBool(false)
```

### 7.4 getStateScript

`this.getStateScript()` returns the serialized state portion of the locking script, which can be used to construct the expected output:

```
    sigma = {p1: v1, ..., pn: vn}
    serialized = serialize(v1) ++ ... ++ serialize(vn) ++ OP_DROP^n
    ────────────────────────────────────────────────────────────────
    <this.getStateScript(), env, sigma>  -->  VBytes(serialized)
```

### 7.5 Example: Counter Contract State Transition

```
Transaction 1 (Deploy):
    Output[0].script = <0> OP_DROP <counter_code>
                        ^-- initial counter value = 0

Transaction 2 (Increment by 5):
    Input[0].script  = <5> <preimage>     /* amount=5, sighash preimage */
    Output[0].script = <5> OP_DROP <counter_code>
                        ^-- new counter value = 5

    The increment method:
    1. Reads current state from preimage: counter = 0
    2. Computes new state: counter = 0 + 5 = 5
    3. Constructs expected output script: <5> OP_DROP <counter_code>
    4. Verifies preimage matches (output contains expected script)
    5. assert succeeds -> transaction is valid
```

---

## 8. Script Execution Model

### 8.1 Stack Machine

Bitcoin Script is a stack-based language. Rúnar compilation targets this stack machine.

- The stack holds byte vectors.
- Integers are encoded as Script numbers (little-endian, sign-magnitude, minimal encoding).
- Booleans are encoded as `OP_TRUE` (byte `0x01`) or `OP_FALSE` (empty byte vector `0x`).
- The alt-stack is available for temporary storage.

### 8.2 Execution Flow

```
1. Push unlocking script data onto the stack.
2. Execute locking script:
   a. Read parameters from the stack.
   b. Execute method body.
   c. Leave success/failure on top of stack.
3. Script succeeds iff stack top is truthy.
```

### 8.3 Script Size Limits

BSV (post-Genesis) has removed most script size limits, but Rúnar still enforces:

- **Stack depth**: Maximum 800 items (enforced at compile time via static analysis).
- **Script size**: No hard limit, but the compiler will warn if the generated script exceeds 100 KB.

### 8.4 Deterministic Execution

All Rúnar operations are deterministic. Given the same unlocking script and locking script, execution always produces the same result. There is no randomness, no I/O, and no access to external state beyond what is provided in the sighash preimage.

---

## 9. Error Conditions

| Condition | Result |
|---|---|
| `assert(false)` | Script fails, transaction invalid |
| Division by zero | Script fails (`OP_DIV` / `OP_MOD` with 0) |
| Array index out of bounds | Compile-time error (if index is constant) or undefined behavior |
| Stack overflow (>800 items) | Compile-time rejection |
| `OP_RETURN` reached | Script terminates immediately; transaction marked invalid |

---

## 10. Formal Properties

### 10.1 Termination

All Rúnar programs terminate. This is guaranteed by:
- No unbounded loops (all loops have compile-time bounds).
- No recursion (checked via call graph analysis).
- All built-in operations terminate.
- The stack depth is bounded.

### 10.2 Determinism

For any given `(unlocking_script, locking_script)` pair, the execution result is deterministic.

### 10.3 Type Safety

If a Rúnar program type-checks, then at runtime:
- No type errors will occur (all operations receive operands of the correct type).
- No stack underflow will occur (static stack analysis guarantees sufficient items).
- The only runtime failures are explicit `assert` failures and division by zero.

### 10.4 UTXO Safety (Affine Guarantee)

If a Rúnar program passes affine type checking, then:
- `SigHashPreimage` values are used exactly once.
- `Sig` values are not duplicated.
- State transitions are properly guarded by `checkPreimage`.
