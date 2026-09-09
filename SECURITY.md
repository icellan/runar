# Security Policy

Rúnar is a compiler that emits **on-chain Bitcoin SV Script** — the locking
scripts it produces directly control real funds. We take security reports
seriously and appreciate responsible disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Yes     |
| < 1.0   | ❌ No (pre-release / release-candidate builds) |

Once 1.0.0 ships, security fixes land on the `1.0.x` line.

## Reporting a Vulnerability

Please report security issues **privately** — do not open a public GitHub issue.

- **Preferred:** [GitHub Security Advisories](https://github.com/icellan/runar/security/advisories/new)
  (Security → Advisories → "Report a vulnerability").
- **Email:** siggi.oskarsson@gmail.com

If you can, include a minimal reproduction (source contract + the offending
output) and the affected tier(s) and version.

## Scope

Because the output of this project controls money, the following are in scope
and especially valued:

- **Compiler miscompilations** — any case where a frontend/codegen pass emits
  Bitcoin Script that does not faithfully implement the source contract
  (e.g. a spending path that should be guarded but isn't, stack
  underflow/overflow, an `assert`/`checkSig`/`checkPreimage` that can be
  bypassed). This includes divergence between the seven compiler tiers
  (TypeScript, Go, Rust, Python, Zig, Ruby, Java) for the same source.
- **SDK signing / wire-protocol bugs** — flaws in transaction construction,
  BIP-143 sighash computation, `canonicalJson` serialization, or the
  `signEnvelope`/`verifyEnvelope` signed-broadcast protocol that could produce
  invalid signatures, accept a forged envelope, or diverge across the seven
  deployment SDKs.
- **Cryptographic-primitive flaws** — incorrect codegen for hash, EC
  (secp256k1 / NIST P-256 / P-384), WOTS+, SLH-DSA, BLAKE3, or related
  primitives that weakens or breaks the on-chain check.

## A Note on the Chronicle Opcode Policy

Compiled contracts depend on the **Chronicle** opcode policy (SV Node v1.2.0),
which activated on BSV mainnet at block **943,816** on 7 April 2026. Every
stateful contract carries `OP_2MUL` in its `checkPreimage` binding blob; the EC,
NIST P-256/P-384 and Merkle primitives also emit `OP_2DIV` and `OP_RSHIFTNUM`.

This is a known and intended property of the compiler, not a vulnerability, and
we are not looking for reports that simply restate it. Two consequences are
worth knowing when assessing anything in this repo:

- A validator still on the pre-Chronicle policy hard-fails on `OP_2MUL` /
  `OP_2DIV` with a `disabled opcode` error, but treats `0xb3`–`0xb7` as
  upgradable NOPs. In the second case it does not abort — it computes a wrong
  result and reports success. Do not treat a pass from a pre-Chronicle tool as
  evidence of correctness.
- The regtest configuration in `integration/regtest.sh` sets
  `chronicleactivationheight=1` so a local node enforces the same rules mainnet
  does. A green integration run therefore says nothing about pre-Chronicle
  behaviour, by design.

Details, and the list of affected contract shapes, are in
[`docs/chronicle-opcode-policy.md`](docs/chronicle-opcode-policy.md). A case
where the *emitted policy does not match what the documentation claims* is in
scope and we would like to hear about it.

## A Note on Formal Verification

Rúnar carries a Lean formal-verification effort (`runar-verification/`), but it
is deliberately scoped. It proves **observational (accept/reject) agreement**
for the **back half** of the pipeline — ANF IR → Stack IR → peephole → emit →
bytes → parse → execute — **modulo 70 codegen axioms** (textbook crypto
semantics and per-primitive codegen→runtime bridges). The frontends (the nine
source-format parsers, validation, typecheck, and ANF lowering) are **out of
scope** of the proof.

Rúnar is **not** "formally verified end to end." For the precise, machine-
checked trust boundary — what is proven, what is axiomatized, and what is
deferred — see
[`runar-verification/TRUST_MANIFEST.md`](runar-verification/TRUST_MANIFEST.md).
A vulnerability inside the verified back half, or in a relied-upon axiom, is
very much in scope.

## Response Expectations

- We aim to **acknowledge** a report within **5 business days**.
- We will keep you informed of our assessment and remediation timeline, and
  coordinate disclosure timing with you.
- With your consent, we are happy to credit you in the advisory and release
  notes.
