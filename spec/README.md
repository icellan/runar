# Rúnar Specification

**Formal specification documents for the Rúnar language, type system, semantics, and IR format.**

This directory contains the normative documents that define what Rúnar is. All compiler implementations -- the TypeScript reference compiler, the Go compiler, the Rust compiler, and the Python compiler -- must conform to these specifications.

---

## Document Index

| Document | Description | Status |
|---|---|---|
| [grammar.md](./grammar.md) | Language grammar in EBNF. Defines the exact TypeScript subset that Rúnar accepts: source file structure, contract declarations, property and method syntax, statements, expressions, literals, and the complete list of disallowed TypeScript features. | Draft v0.1.0 |
| [type-system.md](./type-system.md) | Type system rules. Covers the type hierarchy (ByteString and its domain subtypes, bigint and its Rabin subtypes), FixedArray, type inference, affine type rules for UTXO safety, property types (readonly vs mutable), type compatibility, and the type checking algorithm. | Draft v0.1.0 |
| [semantics.md](./semantics.md) | Operational semantics. Defines how Rúnar programs evaluate: the environment and store model, small-step expression evaluation, statement evaluation, assert semantics, method dispatch (single and multiple public methods), private method inlining, state transition semantics (OP_PUSH_TX), the Script execution model, error conditions, and formal properties (termination, determinism, type safety). | Draft v0.1.0 |
| [ir-format.md](./ir-format.md) | ANF IR specification. Defines the canonical intermediate representation: the top-level structure, all ANF binding value tags, type representations, canonical JSON serialization (RFC 8785), transformation rules from source to ANF, short-circuit lowering, validation rules, and extensibility policy. This is the conformance boundary -- all compilers must produce byte-identical ANF IR. | Draft v0.1.0 |
| [artifact-format.md](./artifact-format.md) | Compiled artifact format. Specifies the JSON artifact produced by the compiler containing the locking script, ABI, state field descriptors, source map, and deployment metadata. | Draft v0.1.0 |
| [opcodes.md](./opcodes.md) | Bitcoin SV opcode reference. Complete reference for all opcodes used by Rúnar with hex values, stack effects, and mappings from Rúnar operations to opcodes. | Draft v0.1.0 |
| [abi.md](./abi.md) | Application Binary Interface specification. Defines the constructor and method signatures, parameter types, and method indexing used by the SDK to interact with compiled contracts. | Draft v0.1.0 |
| [stack-ir.md](./stack-ir.md) | Stack IR specification. Defines the intermediate representation between ANF IR and Bitcoin Script: stack instruction types, stack scheduling, and the virtual stack model. | Draft v0.1.0 |
| [frontend-spec.md](./frontend-spec.md) | Frontend specification. Defines requirements for multi-format parser dispatch and frontend implementations across compilers. | Draft v0.1.0 |

---

## How the Spec Relates to Compiler Implementations

The specification is authoritative. If a compiler's behavior contradicts the spec, the compiler has a bug (unless the spec itself is being amended).

```
  Spec Documents
       |
       | defines
       v
  +--------------------+
  |   Conformance      |     golden-file tests derived from spec examples
  |   Test Suite       |
  +--------------------+
       |
       | must pass
       v
  +--------+  +--------+  +--------+  +--------+
  |  TS    |  |  Go    |  |  Rust  |  | Python |
  | Compiler| | Compiler| | Compiler| | Compiler|
  +--------+  +--------+  +--------+  +--------+
```

The conformance test suite in `conformance/` is derived from the spec's examples and rules. A compiler is conformant if and only if it passes the full conformance suite.

---

## Proposing Spec Changes

1. Open an issue describing the proposed change and its rationale.
2. Draft the change as a pull request modifying the relevant spec document.
3. Update the conformance test suite to reflect the change.
4. All four compilers must be updated (or have tracked issues) before the spec change is merged.
5. The spec version number is bumped according to the versioning policy.

---

## Versioning Policy

The spec uses semantic versioning:

- **Major version** (1.0.0): Breaking changes to the language, type system, or IR format. Existing valid programs may become invalid, or the ANF IR format changes in a non-backward-compatible way.
- **Minor version** (0.2.0): New features that are backward-compatible. Existing valid programs remain valid. New ANF value tags may be added.
- **Patch version** (0.1.1): Clarifications, typo fixes, and additional examples. No behavioral changes.

The current version is **0.1.0** (initial draft). All documents carry the same version number and are updated together.
