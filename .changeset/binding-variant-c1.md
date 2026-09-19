---
"runar-compiler": minor
"runar-decompiler": patch
---

Unify the Any-S OP_PUSH_TX preimage-binding onto a single C=1 pubkey (`038ff83d…`) and add a TypeScript-surface `@bindingVariant <lowS|all>` directive. Default `lowS` is `s = lowS((z+1) mod n)` (422 bytes, accepted under nVersion=1 LOW_S). Opt-in `all` is `s = z+1` as-is (376 bytes, valid only for nVersion != 1). Fail-closed on the eight non-TS surfaces. Replay of #167 onto post-#168 main.
