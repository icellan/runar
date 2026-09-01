---
"runar-compiler": minor
"runar-decompiler": patch
---

Shrink the OP_PUSH_TX preimage-binding construction from 760 to 428 bytes (−44% per covenant method) by switching the on-chain ECDSA signature derivation to the Any-S construction: k=1 (r = Gx, eliminating the k⁻¹ multiply and its 33-byte constant), signing key d = 2²⁴⁸·Gx⁻¹ mod n so the r·d addend is built on-stack in 6 bytes, cheaper byte-reversal loops, and DER-encoding s directly from its minimal script-number encoding. The mod-n/low-S normalisation stays branchless, so static-analyzer execution paths are unchanged. Security properties are identical: the signature is still derived on-chain from the pushed preimage and verified with OP_CHECKSIGVERIFY against a fixed public key, so the BUG-100 binding guarantee is preserved. The blob remains a fixed, sighash-flag-patchable constant (unique `01<flag>7e` marker, `7e21<pubkey>ad` tail) pinned byte-identically across all seven compiler tiers; all conformance goldens, analyzer reports, and SDK fixture artifacts are regenerated.
