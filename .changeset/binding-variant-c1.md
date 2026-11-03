---
"runar-compiler": minor
"runar-ir-schema": minor
---

Move the default OP_PUSH_TX preimage binding to the C=1 Any-S key (`038ff83d…`, d = Gx⁻¹ mod n): the addend is now a single `OP_1ADD` after `00 cat bin2num` (5 bytes instead of 11), so the default blob shrinks from 428 to 422 bytes. Every stateful (and every manual-`checkPreimage`) locking script changes; already-deployed UTXOs are unaffected. Adds the per-method `.runar.ts` directive `@bindingVariant <lowS|all>`: `lowS` is the default; `all` emits a 376-byte blob with no mod-n / low-S fixup that is only spendable when the spending transaction has nVersion != 1 (no Rúnar SDK builds such a transaction). The directive is refused on the eight non-TS surfaces. Ports #170 (original design: brendan-elas, #167).
