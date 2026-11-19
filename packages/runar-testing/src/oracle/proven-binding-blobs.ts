/**
 * The OP_PUSH_TX preimage-binding blobs whose exploit resistance is EXECUTED
 * (not argued) by `__tests__/oppushtx-binding.test.ts`: for every entry the
 * genuine BIP-143 preimage is accepted by the real `@bsv/sdk` Spend engine and
 * decoupled / zeroed / wrong-scope / forged-hashOutputs preimages are rejected.
 *
 * `conformance/preimage-binding/preimage-binding.test.ts` accepts a tier's
 * stateful contract only if it carries one of THESE blobs, so adding a flag or
 * variant here without the execution proof running over it is impossible: the
 * proof iterates this same list.
 *
 * Flags: 0x41 ALL|FORKID (default), 0x43 SINGLE|FORKID (D25: every
 * continuation method of a mutate-only stateful contract), 0xC3
 * SINGLE|ANYONECANPAY|FORKID (D25: a mutate-only method annotated
 * ALL|ANYONECANPAY|FORKID).
 */
export const PROVEN_BINDING_FLAGS = [0x41, 0x43, 0xc3] as const;

/** `lowS` spends at nVersion 1; `all` (opt-in `@bindingVariant all`) at nVersion > 1 only. */
export const PROVEN_BINDING_VARIANTS = ['lowS', 'all'] as const;

export type ProvenBindingFlag = (typeof PROVEN_BINDING_FLAGS)[number];
export type ProvenBindingVariant = (typeof PROVEN_BINDING_VARIANTS)[number];
