/**
 * ABI-type → slot value encoding — the single source of truth for HOW a
 * constructor arg of a given ABI type is represented in the locking script.
 *
 * Three consumers used to answer this question with three hand-maintained
 * `switch` statements, and they drifted:
 *
 *   - the compiler's `slotValueEncoding` (artifact/assembler.ts), which stamps
 *     `ConstructorSlot.valueEncoding`
 *   - `runar-cli`'s `encodingForType` (commands/deploy.ts), which parses
 *     `--args`
 *   - the SDK's `interpretScriptElement` (script-utils.ts), which reads the
 *     values back off chain
 *
 * The drift was a funds bug. `RabinSig` / `RabinPubKey` are `bigint` ALIASES
 * (runar-lang/src/types.ts:68-71) and the compiler consumes them with OP_MOD,
 * i.e. as Script NUMBERS — but they were absent from every one of those
 * switches, so the slot was described as an opaque byte push. The CLI then
 * accepted a big-endian hex modulus and spliced it in verbatim for OP_MOD to
 * read little-endian: the covenant can never verify and the output is
 * unspendable. `boolean` (the CANONICAL primitive name — `bool` is the alias)
 * was missing from the read-back switch in six of the seven SDK tiers, with
 * the same shape of consequence.
 *
 * This is the constructor-slot analogue of `STATE_FIELD_WIDTHS`, which does
 * the same job for the state tail. Keep them side by side.
 */

/** How a constructor arg of a given ABI type is encoded into its slot. */
export type AbiValueEncoding = 'data' | 'scriptnum' | 'bool';

/**
 * ABI type name → slot value encoding, for every type that is NOT a plain
 * data push. Types absent from this table encode as `'data'`: a raw push of
 * the value bytes (`PubKey`, `Sha256`, `Point`, `ByteString`, ...).
 *
 * Aliases are listed explicitly rather than resolved, because the ABI carries
 * the SOURCE spelling: a `RabinPubKey` param is written `"type":"RabinPubKey"`
 * in the artifact, never `"bigint"`. `int` is the surface spelling the
 * Solidity/Move/Go/Rust/Python frontends lower to `bigint`.
 */
export const ABI_VALUE_ENCODINGS: Readonly<Record<string, AbiValueEncoding>> = {
  bigint: 'scriptnum',
  int: 'scriptnum',
  // `RabinSig` / `RabinPubKey` are `bigint` aliases. `verifyRabinSig` lowers
  // to OP_MOD, which reads its operand as a little-endian sign-magnitude
  // Script number — exactly what `bigint` gets.
  RabinSig: 'scriptnum',
  RabinPubKey: 'scriptnum',
  // `boolean` is canonical; `bool` is the alias several frontends spell.
  boolean: 'bool',
  bool: 'bool',
};

/** Classify an ABI type name. Unknown / byte types are a raw data push. */
export function abiValueEncoding(type: string): AbiValueEncoding {
  return ABI_VALUE_ENCODINGS[type] ?? 'data';
}
