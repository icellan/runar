/**
 * Probes that exercise the preimage extractors on a CHOSEN preimage.
 *
 * GK-GAP-010: a public method's SigHashPreimage parameter must be asserted via
 * checkPreimage() on every path, and R3-GK010-GAPS refuses a readonly
 * SigHashPreimage property (a preimage fixed in the locking script can never
 * pass checkPreimage()). So a probe declares the preimage as a parameter and
 * opens with `assert(checkPreimage(p))`, and its script is
 *
 *     <prologue> CHECK_PREIMAGE_BINDING_HEX OP_VERIFY  (once per preimage)
 *     <tail>
 *
 * where each prologue is a single-byte stack copy (OP_DUP / OP_OVER) plus
 * OP_CODESEPARATOR. The copy is what the check consumes, so after its
 * OP_VERIFY the stack is exactly the method-entry stack again. The tail is the
 * code under test; running it alone on the unlocking pushes is running the
 * compiled bytes on the stack an accepting checkPreimage leaves behind.
 *
 * The structure is matched EXACTLY from byte 0 (no substring search), so every
 * blob sits on an opcode boundary and nothing else can hide in the prefix.
 */
import { CHECK_PREIMAGE_BINDING_HEX } from 'runar-compiler';

export function afterPreimageChecks(scriptHex: string, prologues: readonly string[]): string {
  let pos = 0;
  for (const [i, prologue] of prologues.entries()) {
    const head = prologue + CHECK_PREIMAGE_BINDING_HEX + '69';
    if (scriptHex.slice(pos, pos + head.length) !== head) {
      throw new Error(
        `check ${i}: expected <${prologue}> CHECK_PREIMAGE_BINDING OP_VERIFY at hex offset ${pos}; script is ${scriptHex}`,
      );
    }
    pos += head.length;
  }
  const tail = scriptHex.slice(pos);
  if (tail.includes(CHECK_PREIMAGE_BINDING_HEX)) {
    throw new Error(`more checkPreimage blobs than the ${prologues.length} expected: ${scriptHex}`);
  }
  return tail;
}
