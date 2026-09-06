import { StatefulSmartContract, num2bin, cat } from 'runar-lang';

/**
 * Num2BinWidths -- source for `num2bin-widths.anf.json` (NEW-013).
 *
 * `num2bin` is the only builtin whose result is BYTES DERIVED FROM A NUMBER,
 * and for negative values every SDK but Java put the sign bit in the wrong
 * place: on the last magnitude byte, with the zero padding after it, so
 * `num2bin(-1n, 2n)` came out `8100` where OP_NUM2BIN yields `0180`.
 *
 * Nothing in the corpus could see it. Of 72 conformance fixtures only four
 * carry a `num2bin` at all, and in every one of them the result is consumed by
 * an `assert` -- so LENIENT interpretation (which skips asserts) never observes
 * the bytes, and STRICT interpretation stops earlier at the stateful
 * `assert(checkPreimage(...))` that the off-chain interpreter cannot satisfy.
 * The parity corpus therefore agreed six-to-one on a wrong encoding.
 *
 * Routing the bytes into `addDataOutput` makes them a first-class part of the
 * lenient result envelope, so `expected/num2bin-*.json` pins them literally and
 * every tier's driver has to reproduce them. The three widths are chosen so ONE
 * input value exercises all three shapes at once:
 *
 *   8  -- padded, sign bit lands on pure padding (the NEW-013 corner)
 *   2  -- exact width for a 2-byte magnitude; the minimal encoding is final
 *   4  -- padded by a different amount, so a fix that hardcodes 8 still fails
 *
 * The `count` bump keeps a state field moving, so a driver that returned an
 * empty envelope would fail on the state comparison rather than pass vacuously.
 */
class Num2BinWidths extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public publish(v: bigint) {
    this.count = this.count + 1n;
    this.addDataOutput(0n, cat(cat(num2bin(v, 8n), num2bin(v, 2n)), num2bin(v, 4n)));
  }
}
