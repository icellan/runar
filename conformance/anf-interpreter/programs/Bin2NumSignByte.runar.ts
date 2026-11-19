import { StatefulSmartContract, bin2num } from 'runar-lang';
import type { ByteString } from 'runar-lang';

/**
 * Bin2NumSignByte -- source for `bin2num-sign-byte.anf.json` (D12 BM-F1).
 *
 * The sign of a script number is bit 7 of its LAST byte; a trailing 0x00 is
 * sign padding meaning "non-negative". The Zig SDK interpreter stripped that
 * padding first and then read the sign off the previous byte, so
 * `bin2num(ff00)` came out -127 where OP_BIN2NUM yields 255. `ff00` is exactly
 * what `num2bin(255n, 2n)` produces, so a round-trip through num2bin/bin2num
 * of any value whose top byte is >= 0x80 derived a state the covenant refuses.
 *
 * The result goes straight into a state field, so every tier's driver has to
 * reproduce it and the script oracle checks it against a real spend.
 */
class Bin2NumSignByte extends StatefulSmartContract {
  r: bigint;

  constructor(r: bigint) {
    super(r);
    this.r = r;
  }

  public probe(b: ByteString) {
    this.r = bin2num(b);
  }
}
