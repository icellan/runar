# frozen_string_literal: true

require_relative "test_helper"

require "tmpdir"
require "runar_compiler/compiler"

# #180 / #213 / D13: a public method's fixed-width parameter is pinned to its
# declared width at entry (`<copy> OP_SIZE <w> OP_NUMEQUALVERIFY OP_DROP`),
# except a PubKey that only ever reaches checkSig / checkMultiSig / hash160.
# Port of the TypeScript reference pins (05-stack-lower.ts,
# emitFixedWidthParamGate / paramNeedsWidthGate). The expected bytes are the
# TS tier's output for the same sources, in both fold modes.
class TestPrBWidthGates < Minitest::Test
  LOCK_SRC = <<~SRC
    import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
    import type { Point } from 'runar-lang';
    class Lock extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      public lock(p: Point) {
        this.addRawOutput(1000n, cat(cat(toByteString('40'), p), toByteString('87')));
        this.n = this.n + 1n;
        this.addOutput(100000n, this.n);
      }
    }
  SRC

  PAY_TO_KEY_SRC = <<~SRC
    import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
    import type { PubKey } from 'runar-lang';
    class PayToKey extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      public pay(pk: PubKey) {
        this.addRawOutput(1000n, cat(cat(toByteString('21'), pk), toByteString('ac')));
        this.n = this.n + 1n;
        this.addOutput(100000n, this.n);
      }
    }
  SRC

  P2PKH_SRC = <<~SRC
    import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';
    class P2PKH extends SmartContract {
      readonly pubKeyHash: Addr;
      constructor(pubKeyHash: Addr) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
      public unlock(sig: Sig, pubKey: PubKey) {
        assert(hash160(pubKey) === this.pubKeyHash);
        assert(checkSig(sig, pubKey));
      }
    }
  SRC

  HELPER_P2PKH_SRC = <<~SRC
    import { SmartContract, assert, checkSig, hash160 } from 'runar-lang';
    import type { PubKey, Sig, Addr } from 'runar-lang';
    class HelperP2PKH extends SmartContract {
      readonly pkh: Addr;
      constructor(pkh: Addr) { super(pkh); this.pkh = pkh; }
      private verify(s: Sig, k: PubKey): boolean { return checkSig(s, k); }
      public unlock(sig: Sig, pubKey: PubKey) {
        assert(hash160(pubKey) === this.pkh);
        assert(this.verify(sig, pubKey));
      }
    }
  SRC

  PICK_KEY_SRC = <<~SRC
    import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
    import type { PubKey } from 'runar-lang';
    class PickKey extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      public pay(pick: boolean, a: PubKey, b: PubKey) {
        const k = pick ? a : b;
        this.addRawOutput(1000n, cat(cat(toByteString('21'), k), toByteString('ac')));
        this.n = this.n + 1n;
        this.addOutput(100000n, this.n);
      }
    }
  SRC

  ID_KEY_SRC = <<~SRC
    import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
    import type { PubKey } from 'runar-lang';
    class IdKey extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      private id(k: PubKey): PubKey { return k; }
      public pay(pk: PubKey) {
        this.addRawOutput(1000n, cat(cat(toByteString('21'), this.id(pk)), toByteString('ac')));
        this.n = this.n + 1n;
        this.addOutput(100000n, this.n);
      }
    }
  SRC

  def compile_hex(source, file_name, disable)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, source)
      RunarCompiler.compile_from_source(path, disable_constant_folding: disable).script.downcase
    end
  end

  # Occurrences of +sub+ that start on a byte boundary.
  def count_aligned(hex, sub)
    (0..(hex.length - sub.length)).step(2).count { |i| hex[i, sub.length] == sub }
  end

  def test_point_param_and_change_pkh_are_width_gated
    [true, false].each do |disable|
      h = compile_hex(LOCK_SRC, "Lock.runar.ts", disable)
      assert_includes h, "5379820140" + "9d75" + "5279820114" + "9d75", "disable=#{disable}"
      %w[8201409d 8201149d].each do |gate|
        assert_equal 1, count_aligned(h, gate), "disable=#{disable}: #{gate}"
      end
    end
  end

  def test_spliced_pubkey_is_width_gated
    [true, false].each do |disable|
      h = compile_hex(PAY_TO_KEY_SRC, "PayToKey.runar.ts", disable)
      assert_includes h, "5379820121" + "9d75", "disable=#{disable}"
      assert_equal 1, count_aligned(h, "8201219d"), "disable=#{disable}"
    end
  end

  def test_p2pkh_stays_on_standard_template
    [true, false].each do |disable|
      assert_equal "76a90088ac", compile_hex(P2PKH_SRC, "P2PKH.runar.ts", disable), "disable=#{disable}"
    end
  end

  def test_pubkey_verified_through_private_helper_is_not_gated
    [true, false].each do |disable|
      h = compile_hex(HELPER_P2PKH_SRC, "HelperP2PKH.runar.ts", disable)
      refute_includes h, "8201219d", "disable=#{disable}"
    end
  end

  def test_pubkey_through_ternary_arm_is_width_gated
    [true, false].each do |disable|
      h = compile_hex(PICK_KEY_SRC, "PickKey.runar.ts", disable)
      assert_equal 2, count_aligned(h, "8201219d"), "disable=#{disable}"
    end
  end

  def test_pubkey_returned_by_private_helper_is_width_gated
    [true, false].each do |disable|
      h = compile_hex(ID_KEY_SRC, "IdKey.runar.ts", disable)
      assert_equal 1, count_aligned(h, "8201219d"), "disable=#{disable}"
    end
  end
  MERGED_KEY_SRC = <<~'SRC'
    import { StatefulSmartContract, assert } from 'runar-lang';
    import type { PubKey } from 'runar-lang';
    class MergedKey extends StatefulSmartContract {
      closed: bigint = 0n;
      k: PubKey = "000000000000000000000000000000000000000000000000000000000000000000" as PubKey;
      amt: bigint = 0n;
      constructor(seed: bigint) { super(seed); this.closed = seed; }
      public bid(bidderKey: PubKey, bidAmount: bigint) {
        assert(this.closed === 0n);
        let nk = this.k;
        let namt = this.amt;
        if (this.amt === 0n) { nk = bidderKey; namt = bidAmount; }
        else { nk = bidderKey; namt = bidAmount + 1n; }
        this.addOutput(bidAmount, this.closed, nk, namt);
      }
    }
  SRC

  def test_cyclic_merged_local_alias_terminates_and_is_gated
    [true, false].each do |disable|
      h = compile_hex(MERGED_KEY_SRC, "MergedKey.runar.ts", disable)
      assert_includes h, "5479820121" + "9d75", "disable=#{disable}"
      assert_equal 2, count_aligned(h, "8201219d"), "disable=#{disable}"
    end
  end
end
