# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'runar/sdk'

# N-227 (port of sdk:ts N-085): a zero-mutable-field +StatefulSmartContract+
# call underpays MockProvider's 100 sat/KB fee floor.
#
# +AllReadonlyCleanstack+ has ZERO mutable fields, so its +state_fields+ is
# empty and +call+'s +is_stateful+ is +false+ — even though the contract IS
# +parent_stateful+ (+parent_class == 'StatefulSmartContract'+) and still
# auto-injects +checkPreimage+ / OP_CODESEPARATOR at method entry (its
# +claim+ method carries a visible +txPreimage+ ABI param, so
# +needs_op_push_tx+ is true via a present +preimage_index+). That routes the
# call through the "stateless" branch (+elsif needs_op_push_tx ||
# !sig_indices.empty?+), which — before this fix — never recomputed
# fee/change from the REAL (final) unlocking script the way the
# +is_stateful+ branch's rebuild does.
#
# The injected OP_CODESEPARATOR sits right at method entry, so the BIP-143
# scriptCode (everything after it) is almost the WHOLE locking script — far
# bigger than the generic placeholder preimage the earlier sizing pass
# assumed. The real unlocking script ends up hundreds of bytes bigger than
# what fee/change were computed against, so the broadcast tx pays less than
# the fee its own (larger) byte size requires.
#
# Proves: the Ruby SDK's +claim()+ call on a zero-mutable-field
# StatefulSmartContract broadcasts a tx whose actual fee (computed from the
# REAL broadcast bytes this spec parses itself: sum of known input satoshis
# minus sum of output satoshis) meets the 100 sat/KB floor MockProvider's
# fee rate reports.
#
# Does NOT prove on-chain acceptance: Ruby ships no ScriptVM (see CLAUDE.md),
# and MockProvider's own broadcast check here is value-conservation /
# non-vacuity, not a real script interpreter — the TS/Go/Rust/Python SDK
# tests cover the spend. Also does not prove the same fix in TypeScript
# (already fixed, N-085), Go, Rust, Python, Zig or Java — each tier is a
# separate item slot — nor anything about continuation-bearing (non-empty
# +state_fields+) stateful calls, which already take the +is_stateful+
# branch and were unaffected by this bug.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-227 zero-mutable-field StatefulSmartContract call fee floor' do
  # rubocop:enable RSpec/DescribeClass
  let(:caller_address) { '00' * 20 }
  let(:caller_pub_key) { '02' + ('00' * 32) }

  # Named N227_SRC (not the bare SRC this file used before) because
  # `SRC = ...` directly inside an `RSpec.describe do ... end` block binds a
  # TOP-LEVEL Object constant, not a scoped one — a bare `SRC` here collides
  # with any other spec file that also binds a bare `SRC` (that's exactly
  # what CK18-FU8 found and fixed on the other side of this same collision:
  # issue100_spec.rb's `SRC` was renamed to `I100_SRC`). This is read from
  # inside `def load_artifact`, which opens a new scope, so it must stay a
  # constant rather than become a local (N-269;
  # packages/runar-rb/spec/lint/bare_describe_constants_spec.rb guards
  # against reintroducing a bare one).
  N227_SRC = <<~TS
    import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';

    class AllReadonlyCleanstack extends StatefulSmartContract {
      readonly owner: PubKey;

      constructor(owner: PubKey) {
        super(owner);
        this.owner = owner;
      }

      public claim(sig: Sig): void {
        const ownerCopy = this.owner;
        assert(checkSig(sig, this.owner));
      }
    }
  TS

  def load_artifact(dir)
    compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
    $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
    require 'runar_compiler'
    path = File.join(dir, 'AllReadonlyCleanstack.runar.ts')
    File.write(path, N227_SRC)
    Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
  end

  # Minimal raw-tx hex parser: just enough to sum output satoshis and count
  # inputs. Deliberately independent of any crate/library's internal tx
  # types — reads the standard non-segwit Bitcoin tx wire format directly
  # off the bytes the SDK broadcast.
  def parse_tx(hex_str)
    bytes = [hex_str].pack('H*')
    pos = 0

    read_varint = lambda do
      first = bytes.getbyte(pos)
      pos += 1
      case first
      when 0xfd
        v = bytes[pos, 2].unpack1('v')
        pos += 2
        v
      when 0xfe
        v = bytes[pos, 4].unpack1('V')
        pos += 4
        v
      when 0xff
        v = bytes[pos, 8].unpack1('Q<')
        pos += 8
        v
      else
        first
      end
    end

    pos += 4 # version
    input_count = read_varint.call
    input_count.times do
      pos += 32 + 4 # prev txid + prev index
      script_len = read_varint.call
      pos += script_len
      pos += 4 # sequence
    end
    output_count = read_varint.call
    total_output_satoshis = 0
    output_count.times do
      total_output_satoshis += bytes[pos, 8].unpack1('q<')
      pos += 8
      script_len = read_varint.call
      pos += script_len
    end

    [input_count, total_output_satoshis]
  end

  it 'claim() is accepted by MockProvider with the fee floor enforced' do
    Dir.mktmpdir do |dir|
      art = load_artifact(dir)

      # Sanity on the premise: zero mutable state fields, but still a real
      # StatefulSmartContract (auto-injects checkPreimage).
      expect(art.parent_class).to eq('StatefulSmartContract')
      expect(art.state_fields).to be_empty

      provider = Runar::SDK::MockProvider.new # broadcast validation default-on
      signer = Runar::SDK::MockSigner.new(pub_key_hex: caller_pub_key, address: caller_address)
      provider.add_utxo(caller_address, Runar::SDK::Utxo.new(
        txid: 'aa' * 32, output_index: 0, satoshis: 100_000,
        script: "76a914#{caller_address}88ac"
      ))

      contract = Runar::SDK::RunarContract.new(art, [caller_pub_key])
      contract.deploy(provider, signer, Runar::SDK::DeployOptions.new(satoshis: 5_000, change_address: caller_address))

      # claim(sig, txPreimage): both auto-resolved (nil => SDK fills Sig +
      # SigHashPreimage). is_stateful is false here, so neither param is
      # hidden from the caller — mirrors the TS N-085 repro's [null, null].
      contract.call('claim', [nil, nil], provider, signer)

      call_hex = provider.get_broadcasted_txs.last
      input_count, total_out = parse_tx(call_hex)

      # Total input value: the contract's own deployed UTXO (5000 sats) plus,
      # if more than one input is present, the ONE funding UTXO this spec
      # registered (100000 sats) — this spec controls the entire UTXO
      # universe, so the input count alone determines which UTXOs were spent.
      total_in = 5_000
      total_in += 100_000 if input_count > 1

      actual_fee = total_in - total_out
      fee_rate = provider.get_fee_rate
      tx_size_bytes = call_hex.length / 2
      required_fee = (tx_size_bytes * fee_rate / 1000.0).ceil

      expect(actual_fee).to be >= required_fee,
        "fee too low: paid #{actual_fee} sats, required >= #{required_fee} sats " \
        "(tx size #{tx_size_bytes} bytes, fee rate #{fee_rate} sat/KB)"
    end
  end

  # N-227 Part 2, retargeted by N-258 (user decision R99): a call that spends
  # additional contract inputs on a path with NO real per-input unlock builder
  # must fail closed rather than broadcast an invalid tx.
  #
  # N-227 originally pinned this on the zero-mutable-field AllReadonlyCleanstack.
  # N-258 gave that path real per-input unlocks (n258_zero_mutable_field_merge_spec.rb
  # pins the merge tx to the TS vector @bsv/sdk Spend accepts) and narrowed the
  # guard to the paths that still only have the SIZING placeholder: a plain
  # SmartContract (no auto-injected checkPreimage) or a caller-supplied
  # preimage. This pins the plain SmartContract case. Does NOT prove the
  # caller-supplied-preimage case.
  it 'refuses additional_contract_inputs on a path with no per-input unlock builder' do
    Dir.mktmpdir do |dir|
      compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
      $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
      require 'runar_compiler'
      path = File.join(dir, 'P2PKOnly.runar.ts')
      File.write(path, <<~TS)
        import { SmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';

        class P2PKOnly extends SmartContract {
          readonly owner: PubKey;
          constructor(owner: PubKey) { super(owner); this.owner = owner; }
          public unlock(sig: Sig): void { assert(checkSig(sig, this.owner)); }
        }
      TS
      art = Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
      expect(art.parent_class).to eq('SmartContract')

      provider = Runar::SDK::MockProvider.new
      signer = Runar::SDK::MockSigner.new(pub_key_hex: caller_pub_key, address: caller_address)
      provider.add_utxo(caller_address, Runar::SDK::Utxo.new(
        txid: 'bb' * 32, output_index: 0, satoshis: 100_000,
        script: "76a914#{caller_address}88ac"
      ))
      locking_hex = Runar::SDK::RunarContract.new(art, [caller_pub_key]).get_locking_script
      primary = Runar::SDK::Utxo.new(txid: 'aa' * 32, output_index: 0, satoshis: 5_000, script: locking_hex)
      extra = Runar::SDK::Utxo.new(txid: 'cc' * 32, output_index: 1, satoshis: 7_000, script: locking_hex)
      provider.add_contract_utxo(locking_hex, primary)
      provider.add_contract_utxo("#{locking_hex}:extra", extra)

      contract = Runar::SDK::RunarContract.from_utxo(art, primary)
      expect do
        contract.call('unlock', [nil], provider, signer,
                      Runar::SDK::CallOptions.new(additional_contract_inputs: [extra]))
      end.to raise_error(ArgumentError, /additional_contract_inputs is not supported/)
      expect(provider.get_broadcasted_txs).to be_empty
    end
  end
end
