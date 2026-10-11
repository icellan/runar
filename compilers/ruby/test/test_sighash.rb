# frozen_string_literal: true

require 'tempfile'
require_relative 'test_helper'
require 'runar_compiler/frontend/sighash_directive'

# Issue #123 — @sighash per-method BIP-143 sighash mode (Ruby tier).
class TestSighash < Minitest::Test
  SD = RunarCompiler::Frontend::SighashDirective

  def parse(source, file_name = 'X.runar.ts')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  def method_by_name(src, name)
    r = parse(src)
    assert_empty r.errors.map(&:format_message), 'unexpected parse errors'
    r.contract.methods.find { |m| m.name == name }
  end

  # Full-pipeline compile (parse -> validate -> typecheck -> ANF -> emit) via a
  # Tempfile so the fail-closed guard + validation run. Returns the Artifact.
  def compile(src, fold: false)
    tf = Tempfile.new(['C', '.runar.ts'])
    tf.write(src)
    tf.close
    RunarCompiler.compile_from_source(tf.path, disable_constant_folding: !fold)
  ensure
    tf.unlink
  end

  # A SINGLE-safe stateful counter: emits an explicit single addOutput carrying
  # the protected value at this input's index (the legitimate pairwise covenant).
  # A mutate-only continuation is rejected under SINGLE (F1), so the codegen
  # cases use this shape; it exercises the same mode-aware OP_PUSH_TX flag byte
  # + preimage-type assert as any other method.
  def counter_out(directive)
    <<~TS
      class Counter extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        #{directive}
        public bump(): void { this.addOutput(1000n, this.n); }
      }
    TS
  end

  # -------------------------------------------------------------------------
  # Flag grammar
  # -------------------------------------------------------------------------

  def test_parses_common_combos
    assert_equal({ value: 0x41 }, SD.parse_sighash_flags('ALL|FORKID'))
    assert_equal({ value: 0x43 }, SD.parse_sighash_flags('SINGLE|FORKID'))
    assert_equal({ value: 0x42 }, SD.parse_sighash_flags('NONE|FORKID'))
    assert_equal({ value: 0xc1 }, SD.parse_sighash_flags('ALL|ANYONECANPAY|FORKID'))
  end

  def test_order_independent_and_whitespace_tolerant
    assert_equal({ value: 0x43 }, SD.parse_sighash_flags(' FORKID | SINGLE '))
  end

  def test_default_constant
    assert_equal 0x41, SD::SIGHASH_DEFAULT
    assert_equal({ value: SD::SIGHASH_DEFAULT }, SD.parse_sighash_flags('ALL|FORKID'))
  end

  def test_rejects_unknown_flag
    assert_match(/unknown flag "FORKD"/, SD.parse_sighash_flags('ALL|FORKD')[:error])
  end

  def test_rejects_all_none_on_names_not_aliased_value
    assert_match(/cannot combine base types/, SD.parse_sighash_flags('ALL|NONE|FORKID')[:error])
  end

  def test_rejects_two_base_types
    assert SD.parse_sighash_flags('SINGLE|ALL')[:error]
  end

  def test_rejects_no_base_type
    assert_match(/exactly one base type/, SD.parse_sighash_flags('FORKID|ANYONECANPAY')[:error])
  end

  def test_rejects_duplicate_flags
    assert_match(/duplicate flag/, SD.parse_sighash_flags('SINGLE|SINGLE|FORKID')[:error])
  end

  def test_rejects_empty
    assert SD.parse_sighash_flags('')[:error]
    assert SD.parse_sighash_flags('   ')[:error]
  end

  def test_rejects_missing_forkid
    %w[SINGLE ALL NONE ALL|ANYONECANPAY].each do |flags|
      assert_match(/FORKID is mandatory on BSV/, SD.parse_sighash_flags(flags)[:error], flags)
    end
  end

  def test_accepts_once_forkid_added
    assert_equal({ value: 0x43 }, SD.parse_sighash_flags('SINGLE|FORKID'))
    assert_equal({ value: 0xc1 }, SD.parse_sighash_flags('ALL|ANYONECANPAY|FORKID'))
  end

  def test_extract_from_comment_text
    assert_equal({ value: 0x43 }, SD.extract_sighash_directive('/** @sighash SINGLE|FORKID */'))
    assert_equal({ value: 0x42 }, SD.extract_sighash_directive('// @sighash NONE|FORKID'))
    assert_nil SD.extract_sighash_directive('/** no directive here */')
  end

  def test_describe_sighash_round_trips
    assert_equal 'ALL|FORKID', SD.describe_sighash(0x41)
    assert_equal 'SINGLE|FORKID', SD.describe_sighash(0x43)
    assert_equal 'ALL|ANYONECANPAY|FORKID', SD.describe_sighash(0xc1)
    assert_equal 'NONE|FORKID', SD.describe_sighash(0x42)
  end

  # -------------------------------------------------------------------------
  # Parser
  # -------------------------------------------------------------------------

  def test_sets_sighash_type_from_jsdoc
    src = <<~TS
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        public bump(): void { this.addOutput(1000n, this.n); }
      }
    TS
    assert_equal 0x43, method_by_name(src, 'bump').sighash_type
  end

  def test_undefined_without_directive
    src = <<~TS
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        public bump(): void { this.n = this.n + 1n; }
      }
    TS
    assert_nil method_by_name(src, 'bump').sighash_type
  end

  def test_accepts_line_comment
    src = <<~TS
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        // @sighash NONE|FORKID
        public wipe(): void { this.addDataOutput(0n, "6a"); }
      }
    TS
    assert_equal 0x42, method_by_name(src, 'wipe').sighash_type
  end

  def test_error_for_bad_combo
    src = <<~TS
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash ALL|NONE|FORKID */
        public bump(): void { this.n = this.n + 1n; }
      }
    TS
    r = parse(src)
    assert(r.errors.any? { |e| e.message =~ /cannot combine base types/ })
  end

  def test_error_for_sighash_on_private_method
    src = <<~TS
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        private helper(): bigint { return 1n; }
        public bump(): void { this.n = this.n + 1n; }
      }
    TS
    r = parse(src)
    assert(r.errors.any? { |e| e.message =~ /non-public method/ })
  end

  # -------------------------------------------------------------------------
  # Guard narrowing
  # -------------------------------------------------------------------------

  def test_guard_allows_sighash_on_ts
    src = <<~TS
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        public bump(): void { this.addOutput(1000n, this.n); }
      }
    TS
    r = parse(src, 'C.runar.ts')
    refute(r.error_strings.any? { |m| m.include?('not supported') },
           "@sighash must compile on .runar.ts: #{r.error_strings}")
  end

  def test_guard_rejects_sighash_on_non_ts
    src = "# @sighash SINGLE|FORKID\nclass C < SmartContract\nend\n"
    r = RunarCompiler.send(:_parse_source, src, 'C.runar.rb')
    assert r.errors.any?
    assert(r.error_strings.any? { |m| m.include?('@sighash') && m.include?('#123') })
  end

  # -------------------------------------------------------------------------
  # Codegen parity (Ruby bytes == TS)
  # -------------------------------------------------------------------------

  def test_default_equals_explicit_all_forkid
    no_directive = compile(counter_out(''))
    explicit_all = compile(counter_out('/** @sighash ALL|FORKID */'))
    # ALL|FORKID equals the historically-pinned default → identical script.
    assert_equal no_directive.script, explicit_all.script
  end

  def test_single_forkid_flag_byte
    dflt = compile(counter_out(''))
    single = compile(counter_out('/** @sighash SINGLE|FORKID */'))
    refute_equal dflt.script, single.script
    # SINGLE|FORKID appended as the OP_PUSH_TX flag byte: OP_DATA_1 0x43 = "0143".
    assert_includes single.script, '0143'
    # The default is still pinned to the 0x41 push.
    assert_includes dflt.script, '0141'
    refute_includes single.script, '0141'
  end

  def test_anyonecanpay_flag_byte
    acp = compile(counter_out('/** @sighash ALL|ANYONECANPAY|FORKID */'))
    assert_includes acp.script, '01c1'
  end

  def test_abi_carries_sighash_type
    single = compile(counter_out('/** @sighash SINGLE|FORKID */'))
    dflt = compile(counter_out(''))
    single_bump = single.abi.methods.find { |m| m.name == 'bump' }
    dflt_bump = dflt.abi.methods.find { |m| m.name == 'bump' }
    assert_equal 0x43, single_bump.sig_hash_type
    assert_nil dflt_bump.sig_hash_type
    # And it surfaces in the serialized artifact JSON.
    json = JSON.parse(RunarCompiler.artifact_to_json(single))
    bump = json['abi']['methods'].find { |m| m['name'] == 'bump' }
    assert_equal 0x43, bump['sigHashType']
  end

  def test_anf_preimage_assert_uses_declared_mode
    single = compile(counter_out('/** @sighash SINGLE|FORKID */'))
    json = RunarCompiler.artifact_to_json(single)
    # The expected sighash const 0x43 = 67, and the check_preimage carries the flag.
    assert_includes json, '"sighashFlag": 67'
    # F-263: the runtime preimage-type assert must compare extractSigHashType
    # against the DECLARED mode. A bare `assert_includes json, '67'` was entailed
    # by the line above (and by abi.sigHashType), so it could not catch the
    # expected-const being lowered as the 0x41 default. This proves the
    # `extractSigHashType(pre) === <const>` operand is 67; it does not prove the
    # emitted script bytes or on-chain behaviour (see the codegen tests above).
    bump = JSON.parse(json)['anf']['methods'].find { |m| m['name'] == 'bump' }
    by_name = bump['body'].to_h { |b| [b['name'], b['value']] }
    cmp = bump['body'].map { |b| b['value'] }.find do |v|
      v['kind'] == 'bin_op' && v['op'] == '===' &&
        by_name[v['left']]&.values_at('kind', 'func') == %w[call extractSigHashType]
    end
    refute_nil cmp, 'no extractSigHashType(...) === <const> preimage-type assert in bump'
    expected = by_name[cmp['right']]
    assert_equal 'load_const', expected['kind']
    assert_equal 67, expected['value']
  end

  # The sighash_flag must survive the default-ON constant-fold pass (the Python
  # port caught a fold pass dropping it).
  def test_sighash_survives_constant_folding
    single = compile(counter_out('/** @sighash SINGLE|FORKID */'), fold: true)
    assert_includes single.script, '0143'
    bump = single.abi.methods.find { |m| m.name == 'bump' }
    assert_equal 0x43, bump.sig_hash_type
    json = RunarCompiler.artifact_to_json(single)
    assert_includes json, '"sighashFlag": 67'
  end

  # -------------------------------------------------------------------------
  # Field-usage validation — the 5 security rules (one rejection each)
  # -------------------------------------------------------------------------

  def errors_of(src)
    r = parse(src)
    return r.errors.map(&:message) if r.contract.nil?
    RunarCompiler.send(:_validate, r.contract).errors.map(&:message)
  end

  def warnings_of(src)
    r = parse(src)
    return [] if r.contract.nil?
    RunarCompiler.send(:_validate, r.contract).warnings.map(&:message)
  end

  def compiles?(src)
    r = parse(src)
    return false if r.contract.nil? || r.errors.any?
    RunarCompiler.send(:_validate, r.contract).errors.empty?
  end

  # Rule 1 — ANYONECANPAY rejects extractHashPrevouts (+ extractPrevOutputScript).
  def test_rule1_anyonecanpay_rejects_hashprevouts
    src = <<~TS
      class Guard extends SmartContract {
        readonly expected: ByteString;
        constructor(expected: ByteString) { super(expected); this.expected = expected; }
        /** @sighash ALL|ANYONECANPAY|FORKID */
        public spend(pre: SigHashPreimage): void {
          assert(checkPreimage(pre));
          assert(extractHashPrevouts(pre) === this.expected);
        }
      }
    TS
    assert(errors_of(src).any? { |e| e =~ /hashPrevouts.*zeroed under ANYONECANPAY/ })
    # The same read under the ALL default is accepted.
    ok = src.sub('/** @sighash ALL|ANYONECANPAY|FORKID */', '')
    assert compiles?(ok)
  end

  def test_rule1_anyonecanpay_rejects_prevout_script
    src = <<~TS
      class Co extends StatefulSmartContract {
        readonly h0: ByteString;
        n: bigint;
        constructor(h0: ByteString, n: bigint) { super(h0, n); this.h0 = h0; this.n = n; }
        /** @sighash ALL|ANYONECANPAY|FORKID */
        public coSpend(): void {
          const s = extractPrevOutputScript(1n, this.h0);
          assert(len(s) > 0n);
        }
      }
    TS
    assert(errors_of(src).any? { |e| e =~ /companion input|prevout script/ })
  end

  # Rule 2 — non-pure-ALL rejects extractHashSequence.
  def test_rule2_non_all_rejects_hashsequence
    src = <<~TS
      class Seq extends SmartContract {
        readonly expected: ByteString;
        constructor(expected: ByteString) { super(expected); this.expected = expected; }
        /** @sighash SINGLE|FORKID */
        public spend(pre: SigHashPreimage): void {
          assert(checkPreimage(pre));
          assert(extractHashSequence(pre) === this.expected);
        }
      }
    TS
    assert(errors_of(src).any? { |e| e =~ /hashSequence, which is zeroed under any mode other than SIGHASH_ALL/ })
  end

  # Rule 3 — NONE rejects all output bindings (state continuation here).
  def test_rule3_none_rejects_continuation
    src = <<~TS
      class Counter extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash NONE|FORKID */
        public bump(): void { this.n = this.n + 1n; }
      }
    TS
    assert(errors_of(src).any? { |e| e =~ /NONE commits to NO outputs|continuation/ })
  end

  # Rule 4 — SINGLE rejects a mutate-only continuation (value-skimmable, F1).
  def test_rule4_single_rejects_mutate_only_continuation
    src = <<~TS
      class Counter extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        public bump(): void { this.n = this.n + 1n; }
      }
    TS
    assert(errors_of(src).any? { |e| e =~ /mutate-only SINGLE continuation is unsound|sized by the caller-chosen _newAmount/ })
    refute compiles?(src)
  end

  # Rule 4 — SINGLE rejects >1 committed output.
  def test_rule4_single_rejects_multi_output
    src = <<~TS
      class Multi extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
        /** @sighash SINGLE|FORKID */
        public split(): void {
          this.addOutput(1000n, this.count);
          this.addOutput(2000n, this.count);
        }
      }
    TS
    assert(errors_of(src).any? { |e| e =~ /SINGLE commits ONLY to the output at this input/ })
  end

  # Rule 4 — SINGLE rejects requireOutputP2PKH (fixed index not provably same-index, F4).
  def test_rule4_single_rejects_require_output_p2pkh
    src = <<~TS
      class Cov extends StatefulSmartContract {
        readonly bondPKH: ByteString;
        readonly bond: bigint;
        constructor(bondPKH: ByteString, bond: bigint) { super(bondPKH, bond); this.bondPKH = bondPKH; this.bond = bond; }
        /** @sighash SINGLE|FORKID */
        public payBond() { requireOutputP2PKH(0n, this.bondPKH, this.bond); }
      }
    TS
    assert(errors_of(src).any? { |e| e =~ /'requireOutputP2PKH' asserts an output at a fixed index.*SINGLE/ })
  end

  # Rule 4 — SINGLE allows an explicit single addOutput, with a value-pinning WARNING.
  def test_rule4_single_allows_single_output_with_warning
    src = <<~TS
      class Pay extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        public settle(): void { this.addOutput(1000n, this.n); }
      }
    TS
    assert compiles?(src)
    assert(warnings_of(src).any? { |w| w =~ /SINGLE commits ONLY to the output at this input|carries the FULL protected value/ })
  end

  # F3 — transitive walk covers the for-loop header (condition) under NONE.
  def test_f3_walk_covers_for_loop_condition
    src = <<~TS
      class C extends SmartContract {
        readonly expected: ByteString;
        constructor(expected: ByteString) { super(expected); this.expected = expected; }
        /** @sighash NONE|FORKID */
        public spend(pre: SigHashPreimage): void {
          for (let i = 0n; i < 3n && extractOutputHash(pre) === this.expected; i++) { assert(i < 2n); }
          assert(checkPreimage(pre));
        }
      }
    TS
    assert(errors_of(src).any? { |e| e =~ /hashOutputs.*zeroed under NONE/ })
  end

  # Default (no directive) is never flagged — the same shapes compile.
  def test_default_never_flagged
    src = <<~TS
      class Counter extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        public bump(): void { this.n = this.n + 1n; }
      }
    TS
    assert compiles?(src)
  end
end
