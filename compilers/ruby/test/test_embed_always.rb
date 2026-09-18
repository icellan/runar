# frozen_string_literal: true

require 'tempfile'
require_relative 'test_helper'

# Issue #109 — `/** @embedAlways */` readonly-field DCE opt-out (Ruby tier).
#
# The compiler eliminates a readonly property that no method references (an
# emergent effect of ANF dead-binding DCE: the dead `load_prop` is dropped, so
# no constructor slot is emitted). This silently removes deploy-time metadata
# fields an author intends to recover from the on-chain script later. The
# `/** @embedAlways */` comment directive on a readonly field forces it into the
# locking script (a constructor slot). Honored only on the `.runar.ts` surface.
class TestEmbedAlways < Minitest::Test
  def parse(source, file_name = 'Meta.runar.ts')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  # A stateless contract with a metadata field the body never reads.
  # DIRECTIVE is spliced in immediately before the `metadataId` field.
  def source(directive)
    <<~TS
      import { SmartContract, assert, Addr, PubKey, Sig, ByteString, hash160, checkSig } from 'runar-lang';

      class Meta extends SmartContract {
        readonly pubKeyHash: Addr;
        #{directive}
        readonly metadataId: ByteString;

        constructor(pubKeyHash: Addr, metadataId: ByteString) {
          super(pubKeyHash, metadataId);
          this.pubKeyHash = pubKeyHash;
          this.metadataId = metadataId;
        }

        public unlock(sig: Sig, pubKey: PubKey) {
          assert(hash160(pubKey) === this.pubKeyHash);
          assert(checkSig(sig, pubKey));
        }
      }
    TS
  end

  def compile(directive, fold: false)
    tf = Tempfile.new(['Meta', '.runar.ts'])
    tf.write(source(directive))
    tf.close
    RunarCompiler.compile_from_source(tf.path, disable_constant_folding: !fold)
  ensure
    tf.unlink
  end

  # -------------------------------------------------------------------------
  # Parser
  # -------------------------------------------------------------------------

  def test_jsdoc_directive_sets_embed_always
    r = parse(source('/** @embedAlways */'))
    assert_empty r.errors.map(&:format_message)
    prop = r.contract.properties.find { |p| p.name == 'metadataId' }
    assert prop.embed_always, 'metadataId should be @embedAlways'
    other = r.contract.properties.find { |p| p.name == 'pubKeyHash' }
    refute other.embed_always, 'un-annotated sibling stays unset'
  end

  def test_line_comment_directive_sets_embed_always
    r = parse(source('// @embedAlways'))
    prop = r.contract.properties.find { |p| p.name == 'metadataId' }
    assert prop.embed_always
  end

  def test_no_directive_leaves_embed_always_unset
    r = parse(source(''))
    prop = r.contract.properties.find { |p| p.name == 'metadataId' }
    refute prop.embed_always
  end

  def test_word_boundary_identifier_does_not_trip
    # A field named `embedAlwaysX` in a comment must NOT register a directive.
    r = parse(source('// embedAlwaysX marker'))
    prop = r.contract.properties.find { |p| p.name == 'metadataId' }
    refute prop.embed_always
  end

  # -------------------------------------------------------------------------
  # Preservation through DCE into a constructor slot
  # -------------------------------------------------------------------------

  def test_unannotated_field_is_eliminated
    art = compile('')
    # pubKeyHash is referenced -> 1 slot; metadataId is dead -> no slot.
    assert_equal 1, art.constructor_slots.length
  end

  def test_annotated_field_is_preserved
    art = compile('/** @embedAlways */')
    # Both pubKeyHash and metadataId now carry constructor slots.
    assert_equal 2, art.constructor_slots.length
  end

  def test_annotated_hex_carries_more_bytes
    off = compile('')
    on = compile('/** @embedAlways */')
    refute_equal on.script, off.script
    assert on.script.length > off.script.length,
           "annotated hex (#{on.script.length}) should exceed un-annotated (#{off.script.length})"
  end

  # Preservation must survive the default-ON constant-fold pass too.
  def test_annotated_field_preserved_with_folding_on
    art = compile('/** @embedAlways */', fold: true)
    assert_equal 2, art.constructor_slots.length
  end

  # -------------------------------------------------------------------------
  # Guard narrowing: .runar.ts allowed; other formats fail closed
  # -------------------------------------------------------------------------

  def test_guard_allows_embed_always_on_ts
    r = parse(source('/** @embedAlways */'), 'Meta.runar.ts')
    refute(r.error_strings.any? { |m| m.include?('@embedAlways') },
           "@embedAlways must compile on .runar.ts: #{r.error_strings}")
  end

  def test_guard_rejects_embed_always_on_non_ts
    # A Ruby-format source with the directive marker must still fail closed.
    src = <<~RB
      # @embedAlways
      class Meta < SmartContract
      end
    RB
    r = RunarCompiler.send(:_parse_source, src, 'Meta.runar.rb')
    assert r.errors.any?, 'expected fail-closed error for @embedAlways on .runar.rb'
    assert(r.error_strings.any? { |m| m.include?('@embedAlways') && m.include?('#109') })
  end

  # -------------------------------------------------------------------------
  # Regression: @embedAlways must survive a FIXED-POINT DCE.
  #
  # The preservation used to be an alias pair: the injected +load_prop+ plus a
  # +load_const("@ref:<t>")+ binding whose only job was to make the +load_prop+
  # look referenced. That survives ONE DCE sweep but not the fixed-point loop:
  # sweep 1 drops the now-unreferenced alias, sweep 2 then drops the +load_prop+
  # it was protecting, and BOTH halves vanish.
  #
  # DCE only runs from inside the EC optimizer's changed-gate, so the probe has
  # to arm it: +ecMulGen(1n)+ folds to the generator constant, which flips
  # +changed+ and lets dead-binding elimination run.
  #
  # Zig marks the injected +load_prop+ itself with +preserve = true+ and reads
  # that flag in +has_side_effect+; this tier now does the same.
  # -------------------------------------------------------------------------

  # EC-armed probe. +metadataId+ (param 1) carries DIRECTIVE; +droppedField+
  # (param 2) is an un-annotated, unreferenced control that MUST still be
  # eliminated, so a passing test cannot be satisfied by "retain everything".
  def ec_source(directive)
    <<~TS
      import { SmartContract, assert, Addr, PubKey, Sig, ByteString, hash160, checkSig, ecMulGen, ecPointX } from 'runar-lang';

      class EcMeta extends SmartContract {
        readonly pubKeyHash: Addr;
        #{directive}
        readonly metadataId: ByteString;
        readonly droppedField: ByteString;

        constructor(pubKeyHash: Addr, metadataId: ByteString, droppedField: ByteString) {
          super(pubKeyHash, metadataId, droppedField);
          this.pubKeyHash = pubKeyHash;
          this.metadataId = metadataId;
          this.droppedField = droppedField;
        }

        public unlock(sig: Sig, pubKey: PubKey) {
          const g = ecMulGen(1n);
          assert(ecPointX(g) > 0n);
          assert(hash160(pubKey) === this.pubKeyHash);
          assert(checkSig(sig, pubKey));
        }
      }
    TS
  end

  def compile_ec(directive)
    tf = Tempfile.new(['EcMeta', '.runar.ts'])
    tf.write(ec_source(directive))
    tf.close
    RunarCompiler.compile_from_source(tf.path, disable_constant_folding: true)
  ensure
    tf.unlink
  end

  def test_ec_armed_annotated_field_survives_fixed_point_dce
    art = compile_ec('/** @embedAlways */')
    idx = art.constructor_slots.map(&:param_index).sort
    assert_includes idx, 1, "@embedAlways metadataId dropped by fixed-point DCE (slots: #{idx})"
  end

  def test_ec_armed_unannotated_dead_field_still_eliminated
    # Control: the fix must not degenerate into "keep every load_prop".
    ['', '/** @embedAlways */'].each do |directive|
      art = compile_ec(directive)
      idx = art.constructor_slots.map(&:param_index).sort
      refute_includes idx, 2, "droppedField must stay eliminated (directive=#{directive.inspect})"
    end
  end

  def test_ec_armed_annotated_hex_carries_more_bytes
    off = compile_ec('')
    on = compile_ec('/** @embedAlways */')
    refute_equal on.script, off.script
    assert on.script.length > off.script.length,
           "annotated hex (#{on.script.length}) should exceed un-annotated (#{off.script.length})"
  end
end
