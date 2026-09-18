# frozen_string_literal: true

# N-132 — a string +ANFProperty.initialValue+ on the +--ir+ trust boundary.
#
# The string arm of +initialValue+ carries two different things, and the
# discriminator is the trailing +n+ — exactly as it is for +load_const.value+:
#
#   "42n"       a decimal bigint -> the number 42
#   "deadbeef"  a hex ByteString -> the bytes de ad be ef
#
# Ruby implemented NEITHER reading correctly. +_decode_const_value+ applies
# +decimal_bigint_literal?+ to every +load_const+, but +_anf_property_from_hash+
# passed +initialValue+ through untouched, so every string went to the hex arm
# — and that arm is +[s].pack("H*")+, which does not fail on a non-hex
# character: +pack+ maps one to +(c & 15) + (c >> 6) * 9+. Measured:
#
#   "42n"   -> 0x42 0x70   instead of the number 42
#   "-3n"   -> 0x02 0xd370 instead of -3
#   "zz"    -> 0x33        instead of a refusal
#   "5"     -> 0x50        instead of a refusal (odd length)
#
# Every one of those is bytes in a locking script that the IR did not contain,
# and every one of them differed from what Rust, Zig and Java emitted for the
# same input. So this file pins BOTH halves: the bigint arm Ruby was missing,
# and the strictness the hex arm never had.
#
# The probe is a four-byte script — push the property, OP_EQUALVERIFY against
# the parameter — so each assertion is about the property's bytes and nothing
# else.

require 'json'
require_relative 'test_helper'

class TestN132InitialValueString < Minitest::Test
  # secp256k1's group order, minimally encoded as script push data: PUSH33
  # then the 33-byte little-endian sign-magnitude body.
  EC_N = '115792089237316195423570985008687907852837564279074904382605163141518161494337'
  EC_N_PUSH = '21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00'

  # Smallest IR that pushes one property's initialValue. The value is spliced
  # in as raw JSON text so a test can write a string, a number, or a literal of
  # any width without a Ruby type getting an opinion about it first.
  def ir(initial_value_json)
    <<~JSON
      {
        "contractName": "InitProbe",
        "properties": [
          {"name": "v", "type": "bigint", "readonly": true, "initialValue": #{initial_value_json}}
        ],
        "methods": [
          {"name": "constructor", "params": [], "isPublic": false,
           "body": [{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
          {"name": "check", "params": [{"name": "expected", "type": "bigint"}], "isPublic": true,
           "body": [
             {"name": "t0", "value": {"kind": "load_prop", "name": "v"}},
             {"name": "t1", "value": {"kind": "load_param", "name": "expected"}},
             {"name": "t2", "value": {"kind": "bin_op", "left": "t0", "op": "===", "right": "t1"}},
             {"name": "t3", "value": {"kind": "assert", "value": "t2"}}
           ]}
        ]
      }
    JSON
  end

  def script_hex(initial_value_json)
    RunarCompiler.compile_from_ir_bytes(ir(initial_value_json)).script
  end

  # Not "it loads" — "it loads AS the number it spells". A loader that accepted
  # the string and read it as something else passes any does-it-load test and
  # still emits a locking script the IR does not describe. Which is precisely
  # what Ruby did: it accepted "42n" and pushed 0x4270.
  def test_decimal_bigint_string_means_the_integer
    [['"42n"', '42'], ['"-3n"', '-3'], ['"0n"', '0']].each do |str, int|
      assert_equal script_hex(int), script_hex(str),
                   "initialValue #{str} must lower to the same bytes as #{int}"
    end
  end

  # 0 is what every fallback path also produces, so a non-zero case is what
  # makes the equality above mean something. Pin the literal bytes.
  def test_decimal_bigint_string_exact_bytes
    assert_equal '012a7c9c', script_hex('"42n"')
  end

  # The reason the string form exists (issue #121): a value this wide cannot
  # survive a JSON number in a double-backed reader.
  def test_oversize_bigint_string_is_not_truncated
    assert_includes script_hex("\"#{EC_N}n\""), EC_N_PUSH
  end

  # The control an over-broad fix fails: "1000" is the two bytes 0x10 0x00, not
  # one thousand. A tier that reads any all-digit string as decimal passes
  # every other test in this file.
  def test_bare_digit_string_is_hex_not_decimal
    as_hex = script_hex('"1000"')
    as_decimal = script_hex('1000')
    assert_equal '0210007c9c', as_hex
    assert_equal '02e8037c9c', as_decimal
    refute_equal as_hex, as_decimal
  end

  def test_hex_bytestring_still_decodes
    assert_equal '04deadbeef7c9c', script_hex('"deadbeef"')
    assert_equal '007c9c', script_hex('""')
  end

  # A string that is neither form is REFUSED, not decoded into whatever bytes
  # +pack("H*")+ happens to produce. This is the half Ruby had no version of.
  def test_unreadable_string_is_refused
    ['"zz"', '"5"', '"5nn"', '"1.5n"', '"n"', '"-n"'].each do |bad|
      assert_raises(StandardError, "initialValue #{bad} must be refused") do
        RunarCompiler.compile_from_ir_bytes(ir(bad))
      end
    end
  end

  # Vacuity guard: every assertion above rests on this document being the shape
  # it claims, with exactly one property carrying the spliced value.
  def test_probe_ir_is_well_formed
    doc = JSON.parse(ir('42'))
    assert_equal ['v'], doc['properties'].map { |p| p['name'] }
    assert_equal 42, doc['properties'][0]['initialValue']
  end
end
