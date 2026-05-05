#!/usr/bin/env ruby
# frozen_string_literal: true

# ANF interpreter parity driver — Ruby SDK.
#
# See ../PROTOCOL.md for the input/output spec. Reads a single JSON input
# file from ARGV[0], invokes the Ruby SDK's ANF interpreter, and prints the
# result as JSON on stdout. Exits 0 on success, non-zero on any error.

require 'json'
require 'pathname'

DRIVER_DIR = File.expand_path(__dir__)

# packages/runar-rb/lib lives four levels up from this driver file:
#   conformance/anf-interpreter/drivers/ruby/driver.rb
#     -> conformance/anf-interpreter/drivers   (..)
#     -> conformance/anf-interpreter           (../..)
#     -> conformance                           (../../..)
#     -> repo root                             (../../../..)
RUNAR_RB_LIB = File.expand_path('../../../../packages/runar-rb/lib', DRIVER_DIR)
$LOAD_PATH.unshift(RUNAR_RB_LIB) unless $LOAD_PATH.include?(RUNAR_RB_LIB)

require 'runar/sdk/anf_interpreter'

BIGINT_RE = /\A-?\d+n\z/.freeze

# Recursively decode "Xn"-suffixed strings to Ruby Integer.
# Hashes/Arrays are walked; all other values pass through.
def decode_bigints(value)
  case value
  when String
    BIGINT_RE.match?(value) ? value.chomp('n').to_i : value
  when Array
    value.map { |v| decode_bigints(v) }
  when Hash
    value.each_with_object({}) { |(k, v), out| out[k] = decode_bigints(v) }
  else
    value
  end
end

# Recursively re-encode Integers as "Xn" strings (round-trip of decode_bigints).
def encode_bigints(value)
  case value
  when Integer
    "#{value}n"
  when Array
    value.map { |v| encode_bigints(v) }
  when Hash
    value.each_with_object({}) { |(k, v), out| out[k.to_s] = encode_bigints(v) }
  else
    value
  end
end

# Resolve the path to the ANF IR for a given input record.
#
# The protocol spec uses the `anfPath` field. The cross-interpreter inputs
# checked into this repo currently use the shorter `case` form (test name
# under conformance/tests/<case>/expected-ir.json); accept either so the
# driver works against both.
def resolve_anf_path(input, input_file_path)
  if input['anfPath']
    return File.expand_path(input['anfPath'])
  end

  case_name = input['case']
  raise "input must contain either 'anfPath' or 'case' (got keys: #{input.keys.inspect})" unless case_name

  # Walk up from the input file to find the conformance/ root, then descend
  # into tests/<case>/expected-ir.json.
  input_dir = File.dirname(File.expand_path(input_file_path))
  pn = Pathname.new(input_dir)
  conformance_root = nil
  pn.ascend do |p|
    if p.basename.to_s == 'conformance'
      conformance_root = p
      break
    end
  end
  raise "could not locate conformance/ directory walking up from #{input_dir}" unless conformance_root

  File.join(conformance_root.to_s, 'tests', case_name, 'expected-ir.json')
end

def main
  input_path = ARGV[0]
  raise 'usage: driver.rb <input-json-file>' unless input_path

  raw = JSON.parse(File.read(input_path))

  method_name = raw['methodName']
  current_state = decode_bigints(raw['currentState'] || {}) || {}
  args = decode_bigints(raw['args'] || {}) || {}
  constructor_args = decode_bigints(raw['constructorArgs'] || []) || []

  anf_path = resolve_anf_path(raw, input_path)
  anf = JSON.parse(File.read(anf_path))

  state, data_outputs = Runar::SDK::ANFInterpreter.compute_new_state_and_data_outputs(
    anf,
    method_name,
    current_state,
    args,
    constructor_args: constructor_args,
  )

  encoded_state = encode_bigints(state)
  encoded_outputs = (data_outputs || []).map do |out|
    sats = out[:satoshis]
    sats = out['satoshis'] if sats.nil?
    script = out[:script]
    script = out['script'] if script.nil?
    {
      'satoshis' => "#{sats.to_i}n",
      'script' => (script || '').to_s,
    }
  end

  output = {
    'state' => encoded_state,
    'dataOutputs' => encoded_outputs,
  }

  puts JSON.generate(output)
  exit 0
end

begin
  main
rescue StandardError => e
  warn "driver error: #{e.class}: #{e.message}"
  warn e.backtrace.join("\n") if ENV['DEBUG']
  exit 1
end
