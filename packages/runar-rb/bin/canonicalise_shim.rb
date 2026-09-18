#!/usr/bin/env ruby
# frozen_string_literal: true

# Ruby-tier CLI shim for the cross-tier canonicalJson (RFC 8785 / JCS)
# differential fuzzer (conformance/fuzzer/canonical-json-differential.ts).
#
# Protocol (single-shot, stdin -> stdout), mirrors the Go / Rust / Python /
# Zig shims:
#
#   {"mode":"json","value":<any JSON>}
#       Parse `value` with JSON.parse (Integer and Float are distinct Ruby
#       types, preserving the int-vs-float distinction the interop spec
#       relies on), run Runar::SDK::Envelope.canonical_json, print bytes,
#       exit 0.
#   {"mode":"utf16","key":"<string>","units":[<int>,...]}
#       Build {key => <string from UTF-16 units>} where lone surrogates are
#       emitted as their 3-byte WTF-8 form, so canonical_json's UTF-8 /
#       lone-surrogate guard rejects them.
#   {"mode":"deep","depth":<int>,"shape":"array"|"object"}
#       Build `depth` nested containers around the integer leaf 1, NATIVELY.
#   {"mode":"bigstring","bytes":<int>,"where":"value"|"key"}
#       Build a one-entry Hash whose value (or key) is `bytes` ASCII 'a',
#       NATIVELY, and respond with the SHA-256 of the canonical bytes.
#
#   Why `deep` / `bigstring` describe the value instead of carrying it: see the
#   max_nesting note below. The transport must not impose a limit on the thing
#   under test.
#
#   On a typed rejection the shim prints "RUNAR_CANON_ERR:<message>" to
#   stdout and exits 3; on native stack exhaustion (which is NOT a rejection)
#   it prints "RUNAR_CANON_CRASH:<message>" and exits 3; any other failure
#   exits 1.

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))

require 'digest'
require 'json'
require 'runar/sdk'

DIGEST_PREFIX = 'RUNAR_CANON_SHA256:'

# Build `depth` nested containers around the integer leaf 1, iteratively.
def build_deep(depth, shape)
  v = 1
  depth.times { v = shape == 'array' ? [v] : { 'k' => v } }
  v
end

def build_big_string(nbytes, where)
  s = 'a' * nbytes
  where == 'value' ? { 's' => s } : { s => 1 }
end

def utf16_units_to_string(units)
  bytes = []
  i = 0
  n = units.length
  while i < n
    u = units[i]
    if u >= 0xD800 && u <= 0xDBFF && i + 1 < n && units[i + 1] >= 0xDC00 && units[i + 1] <= 0xDFFF
      cp = 0x10000 + ((u - 0xD800) << 10) + (units[i + 1] - 0xDC00)
      bytes.concat(codepoint_to_utf8(cp))
      i += 2
      next
    end
    bytes.concat(codepoint_to_utf8(u))
    i += 1
  end
  # Force UTF-8 so canonical_json's valid_encoding? / surrogate guard fires.
  bytes.pack('C*').force_encoding('UTF-8')
end

def codepoint_to_utf8(cp)
  if cp < 0x80
    [cp]
  elsif cp < 0x800
    [0xC0 | (cp >> 6), 0x80 | (cp & 0x3F)]
  elsif cp < 0x10000
    [0xE0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F)]
  else
    [0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3F), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F)]
  end
end

raw = $stdin.read
begin
  # max_nesting: false — the REQUEST parser must not be the thing that limits
  # how deep a case can be. Ruby's JSON.parse defaults to max_nesting: 100, and
  # with that default this shim reported "parse request: nesting of 101 is too
  # deep" on stderr with exit 1 for any deep case, never calling canonical_json
  # at all. Read as a rejection, that made Ruby look like it AGREED with the TS
  # reference's depth guard; Ruby's canonical_json in fact has no depth guard —
  # handed a natively-built depth-600 array it returns 1201 bytes. The harness
  # was manufacturing the very agreement it existed to test for.
  req = JSON.parse(raw, max_nesting: false)
rescue StandardError => e
  warn "parse request: #{e}"
  exit 1
end

case req['mode']
when 'json'
  value = req['value']
when 'utf16'
  value = { req['key'].to_s => utf16_units_to_string(req['units'] || []) }
when 'deep'
  value = build_deep(req['depth'].to_i, req['shape'] || 'array')
when 'bigstring'
  value = build_big_string(req['bytes'].to_i, req['where'] || 'value')
else
  warn "unknown mode #{req['mode'].inspect}"
  exit 1
end

begin
  out = Runar::SDK::Envelope.canonical_json(value)
rescue ArgumentError, TypeError, KeyError => e
  $stdout.write("RUNAR_CANON_ERR:#{e.message}")
  exit 3
rescue SystemStackError
  # Native stack exhaustion is not the typed rejection a guard produces, so it
  # carries the CRASH prefix, not the REJECT prefix: the driver normalises
  # every REJECT to one token, and RUNAR_CANON_ERR here would score a tier that
  # DIED as agreeing with a tier that rejected cleanly.
  $stdout.write('RUNAR_CANON_CRASH:SystemStackError (native stack, not a guard)')
  exit 3
end
if req['mode'] == 'bigstring'
  $stdout.write("#{DIGEST_PREFIX}#{Digest::SHA256.hexdigest(out)}")
  exit 0
end
$stdout.write(out)
