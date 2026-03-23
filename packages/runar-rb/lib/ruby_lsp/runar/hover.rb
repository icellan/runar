# frozen_string_literal: true

# Runar hover listener for the Ruby LSP.
#
# Provides contextual documentation when the user hovers over Runar-specific
# identifiers in .runar.rb contract files:
#
#   - Builtin function calls (sha256, check_sig, num2bin, ...)
#   - Type constants (Bigint, ByteString, PubKey, ...)
#   - Runar DSL methods (prop, runar_public, params)
#
# File scoping:
#   Only activates for files whose URI ends with .runar.rb.  Regular Ruby
#   files in the same project are left untouched.
#
# Response builder categories:
#   :title        — shown as the hover heading
#   :documentation — shown as the hover body

module RubyLsp
  module Runar
    class Hover
      # Documentation strings for every Runar builtin function.
      # Keys are the Ruby method name (snake_case) as a String.
      BUILTIN_DOCS = {
        # Assertion
        'assert' => '`assert(condition)` — Runar assertion. Raises if condition is falsey. ' \
          'Compiles to OP_VERIFY in Bitcoin Script.',

        # Signature verification
        'check_sig' => '`check_sig(sig, pub_key) -> Boolean` — Verify an ECDSA signature ' \
          'against the contract\'s transaction preimage. Both arguments are ByteStrings.',
        'check_multi_sig' => '`check_multi_sig(sigs, pub_keys) -> Boolean` — Verify m-of-n ' \
          'ECDSA signatures (Bitcoin-style ordered multi-sig).',
        'check_preimage' => '`check_preimage(preimage) -> Boolean` — Verify that the provided ' \
          'SigHashPreimage matches the current transaction (OP_CHECKDATASIG-based).',
        'verify_rabin_sig' => '`verify_rabin_sig(msg, sig, padding, pub_key) -> Boolean` — ' \
          'Verify a Rabin signature. All arguments are hex-encoded ByteStrings.',

        # Post-quantum signature verification
        'verify_wots' => '`verify_wots(msg, sig, pub_key) -> Boolean` — Verify a WOTS+ ' \
          'one-time signature (~10 KB compiled script). Experimental post-quantum primitive.',
        'verify_slh_dsa_sha2_128s' => '`verify_slh_dsa_sha2_128s(msg, sig, pub_key) -> Boolean`' \
          ' — Verify an SLH-DSA-SHA2-128s signature (FIPS 205). Experimental post-quantum.',
        'verify_slh_dsa_sha2_128f' => '`verify_slh_dsa_sha2_128f(msg, sig, pub_key) -> Boolean`' \
          ' — Verify an SLH-DSA-SHA2-128f signature (FIPS 205). Experimental post-quantum.',
        'verify_slh_dsa_sha2_192s' => '`verify_slh_dsa_sha2_192s(msg, sig, pub_key) -> Boolean`' \
          ' — Verify an SLH-DSA-SHA2-192s signature (FIPS 205). Experimental post-quantum.',
        'verify_slh_dsa_sha2_192f' => '`verify_slh_dsa_sha2_192f(msg, sig, pub_key) -> Boolean`' \
          ' — Verify an SLH-DSA-SHA2-192f signature (FIPS 205). Experimental post-quantum.',
        'verify_slh_dsa_sha2_256s' => '`verify_slh_dsa_sha2_256s(msg, sig, pub_key) -> Boolean`' \
          ' — Verify an SLH-DSA-SHA2-256s signature (FIPS 205). Experimental post-quantum.',
        'verify_slh_dsa_sha2_256f' => '`verify_slh_dsa_sha2_256f(msg, sig, pub_key) -> Boolean`' \
          ' — Verify an SLH-DSA-SHA2-256f signature (FIPS 205). Experimental post-quantum.',

        # SHA-256 compression
        'sha256_compress' => '`sha256_compress(state, block) -> ByteString` — SHA-256 ' \
          'single-block compression function (FIPS 180-4). state is 32 bytes, block is 64 bytes. ' \
          'Returns 32-byte hex string. Use the SHA-256 IV for the first block.',
        'sha256_finalize' => '`sha256_finalize(state, remaining, msg_bit_len) -> ByteString` — ' \
          'Apply SHA-256 padding and finalize (1-2 compression rounds). Returns 32-byte hex string.',

        # BLAKE3 (mock in Ruby SDK)
        'blake3_compress' => '`blake3_compress(chaining_value, block) -> ByteString` — ' \
          'BLAKE3 single-block compression (~10,000 opcodes compiled). Returns 32-byte hex string.',
        'blake3_hash' => '`blake3_hash(message) -> ByteString` — BLAKE3 hash for messages ' \
          'up to 64 bytes. Returns 32-byte hex string.',

        # Hash functions
        'sha256' => '`sha256(data) -> ByteString` — SHA-256 hash. Input and output are ' \
          'hex-encoded ByteStrings. Returns 32 bytes.',
        'ripemd160' => '`ripemd160(data) -> ByteString` — RIPEMD-160 hash. Input and output ' \
          'are hex-encoded ByteStrings. Returns 20 bytes.',
        'hash160' => '`hash160(data) -> ByteString` — RIPEMD160(SHA256(data)). Standard ' \
          'Bitcoin address hash. Returns 20 bytes.',
        'hash256' => '`hash256(data) -> ByteString` — SHA256(SHA256(data)). Standard ' \
          'Bitcoin transaction hash. Returns 32 bytes.',

        # Preimage extraction
        'extract_locktime' => '`extract_locktime(preimage) -> Bigint` — Extract the locktime ' \
          'field from a SigHashPreimage.',
        'extract_output_hash' => '`extract_output_hash(preimage) -> ByteString` — Extract the ' \
          'hash of the transaction outputs from a SigHashPreimage. Returns 32 bytes.',
        'extract_amount' => '`extract_amount(preimage) -> Bigint` — Extract the input amount ' \
          '(satoshis) from a SigHashPreimage.',
        'extract_version' => '`extract_version(preimage) -> Bigint` — Extract the transaction ' \
          'version from a SigHashPreimage.',
        'extract_sequence' => '`extract_sequence(preimage) -> Bigint` — Extract the input ' \
          'sequence number from a SigHashPreimage.',
        'extract_hash_prevouts' => '`extract_hash_prevouts(preimage) -> ByteString` — Extract ' \
          'hashPrevouts from a SigHashPreimage. Returns 32 bytes.',
        'extract_outpoint' => '`extract_outpoint(preimage) -> ByteString` — Extract the input ' \
          'outpoint (txid + vout) from a SigHashPreimage. Returns 36 bytes.',

        # Math utilities
        'safediv' => '`safediv(a, b) -> Bigint` — Integer division truncating toward zero ' \
          '(Bitcoin Script semantics). Returns 0 when b is 0.',
        'safemod' => '`safemod(a, b) -> Bigint` — Modulo with Bitcoin Script sign semantics ' \
          '(sign matches dividend). Returns 0 when b is 0.',
        'clamp' => '`clamp(value, lo, hi) -> Bigint` — Clamp value to the range [lo, hi].',
        'sign' => '`sign(n) -> Bigint` — Returns 1 for positive, -1 for negative, 0 for zero.',
        'pow' => '`pow(base, exp) -> Bigint` — Integer exponentiation.',
        'mul_div' => '`mul_div(a, b, c) -> Bigint` — Multiply a by b then divide by c ' \
          '(integer, truncates toward zero).',
        'percent_of' => '`percent_of(amount, bps) -> Bigint` — Calculate a percentage of ' \
          'amount in basis points (bps / 10,000).',
        'sqrt' => '`sqrt(n) -> Bigint` — Integer square root using Newton\'s method.',
        'gcd' => '`gcd(a, b) -> Bigint` — Greatest common divisor.',
        'div_mod' => '`div_mod(a, b) -> Bigint` — Returns the quotient of integer division.',
        'log2' => '`log2(n) -> Bigint` — Floor of base-2 logarithm.',
        'bool' => '`bool(n) -> Boolean` — Convert integer to boolean (false if 0, true otherwise).',
        'within' => '`within(x, lo, hi) -> Boolean` — Returns true when lo <= x < hi.',
        'abs' => '`abs(n) -> Bigint` — Absolute value of an integer.',
        'min' => '`min(a, b) -> Bigint` — Minimum of two integers.',
        'max' => '`max(a, b) -> Bigint` — Maximum of two integers.',

        # Binary utilities
        'len' => '`len(data) -> Bigint` — Byte length of a hex-encoded ByteString.',
        'cat' => '`cat(a, b) -> ByteString` — Concatenate two hex-encoded ByteStrings.',
        'substr' => '`substr(data, start, length) -> ByteString` — Extract a substring of ' \
          'bytes. start and length are in bytes.',
        'left' => '`left(data, length) -> ByteString` — Left-most bytes of a hex string.',
        'right' => '`right(data, length) -> ByteString` — Right-most bytes of a hex string.',
        'reverse_bytes' => '`reverse_bytes(data) -> ByteString` — Reverse byte order of a ' \
          'hex-encoded ByteString.',
        'num2bin' => '`num2bin(value, length) -> ByteString` — Encode an integer as a ' \
          'little-endian sign-magnitude hex string of the given byte length ' \
          '(Bitcoin Script number encoding).',
        'bin2num' => '`bin2num(data) -> Bigint` — Decode a little-endian sign-magnitude hex ' \
          'string to an integer (Bitcoin Script number encoding).',

        # EC operations
        'ec_add' => '`ec_add(p, q) -> Point` — Add two secp256k1 elliptic curve points.',
        'ec_mul' => '`ec_mul(p, k) -> Point` — Multiply a secp256k1 point by a scalar.',
        'ec_mul_gen' => '`ec_mul_gen(k) -> Point` — Multiply the secp256k1 generator G by scalar k.',
        'ec_negate' => '`ec_negate(p) -> Point` — Negate a secp256k1 point.',
        'ec_on_curve' => '`ec_on_curve(p) -> Boolean` — Return true if p is on the secp256k1 curve.',
        'ec_mod_reduce' => '`ec_mod_reduce(value, m) -> Bigint` — Reduce value modulo m.',
        'ec_encode_compressed' => '`ec_encode_compressed(p) -> ByteString` — Encode a ' \
          'secp256k1 Point as a 33-byte compressed public key.',
        'ec_make_point' => '`ec_make_point(x, y) -> Point` — Construct a Point from x and y ' \
          'coordinates (each a 32-byte ByteString).',
        'ec_point_x' => '`ec_point_x(p) -> ByteString` — Extract the x coordinate from a Point.',
        'ec_point_y' => '`ec_point_y(p) -> ByteString` — Extract the y coordinate from a Point.',
      }.freeze

      # Documentation strings for Runar type constants.
      # Keys are the constant name as a String.
      TYPE_DOCS = {
        'Bigint'         => '`Bigint` — Runar integer type. Maps to Ruby Integer; ' \
          'compiles to OP_NUM in Bitcoin Script.',
        'Int'            => '`Int` — Alias for Bigint. Runar integer type.',
        'ByteString'     => '`ByteString` — Runar byte array type, represented as a ' \
          'hex-encoded String in Ruby. Compiles to a byte push in Bitcoin Script.',
        'PubKey'         => '`PubKey` — A 33-byte compressed secp256k1 public key, ' \
          'hex-encoded. Subtype of ByteString.',
        'Sig'            => '`Sig` — A DER-encoded ECDSA signature, hex-encoded. ' \
          'Subtype of ByteString.',
        'Addr'           => '`Addr` — A Bitcoin address string. Subtype of ByteString.',
        'Sha256'         => '`Sha256` — A 32-byte SHA-256 hash, hex-encoded. ' \
          'Subtype of ByteString.',
        'Ripemd160'      => '`Ripemd160` — A 20-byte RIPEMD-160 hash, hex-encoded. ' \
          'Subtype of ByteString.',
        'SigHashPreimage' => '`SigHashPreimage` — A BIP-143 sighash preimage, hex-encoded. ' \
          'Passed to check_preimage and the extract_* builtins.',
        'RabinSig'       => '`RabinSig` — A Rabin signature value, hex-encoded. ' \
          'Subtype of ByteString.',
        'RabinPubKey'    => '`RabinPubKey` — A Rabin public key, hex-encoded. ' \
          'Subtype of ByteString.',
        'Point'          => '`Point` — A 64-byte secp256k1 curve point (x[32] || y[32], ' \
          'big-endian, no prefix byte). Subtype of ByteString.',
        'OpCodeType'     => '`OpCodeType` — A single Bitcoin Script opcode byte, ' \
          'hex-encoded. Subtype of ByteString.',
        'Boolean'        => '`Boolean` — Runar boolean type. Maps to Ruby true/false.',
      }.freeze

      # Documentation strings for Runar DSL class methods.
      DSL_DOCS = {
        'prop'         => '`prop :name, Type [, readonly: true] [, default: value]` — ' \
          'Declare a typed property on a Runar contract. Generates attr_reader (readonly) ' \
          'or attr_accessor (mutable). Properties with defaults are excluded from the ' \
          'auto-generated constructor.',
        'runar_public' => '`runar_public [param: Type, ...]` — Mark the immediately following ' \
          'method as a public spending entry point. Public methods become Bitcoin Script ' \
          'unlocking paths.',
        'params'       => '`params param: Type, ...` — Annotate parameter types for the ' \
          'immediately following method without changing its visibility.',
      }.freeze

      # @param response_builder [Object] LSP response builder (responds to #push)
      # @param node_context [Object] Context for the node under the cursor
      # @param dispatcher [Prism::Dispatcher] Dispatcher for registering Prism node events
      def initialize(response_builder, node_context, dispatcher)
        @response_builder = response_builder
        @node_context     = node_context

        return unless runar_file?

        dispatcher.register(self, :on_call_node_enter)
        dispatcher.register(self, :on_constant_read_node_enter)
      end

      # Handle hover over a method call node.
      # Matches builtin function calls and DSL methods.
      def on_call_node_enter(node)
        name = node.name.to_s

        doc = BUILTIN_DOCS[name] || DSL_DOCS[name]
        return unless doc

        @response_builder.push(name, category: :title)
        @response_builder.push(doc, category: :documentation)
      end

      # Handle hover over a constant reference node (e.g. Bigint, ByteString).
      def on_constant_read_node_enter(node)
        name = node.name.to_s

        doc = TYPE_DOCS[name]
        return unless doc

        @response_builder.push(name, category: :title)
        @response_builder.push(doc, category: :documentation)
      end

      private

      # Returns true when the file currently being hovered is a Runar contract
      # (.runar.rb extension).
      def runar_file?
        uri = uri_from_context
        return false unless uri

        uri.to_s.end_with?('.runar.rb')
      end

      # Extract the URI from node_context. Ruby LSP exposes the document URI
      # on node_context, but the exact accessor differs across versions.
      # We try the documented path first, then fall back to instance variables
      # so that API changes degrade gracefully rather than crashing the LSP.
      def uri_from_context
        if @node_context.respond_to?(:document_uri)
          @node_context.document_uri
        elsif @node_context.respond_to?(:uri)
          @node_context.uri
        else
          @node_context.instance_variable_get(:@uri)
        end
      rescue StandardError
        nil
      end
    end
  end
end
