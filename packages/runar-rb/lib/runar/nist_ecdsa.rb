# frozen_string_literal: true

require 'openssl'

# Real NIST P-256 / P-384 ECDSA signing and verification, used by the
# hybrid P256Wallet / P384Wallet contract examples.
#
# Wraps OpenSSL::PKey::EC with the on-wire formats Runar contracts use:
#   - Public keys are 33-byte (P-256) / 49-byte (P-384) compressed points,
#     hex-encoded.
#   - Signatures are raw r || s concatenations (64 / 96 bytes), hex-encoded —
#     NOT DER. This matches the input shape that the compiled `verifyECDSA_P256`
#     / `verifyECDSA_P384` Bitcoin Script verifier expects on the stack.
#
# The compiled verifier hashes the message with SHA-256 (P-256) / SHA-384
# (P-384) before verifying, so this module hashes consistently.
module Runar
  module NistECDSA
    module_function

    # ----- P-256 (prime256v1) -------------------------------------------------

    # Generate a fresh P-256 key pair.
    # @return [Hash] { sk: <hex priv key>, pk_compressed: <33-byte hex> }
    def p256_keygen
      keygen('prime256v1', 32)
    end

    # Sign `msg` (binary string or hex) with a P-256 private key.
    # The verifier hashes with SHA-256, so we sign SHA-256(msg).
    # Returns 64-byte raw r||s as a hex string.
    def p256_sign(msg, sk_hex)
      sign('prime256v1', sk_hex, msg, OpenSSL::Digest::SHA256, 32)
    end

    # Verify a P-256 signature.
    # @param msg [String]      hex-encoded message bytes (verifier hashes SHA-256)
    # @param sig_hex [String]  hex-encoded 64-byte raw r||s signature
    # @param pk_hex [String]   hex-encoded 33-byte compressed public key
    def p256_verify(msg, sig_hex, pk_hex)
      verify_raw('prime256v1', msg, sig_hex, pk_hex, OpenSSL::Digest::SHA256, 32)
    end

    # ----- P-384 (secp384r1) --------------------------------------------------

    # Generate a fresh P-384 key pair.
    # @return [Hash] { sk: <hex priv key>, pk_compressed: <49-byte hex> }
    def p384_keygen
      keygen('secp384r1', 48)
    end

    # Sign `msg` with a P-384 private key. Verifier hashes with SHA-384.
    # Returns 96-byte raw r||s as a hex string.
    def p384_sign(msg, sk_hex)
      sign('secp384r1', sk_hex, msg, OpenSSL::Digest::SHA384, 48)
    end

    # Verify a P-384 signature.
    # @param msg [String]      hex-encoded message bytes (verifier hashes SHA-384)
    # @param sig_hex [String]  hex-encoded 96-byte raw r||s signature
    # @param pk_hex [String]   hex-encoded 49-byte compressed public key
    def p384_verify(msg, sig_hex, pk_hex)
      verify_raw('secp384r1', msg, sig_hex, pk_hex, OpenSSL::Digest::SHA384, 48)
    end

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def keygen(curve_name, coord_len)
      # OpenSSL 3.x makes EC keys immutable; use OpenSSL.generate_key instead
      # of building an empty key and calling generate_key! on it.
      key = OpenSSL::PKey::EC.generate(curve_name)
      sk_int = key.private_key.to_i
      sk_hex = sk_int.to_s(16).rjust(coord_len * 2, '0')
      pub_point = key.public_key
      pk_compressed_bytes = pub_point.to_octet_string(:compressed)
      { sk: sk_hex, pk_compressed: pk_compressed_bytes.unpack1('H*') }
    end

    def sign(curve_name, sk_hex, msg, digest_class, coord_len)
      msg_bytes = hex_to_bytes(msg)
      key = ec_from_priv_hex(curve_name, sk_hex)
      digest = digest_class.new.digest(msg_bytes)
      der = key.dsa_sign_asn1(digest)
      r, s = parse_der_sig(der)
      raw = pad_int(r, coord_len) + pad_int(s, coord_len)
      raw.unpack1('H*')
    end

    def verify_raw(curve_name, msg, sig_hex, pk_hex, digest_class, coord_len)
      msg_bytes = hex_to_bytes(msg)
      sig_bytes = hex_to_bytes(sig_hex)
      return false unless sig_bytes.bytesize == coord_len * 2

      r = bytes_to_int(sig_bytes.byteslice(0, coord_len))
      s = bytes_to_int(sig_bytes.byteslice(coord_len, coord_len))
      der = encode_der_sig(r, s)

      pk = ec_from_pub_hex(curve_name, pk_hex)
      digest = digest_class.new.digest(msg_bytes)
      pk.dsa_verify_asn1(digest, der)
    rescue OpenSSL::PKey::ECError, ArgumentError
      false
    end

    def hex_to_bytes(s)
      str = s.to_s
      # Allow callers to pass either binary strings or hex strings.
      return str if str.encoding == Encoding::ASCII_8BIT && str !~ /\A[0-9a-fA-F]*\z/

      [str].pack('H*')
    end

    def pad_int(n, length)
      hex = n.to_s(16).rjust(length * 2, '0')
      [hex].pack('H*')
    end

    def bytes_to_int(b)
      b.unpack1('H*').to_i(16)
    end

    def parse_der_sig(der)
      seq = OpenSSL::ASN1.decode(der)
      r = seq.value[0].value.to_i
      s = seq.value[1].value.to_i
      [r, s]
    end

    def encode_der_sig(r, s)
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Integer.new(r),
        OpenSSL::ASN1::Integer.new(s),
      ]).to_der
    end

    def ec_from_priv_hex(curve_name, sk_hex)
      # Build an EC key from the raw private scalar by emitting an ASN.1 SEC1
      # ECPrivateKey structure and feeding it to OpenSSL::PKey.read (works on
      # OpenSSL 3.x where EC keys are immutable).
      group = OpenSSL::PKey::EC::Group.new(curve_name)
      sk_bytes = [sk_hex.rjust(group.degree / 4, '0')].pack('H*')
      sk_bn = OpenSSL::BN.new(sk_hex, 16)
      pub_point = group.generator.mul(sk_bn)

      # SEC1 ECPrivateKey: SEQUENCE { version INT 1, privateKey OCT, [0] OID, [1] BIT STRING pubkey }
      curve_oid = OpenSSL::ASN1::ObjectId.new(curve_name)
      params_tagged = OpenSSL::ASN1::ASN1Data.new([curve_oid], 0, :CONTEXT_SPECIFIC)
      pubkey_bs = OpenSSL::ASN1::BitString.new(pub_point.to_octet_string(:uncompressed))
      pubkey_tagged = OpenSSL::ASN1::ASN1Data.new([pubkey_bs], 1, :CONTEXT_SPECIFIC)
      sec1 = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Integer.new(1),
        OpenSSL::ASN1::OctetString.new(sk_bytes),
        params_tagged,
        pubkey_tagged,
      ])
      OpenSSL::PKey.read(sec1.to_der)
    end

    def ec_from_pub_hex(curve_name, pk_hex)
      group = OpenSSL::PKey::EC::Group.new(curve_name)
      bn = OpenSSL::BN.new(pk_hex, 16)
      point = OpenSSL::PKey::EC::Point.new(group, bn)

      # OpenSSL >= 3: build an EC key by encoding SubjectPublicKeyInfo (SPKI).
      ec_oid = OpenSSL::ASN1::ObjectId.new('id-ecPublicKey')
      curve_oid = OpenSSL::ASN1::ObjectId.new(curve_name)
      spki = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Sequence.new([ec_oid, curve_oid]),
        OpenSSL::ASN1::BitString.new(point.to_octet_string(:uncompressed)),
      ])
      OpenSSL::PKey.read(spki.to_der)
    end
  end
end
