# frozen_string_literal: true

# SLH-DSA (FIPS 205) SHA-256 reference implementation.
#
# Implements all 6 SHA-256 parameter sets for key generation, signing, and
# verification. Used by the Runar Ruby runtime for real SLH-DSA verification
# in contract tests.
#
# Based on FIPS 205 (Stateless Hash-Based Digital Signature Standard).
# Only the SHA2 instantiation (not SHAKE) is implemented.
#
# IMPORTANT: The WOTS+ within SLH-DSA uses FIPS 205's tweakable hash
# T(PK.seed, ADRS, M) with compressed ADRS — this is DIFFERENT from the
# standalone WOTS+ in wots.rb which uses a simpler
# F(pubSeed, chainIdx, stepIdx, M).
#
# Port reference: packages/runar-rs/src/slh_dsa.rs and
#                 packages/runar-go/slh_dsa.go.
#
# All public inputs/outputs are hex-encoded strings to match the
# Runar::Builtins interface.

require 'digest'

module Runar
  module SLHDSA
    # --------------------------------------------------------------------
    # Parameter sets (FIPS 205 Table 1, SHA2 variants only)
    # --------------------------------------------------------------------

    # For w=16, log2(w)=4. len1 = ceil(8*n / 4) = 2*n; len2 = floor(log2(len1*15) / 4) + 1 = 3.
    def self.wots_len(n, w = 16)
      log2_w = 4 # only w=16 in FIPS 205 SHA2
      len1 = ((8 * n) + log2_w - 1) / log2_w
      product = len1 * (w - 1)
      bits = 0
      v = product
      while v > 1
        v >>= 1
        bits += 1
      end
      len2 = (bits / log2_w) + 1
      len1 + len2
    end

    PARAM_SETS = {
      sha2_128s: { name: 'SLH-DSA-SHA2-128s', n: 16, h: 63, d: 7,  hp: 9, a: 12, k: 14, w: 16, len: wots_len(16) }.freeze,
      sha2_128f: { name: 'SLH-DSA-SHA2-128f', n: 16, h: 66, d: 22, hp: 3, a: 6,  k: 33, w: 16, len: wots_len(16) }.freeze,
      sha2_192s: { name: 'SLH-DSA-SHA2-192s', n: 24, h: 63, d: 7,  hp: 9, a: 14, k: 17, w: 16, len: wots_len(24) }.freeze,
      sha2_192f: { name: 'SLH-DSA-SHA2-192f', n: 24, h: 66, d: 22, hp: 3, a: 8,  k: 33, w: 16, len: wots_len(24) }.freeze,
      sha2_256s: { name: 'SLH-DSA-SHA2-256s', n: 32, h: 64, d: 8,  hp: 8, a: 14, k: 22, w: 16, len: wots_len(32) }.freeze,
      sha2_256f: { name: 'SLH-DSA-SHA2-256f', n: 32, h: 68, d: 17, hp: 4, a: 8,  k: 35, w: 16, len: wots_len(32) }.freeze
    }.freeze

    # --------------------------------------------------------------------
    # ADRS (Address) — 32-byte domain separator (FIPS 205 Section 4.2)
    # --------------------------------------------------------------------

    ADRS_SIZE = 32

    # Address type constants
    ADRS_WOTS_HASH  = 0
    ADRS_WOTS_PK    = 1
    ADRS_TREE       = 2
    ADRS_FORS_TREE  = 3
    ADRS_FORS_ROOTS = 4
    ADRS_WOTS_PRF   = 5
    ADRS_FORS_PRF   = 6

    # ADRS is represented as a 32-byte binary string. Use these helpers to
    # mutate it in place (the string must be mutable / non-frozen).
    def self.new_adrs
      String.new("\x00" * ADRS_SIZE, encoding: Encoding::ASCII_8BIT)
    end

    def self.set_layer_address(adrs, layer)
      adrs.setbyte(0, (layer >> 24) & 0xff)
      adrs.setbyte(1, (layer >> 16) & 0xff)
      adrs.setbyte(2, (layer >> 8) & 0xff)
      adrs.setbyte(3, layer & 0xff)
    end

    def self.set_tree_address(adrs, tree)
      # Bytes 4-15 (12 bytes big-endian). Ruby Integer is unbounded, so any
      # overflow above 2^96 is silently truncated — same behavior as Rust/Go.
      12.times do |i|
        shift = 8 * i
        byte = shift < 96 ? ((tree >> shift) & 0xff) : 0
        adrs.setbyte(4 + 11 - i, byte)
      end
    end

    def self.set_type(adrs, typ)
      adrs.setbyte(16, (typ >> 24) & 0xff)
      adrs.setbyte(17, (typ >> 16) & 0xff)
      adrs.setbyte(18, (typ >> 8) & 0xff)
      adrs.setbyte(19, typ & 0xff)
      # Zero bytes 20-31
      (20..31).each { |i| adrs.setbyte(i, 0) }
    end

    def self.set_key_pair_address(adrs, kp)
      adrs.setbyte(20, (kp >> 24) & 0xff)
      adrs.setbyte(21, (kp >> 16) & 0xff)
      adrs.setbyte(22, (kp >> 8) & 0xff)
      adrs.setbyte(23, kp & 0xff)
    end

    def self.set_chain_address(adrs, chain)
      adrs.setbyte(24, (chain >> 24) & 0xff)
      adrs.setbyte(25, (chain >> 16) & 0xff)
      adrs.setbyte(26, (chain >> 8) & 0xff)
      adrs.setbyte(27, chain & 0xff)
    end

    def self.set_hash_address(adrs, h)
      adrs.setbyte(28, (h >> 24) & 0xff)
      adrs.setbyte(29, (h >> 16) & 0xff)
      adrs.setbyte(30, (h >> 8) & 0xff)
      adrs.setbyte(31, h & 0xff)
    end

    def self.set_tree_height(adrs, height)
      set_chain_address(adrs, height)
    end

    def self.set_tree_index(adrs, index)
      set_hash_address(adrs, index)
    end

    def self.get_key_pair_address(adrs)
      (adrs.getbyte(20) << 24) |
        (adrs.getbyte(21) << 16) |
        (adrs.getbyte(22) << 8) |
        adrs.getbyte(23)
    end

    # Compressed ADRS for SHA2 (22 bytes):
    #   c[0] = adrs[3] (layer, 1 byte)
    #   c[1..9]  = adrs[8..16]  (tree address bytes 8-15, 8 bytes)
    #   c[9]  = adrs[19] (type, 1 byte)
    #   c[10..22] = adrs[20..32]  (12 bytes)
    def self.compress_adrs(adrs)
      out = String.new(capacity: 22).b
      out << adrs.byteslice(3, 1)
      out << adrs.byteslice(8, 8)
      out << adrs.byteslice(19, 1)
      out << adrs.byteslice(20, 12)
      out
    end

    # --------------------------------------------------------------------
    # Hash functions (FIPS 205 Section 11.1 — SHA2 instantiation)
    # --------------------------------------------------------------------

    # Tweakable hash: T_l(PK.seed, ADRS, M) = trunc_n(SHA-256(PK.seed || pad || ADRSc || M))
    # pad is (64 - n) zero bytes to align the block.
    def self.t_hash(pk_seed, adrs, msg, n)
      adrs_c = compress_adrs(adrs)
      pad = "\x00".b * (64 - n)
      input = pk_seed + pad + adrs_c + msg
      Digest::SHA256.digest(input)[0, n]
    end

    # PRF(PK.seed, SK.seed, ADRS) = T(PK.seed, ADRS, SK.seed)
    def self.prf(pk_seed, sk_seed, adrs, n)
      t_hash(pk_seed, adrs, sk_seed, n)
    end

    # PRFmsg: randomized message hashing.
    def self.prf_msg(sk_prf, opt_rand, msg, n)
      pad = "\x00".b * (64 - n)
      input = pad + sk_prf + opt_rand + msg
      Digest::SHA256.digest(input)[0, n]
    end

    # Hmsg: hash message to get FORS + tree indices (SHA-256 + MGF1-style extension).
    def self.hmsg(r, pk_seed, pk_root, msg, out_len)
      seed = r + pk_seed + pk_root + msg
      hash = Digest::SHA256.digest(seed)

      result = String.new(capacity: out_len).b
      counter = 0
      while result.bytesize < out_len
        block = Digest::SHA256.digest(hash + [counter].pack('N'))
        copy_len = [32, out_len - result.bytesize].min
        result << block.byteslice(0, copy_len)
        counter += 1
      end
      result
    end

    # --------------------------------------------------------------------
    # WOTS+ helpers (FIPS 205 Section 5) — byte-level, mutates adrs
    # --------------------------------------------------------------------

    def self.wots_chain(x, start, steps, pk_seed, adrs, n)
      tmp = x
      (start...(start + steps)).each do |j|
        set_hash_address(adrs, j)
        tmp = t_hash(pk_seed, adrs, tmp, n)
      end
      tmp
    end

    def self.wots_len1(n, w)
      log2_w = Math.log2(w).to_i
      (8 * n + log2_w - 1) / log2_w
    end

    def self.wots_len2(n, w)
      l1 = wots_len1(n, w)
      log2_w = Math.log2(w)
      (Math.log2(l1 * (w - 1)) / log2_w).floor + 1
    end

    # base_w: decomposes a byte string into an array of log2(w)-bit digits,
    # MSB-first within each byte.
    def self.base_w(msg_bytes, w, out_len)
      log_w = Math.log2(w).to_i
      bits = []
      msg_bytes.each_byte do |byte|
        j = 8 - log_w
        while j >= 0
          bits << ((byte >> j) & (w - 1))
          j -= log_w
        end
      end
      bits[0, out_len]
    end

    def self.to_byte(value, n)
      b = Array.new(n, 0)
      val = value & ((1 << (8 * n)) - 1) # mask to n bytes (unsigned)
      (n - 1).downto(0) do |i|
        break if val.zero?

        b[i] = val & 0xff
        val >>= 8
      end
      b.pack('C*')
    end

    def self.slh_wots_pk_from_sig(sig, msg, pk_seed, adrs, params)
      n = params[:n]
      w = params[:w]
      len = params[:len]
      l1 = wots_len1(n, w)
      l2 = wots_len2(n, w)

      msg_digits = base_w(msg, w, l1)

      # Compute checksum
      csum = 0
      msg_digits.each { |d| csum += (w - 1) - d }

      log2_w = Math.log2(w)
      raw_shift = 8 - (((l2 * log2_w).to_i) % 8)
      shift = raw_shift == 8 ? 0 : raw_shift
      csum_byte_len = ((l2 * log2_w) / 8.0).ceil
      csum_bytes = to_byte(csum << shift, csum_byte_len)
      csum_digits = base_w(csum_bytes, w, l2)

      all_digits = msg_digits + csum_digits

      kp_addr = get_key_pair_address(adrs)
      tmp_adrs = adrs.dup
      set_type(tmp_adrs, ADRS_WOTS_HASH)
      set_key_pair_address(tmp_adrs, kp_addr)

      parts = String.new(capacity: len * n).b
      len.times do |i|
        set_chain_address(tmp_adrs, i)
        sig_i = sig.byteslice(i * n, n)
        parts << wots_chain(sig_i, all_digits[i], (w - 1) - all_digits[i], pk_seed, tmp_adrs, n)
      end

      pk_adrs = adrs.dup
      set_type(pk_adrs, ADRS_WOTS_PK)
      t_hash(pk_seed, pk_adrs, parts, n)
    end

    def self.slh_wots_sign(msg, sk_seed, pk_seed, adrs, params)
      n = params[:n]
      w = params[:w]
      len = params[:len]
      l1 = wots_len1(n, w)
      l2 = wots_len2(n, w)

      msg_digits = base_w(msg, w, l1)

      csum = 0
      msg_digits.each { |d| csum += (w - 1) - d }

      log2_w = Math.log2(w)
      raw_shift = 8 - (((l2 * log2_w).to_i) % 8)
      shift = raw_shift == 8 ? 0 : raw_shift
      csum_byte_len = ((l2 * log2_w) / 8.0).ceil
      csum_bytes = to_byte(csum << shift, csum_byte_len)
      csum_digits = base_w(csum_bytes, w, l2)

      all_digits = msg_digits + csum_digits

      kp_addr = get_key_pair_address(adrs)
      sig_parts = String.new(capacity: len * n).b
      len.times do |i|
        sk_adrs = adrs.dup
        set_type(sk_adrs, ADRS_WOTS_PRF)
        set_key_pair_address(sk_adrs, kp_addr)
        set_chain_address(sk_adrs, i)
        set_hash_address(sk_adrs, 0)
        sk = prf(pk_seed, sk_seed, sk_adrs, n)

        chain_adrs = adrs.dup
        set_type(chain_adrs, ADRS_WOTS_HASH)
        set_key_pair_address(chain_adrs, kp_addr)
        set_chain_address(chain_adrs, i)
        sig_parts << wots_chain(sk, 0, all_digits[i], pk_seed, chain_adrs, n)
      end
      sig_parts
    end

    def self.slh_wots_pk(sk_seed, pk_seed, adrs, params)
      n = params[:n]
      w = params[:w]
      len = params[:len]
      kp_addr = get_key_pair_address(adrs)

      parts = String.new(capacity: len * n).b
      len.times do |i|
        sk_adrs = adrs.dup
        set_type(sk_adrs, ADRS_WOTS_PRF)
        set_key_pair_address(sk_adrs, kp_addr)
        set_chain_address(sk_adrs, i)
        set_hash_address(sk_adrs, 0)
        sk = prf(pk_seed, sk_seed, sk_adrs, n)

        chain_adrs = adrs.dup
        set_type(chain_adrs, ADRS_WOTS_HASH)
        set_key_pair_address(chain_adrs, kp_addr)
        set_chain_address(chain_adrs, i)
        parts << wots_chain(sk, 0, w - 1, pk_seed, chain_adrs, n)
      end

      pk_adrs = adrs.dup
      set_type(pk_adrs, ADRS_WOTS_PK)
      t_hash(pk_seed, pk_adrs, parts, n)
    end

    # --------------------------------------------------------------------
    # XMSS (FIPS 205 Section 6) — Merkle tree with WOTS+ leaves
    # --------------------------------------------------------------------

    def self.slh_xmss_node(sk_seed, pk_seed, idx, height, adrs, params)
      n = params[:n]

      if height.zero?
        leaf_adrs = adrs.dup
        set_type(leaf_adrs, ADRS_WOTS_HASH)
        set_key_pair_address(leaf_adrs, idx)
        return slh_wots_pk(sk_seed, pk_seed, leaf_adrs, params)
      end

      left  = slh_xmss_node(sk_seed, pk_seed, 2 * idx,     height - 1, adrs, params)
      right = slh_xmss_node(sk_seed, pk_seed, 2 * idx + 1, height - 1, adrs, params)

      node_adrs = adrs.dup
      set_type(node_adrs, ADRS_TREE)
      set_tree_height(node_adrs, height)
      set_tree_index(node_adrs, idx)

      t_hash(pk_seed, node_adrs, left + right, n)
    end

    def self.slh_xmss_sign(msg, sk_seed, pk_seed, idx, adrs, params)
      hp = params[:hp]

      sig_adrs = adrs.dup
      set_type(sig_adrs, ADRS_WOTS_HASH)
      set_key_pair_address(sig_adrs, idx)
      result = slh_wots_sign(msg, sk_seed, pk_seed, sig_adrs, params).dup

      hp.times do |j|
        sibling = (idx >> j) ^ 1
        result << slh_xmss_node(sk_seed, pk_seed, sibling, j, adrs, params)
      end
      result
    end

    def self.slh_xmss_pk_from_sig(idx, sig_xmss, msg, pk_seed, adrs, params)
      n = params[:n]
      hp = params[:hp]
      len = params[:len]
      wots_sig_len = len * n
      wots_sig = sig_xmss.byteslice(0, wots_sig_len)
      auth     = sig_xmss.byteslice(wots_sig_len, sig_xmss.bytesize - wots_sig_len)

      w_adrs = adrs.dup
      set_type(w_adrs, ADRS_WOTS_HASH)
      set_key_pair_address(w_adrs, idx)
      node = slh_wots_pk_from_sig(wots_sig, msg, pk_seed, w_adrs, params)

      tree_adrs = adrs.dup
      set_type(tree_adrs, ADRS_TREE)

      hp.times do |j|
        auth_j = auth.byteslice(j * n, n)
        set_tree_height(tree_adrs, j + 1)
        set_tree_index(tree_adrs, idx >> (j + 1))

        combined = if ((idx >> j) & 1).zero?
                     node + auth_j
                   else
                     auth_j + node
                   end
        node = t_hash(pk_seed, tree_adrs, combined, n)
      end
      node
    end

    # --------------------------------------------------------------------
    # FORS (FIPS 205 Section 8) — Forest of random subsets
    # --------------------------------------------------------------------

    # Extract an a-bit integer from md starting at tree_idx * a bits.
    def self.extract_fors_idx(md, tree_idx, a)
      bit_start = tree_idx * a
      byte_start = bit_start / 8
      bit_offset = bit_start % 8

      value = 0
      bits_read = 0
      i = byte_start

      while bits_read < a
        byte = i < md.bytesize ? md.getbyte(i) : 0
        avail_bits = i == byte_start ? 8 - bit_offset : 8
        bits_to_take = [avail_bits, a - bits_read].min
        shift = i == byte_start ? avail_bits - bits_to_take : 8 - bits_to_take
        mask = (1 << bits_to_take) - 1
        value = (value << bits_to_take) | ((byte >> shift) & mask)
        bits_read += bits_to_take
        i += 1
      end

      value
    end

    def self.slh_fors_node(sk_seed, pk_seed, idx, height, adrs, tree_idx, params)
      n = params[:n]
      a = params[:a]

      if height.zero?
        sk_adrs = adrs.dup
        set_type(sk_adrs, ADRS_FORS_PRF)
        set_key_pair_address(sk_adrs, get_key_pair_address(adrs))
        set_tree_height(sk_adrs, 0)
        set_tree_index(sk_adrs, (tree_idx * (1 << a)) + idx)
        sk = prf(pk_seed, sk_seed, sk_adrs, n)

        leaf_adrs = adrs.dup
        set_type(leaf_adrs, ADRS_FORS_TREE)
        set_key_pair_address(leaf_adrs, get_key_pair_address(adrs))
        set_tree_height(leaf_adrs, 0)
        set_tree_index(leaf_adrs, (tree_idx * (1 << a)) + idx)
        return t_hash(pk_seed, leaf_adrs, sk, n)
      end

      left  = slh_fors_node(sk_seed, pk_seed, 2 * idx,     height - 1, adrs, tree_idx, params)
      right = slh_fors_node(sk_seed, pk_seed, 2 * idx + 1, height - 1, adrs, tree_idx, params)

      node_adrs = adrs.dup
      set_type(node_adrs, ADRS_FORS_TREE)
      set_key_pair_address(node_adrs, get_key_pair_address(adrs))
      set_tree_height(node_adrs, height)
      set_tree_index(node_adrs, (tree_idx * (1 << (a - height))) + idx)

      t_hash(pk_seed, node_adrs, left + right, n)
    end

    def self.slh_fors_sign(md, sk_seed, pk_seed, adrs, params)
      n = params[:n]
      a = params[:a]
      k = params[:k]
      kp_addr = get_key_pair_address(adrs)
      parts = String.new.b

      k.times do |i|
        idx = extract_fors_idx(md, i, a)

        sk_adrs = adrs.dup
        set_type(sk_adrs, ADRS_FORS_PRF)
        set_key_pair_address(sk_adrs, kp_addr)
        set_tree_height(sk_adrs, 0)
        set_tree_index(sk_adrs, (i * (1 << a)) + idx)
        sk = prf(pk_seed, sk_seed, sk_adrs, n)
        parts << sk

        a.times do |j|
          sibling_idx = (idx >> j) ^ 1
          parts << slh_fors_node(sk_seed, pk_seed, sibling_idx, j, adrs, i, params)
        end
      end

      parts
    end

    def self.slh_fors_pk_from_sig(fors_signature, md, pk_seed, adrs, params)
      n = params[:n]
      a = params[:a]
      k = params[:k]
      kp_addr = get_key_pair_address(adrs)
      roots = String.new.b
      offset = 0

      k.times do |i|
        idx = extract_fors_idx(md, i, a)

        sk = fors_signature.byteslice(offset, n)
        offset += n

        leaf_adrs = adrs.dup
        set_type(leaf_adrs, ADRS_FORS_TREE)
        set_key_pair_address(leaf_adrs, kp_addr)
        set_tree_height(leaf_adrs, 0)
        set_tree_index(leaf_adrs, (i * (1 << a)) + idx)
        node = t_hash(pk_seed, leaf_adrs, sk, n)

        auth_adrs = adrs.dup
        set_type(auth_adrs, ADRS_FORS_TREE)
        set_key_pair_address(auth_adrs, kp_addr)

        a.times do |j|
          auth_j = fors_signature.byteslice(offset, n)
          offset += n

          set_tree_height(auth_adrs, j + 1)
          tree_index = (i * (1 << (a - j - 1))) + (idx >> (j + 1))
          set_tree_index(auth_adrs, tree_index)

          combined = if ((idx >> j) & 1).zero?
                       node + auth_j
                     else
                       auth_j + node
                     end
          node = t_hash(pk_seed, auth_adrs, combined, n)
        end
        roots << node
      end

      fors_pk_adrs = adrs.dup
      set_type(fors_pk_adrs, ADRS_FORS_ROOTS)
      set_key_pair_address(fors_pk_adrs, kp_addr)
      t_hash(pk_seed, fors_pk_adrs, roots, n)
    end

    # --------------------------------------------------------------------
    # Top-level: keygen / sign / verify (FIPS 205 Sections 9-10)
    # --------------------------------------------------------------------

    # Generate a keypair. seed_hex must be exactly 3*n bytes (SK.seed || SK.prf || PK.seed).
    # Returns { sk: hex (4*n bytes), pk: hex (2*n bytes) }.
    def self.keygen(params, seed_hex = nil)
      n = params[:n]

      s = if seed_hex
            decoded = [seed_hex].pack('H*')
            raise ArgumentError, "seed must be #{3 * n} bytes" if decoded.bytesize != 3 * n

            decoded
          else
            # Deterministic fallback: hash a fixed label and extend.
            buf = String.new.b
            h = Digest::SHA256.digest('slh-dsa-default-seed-for-keygen')
            while buf.bytesize < 3 * n
              block = Digest::SHA256.digest(h + [buf.bytesize].pack('N'))
              take = [32, 3 * n - buf.bytesize].min
              buf << block.byteslice(0, take)
            end
            buf
          end

      sk_seed = s.byteslice(0, n)
      sk_prf  = s.byteslice(n, n)
      pk_seed = s.byteslice(2 * n, n)

      # Compute root of the top XMSS tree.
      adrs = new_adrs
      set_layer_address(adrs, params[:d] - 1)
      root = slh_xmss_node(sk_seed, pk_seed, 0, params[:hp], adrs, params)

      sk_bytes = sk_seed + sk_prf + pk_seed + root
      pk_bytes = pk_seed + root

      {
        sk: sk_bytes.unpack1('H*'),
        pk: pk_bytes.unpack1('H*')
      }
    end

    def self.sign(params, msg_hex, sk_hex)
      n  = params[:n]
      d  = params[:d]
      hp = params[:hp]
      k  = params[:k]
      a  = params[:a]
      h  = params[:h]

      sk_bytes = [sk_hex].pack('H*')
      msg      = [msg_hex].pack('H*')

      sk_seed = sk_bytes.byteslice(0, n)
      sk_prf  = sk_bytes.byteslice(n, n)
      pk_seed = sk_bytes.byteslice(2 * n, n)
      pk_root = sk_bytes.byteslice(3 * n, n)

      # Deterministic signing: optRand = pkSeed.
      opt_rand = pk_seed
      r = prf_msg(sk_prf, opt_rand, msg, n)

      md_len        = (k * a + 7) / 8
      tree_idx_len  = (h - hp + 7) / 8
      leaf_idx_len  = (hp + 7) / 8
      digest_len    = md_len + tree_idx_len + leaf_idx_len
      digest        = hmsg(r, pk_seed, pk_root, msg, digest_len)

      md = digest.byteslice(0, md_len)
      tree_idx = 0
      tree_idx_len.times do |i|
        tree_idx = (tree_idx << 8) | digest.getbyte(md_len + i)
      end
      tree_idx &= (1 << (h - hp)) - 1

      leaf_idx = 0
      leaf_idx_len.times do |i|
        leaf_idx = (leaf_idx << 8) | digest.getbyte(md_len + tree_idx_len + i)
      end
      leaf_idx &= (1 << hp) - 1

      # FORS signature
      fors_adrs = new_adrs
      set_tree_address(fors_adrs, tree_idx)
      set_type(fors_adrs, ADRS_FORS_TREE)
      set_key_pair_address(fors_adrs, leaf_idx)
      fors_sig = slh_fors_sign(md, sk_seed, pk_seed, fors_adrs, params)

      fors_pk = slh_fors_pk_from_sig(fors_sig, md, pk_seed, fors_adrs, params)

      result = String.new.b
      result << r
      result << fors_sig

      current_msg = fors_pk
      current_tree_idx = tree_idx
      current_leaf_idx = leaf_idx

      d.times do |layer|
        layer_adrs = new_adrs
        set_layer_address(layer_adrs, layer)
        set_tree_address(layer_adrs, current_tree_idx)

        xmss_sig = slh_xmss_sign(
          current_msg, sk_seed, pk_seed, current_leaf_idx, layer_adrs, params
        )

        current_msg = slh_xmss_pk_from_sig(
          current_leaf_idx, xmss_sig, current_msg, pk_seed, layer_adrs, params
        )

        result << xmss_sig

        current_leaf_idx = current_tree_idx & ((1 << hp) - 1)
        current_tree_idx >>= hp
      end

      result.unpack1('H*')
    end

    # Verify an SLH-DSA signature. All inputs are hex-encoded strings.
    def self.verify(params, msg_hex, sig_hex, pk_hex)
      n  = params[:n]
      d  = params[:d]
      hp = params[:hp]
      k  = params[:k]
      a  = params[:a]
      h  = params[:h]
      len = params[:len]

      pk = safe_hex_decode(pk_hex)
      return false if pk.nil?
      return false if pk.bytesize != 2 * n

      pk_seed = pk.byteslice(0, n)
      pk_root = pk.byteslice(n, n)

      sig = safe_hex_decode(sig_hex)
      return false if sig.nil?

      msg = safe_hex_decode(msg_hex)
      return false if msg.nil?

      offset = 0
      return false if sig.bytesize < n

      r = sig.byteslice(offset, n)
      offset += n

      fors_sig_len = k * (1 + a) * n
      return false if sig.bytesize < offset + fors_sig_len

      fors_sig = sig.byteslice(offset, fors_sig_len)
      offset += fors_sig_len

      md_len       = (k * a + 7) / 8
      tree_idx_len = (h - hp + 7) / 8
      leaf_idx_len = (hp + 7) / 8
      digest_len   = md_len + tree_idx_len + leaf_idx_len
      digest       = hmsg(r, pk_seed, pk_root, msg, digest_len)

      md = digest.byteslice(0, md_len)
      tree_idx = 0
      tree_idx_len.times do |i|
        tree_idx = (tree_idx << 8) | digest.getbyte(md_len + i)
      end
      tree_idx &= (1 << (h - hp)) - 1

      leaf_idx = 0
      leaf_idx_len.times do |i|
        leaf_idx = (leaf_idx << 8) | digest.getbyte(md_len + tree_idx_len + i)
      end
      leaf_idx &= (1 << hp) - 1

      fors_adrs = new_adrs
      set_tree_address(fors_adrs, tree_idx)
      set_type(fors_adrs, ADRS_FORS_TREE)
      set_key_pair_address(fors_adrs, leaf_idx)
      current_msg = slh_fors_pk_from_sig(fors_sig, md, pk_seed, fors_adrs, params)

      current_tree_idx = tree_idx
      current_leaf_idx = leaf_idx

      xmss_sig_len = (len + hp) * n
      d.times do |layer|
        return false if sig.bytesize < offset + xmss_sig_len

        xmss_sig = sig.byteslice(offset, xmss_sig_len)
        offset += xmss_sig_len

        layer_adrs = new_adrs
        set_layer_address(layer_adrs, layer)
        set_tree_address(layer_adrs, current_tree_idx)

        current_msg = slh_xmss_pk_from_sig(
          current_leaf_idx, xmss_sig, current_msg, pk_seed, layer_adrs, params
        )

        current_leaf_idx = current_tree_idx & ((1 << hp) - 1)
        current_tree_idx >>= hp
      end

      current_msg == pk_root
    end

    # Safe hex decode: returns nil for nil/odd-length/non-hex inputs.
    def self.safe_hex_decode(hex)
      return nil if hex.nil?
      return nil if hex.length.odd?
      return nil unless hex.match?(/\A[0-9a-fA-F]*\z/)

      [hex].pack('H*')
    end
  end
end
