# frozen_string_literal: true

# Shared helpers for Ruby integration tests.
#
# Run with:
#   bundle exec rspec
#
# Requires:
#   - A BSV regtest node at localhost:18332 (user=bitcoin, pass=bitcoin)
#   - bsv-sdk gem for real ECDSA signing

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'openssl'
require 'securerandom'
require 'shellwords'
require 'uri'

require 'runar/sdk'
require 'runar/sdk/local_signer'

PROJECT_ROOT = File.expand_path('../../..', __dir__).freeze

# ---------------------------------------------------------------------------
# Integration helpers
# ---------------------------------------------------------------------------

module IntegrationHelpers
  module_function

  # ---------------------------------------------------------------------------
  # RPC config
  # ---------------------------------------------------------------------------

  RPC_URL  = ENV.fetch('RPC_URL',  'http://localhost:18332').freeze
  RPC_USER = ENV.fetch('RPC_USER', 'bitcoin').freeze
  RPC_PASS = ENV.fetch('RPC_PASS', 'bitcoin').freeze

  # ---------------------------------------------------------------------------
  # RPC helpers
  # ---------------------------------------------------------------------------

  # Make a JSON-RPC call to the regtest node.
  #
  # @param method [String]  RPC method name
  # @param params [Array]   splat parameters
  # @return [Object] the +result+ field of the JSON-RPC response
  # @raise [RuntimeError] on RPC error or HTTP failure
  def rpc_call(method, *params)
    body = JSON.generate(
      jsonrpc: '1.0',
      id: 'runar-rb',
      method: method,
      params: params
    )

    uri  = URI.parse(RPC_URL)
    auth = Base64.strict_encode64("#{RPC_USER}:#{RPC_PASS}")

    request = Net::HTTP::Post.new(uri)
    request['Content-Type']  = 'application/json'
    request['Authorization'] = "Basic #{auth}"
    request.body = body

    response = Net::HTTP.start(uri.host, uri.port, read_timeout: 600) do |http|
      http.request(request)
    end

    data = begin
      JSON.parse(response.body)
    rescue JSON::ParserError
      raise "RPC #{method}: HTTP #{response.code} — non-JSON response"
    end

    if data['error']
      err = data['error']
      msg = err.is_a?(Hash) ? err.fetch('message', err.to_s) : err.to_s
      raise "RPC #{method}: #{msg}"
    end

    data['result']
  end

  # Check whether the regtest node is reachable.
  #
  # @return [Boolean]
  def node_available?
    rpc_call('getblockcount')
    true
  rescue StandardError
    false
  end

  # Mine blocks on regtest.
  #
  # @param blocks [Integer] number of blocks to mine
  def mine(blocks)
    rpc_call('generate', blocks)
  rescue
    addr = rpc_call('getnewaddress')
    rpc_call('generatetoaddress', blocks, addr)
  end

  # Import an address and send coins to it, then mine a block.
  #
  # @param address    [String]  BSV address
  # @param btc_amount [Float]   amount in BTC (default: 1.0)
  def fund_address(address, btc_amount = 1.0)
    rpc_call('importaddress', address, '', false)
    rpc_call('sendtoaddress', address, btc_amount)
    mine(1)
  end

  # ---------------------------------------------------------------------------
  # Base58Check encoding
  # ---------------------------------------------------------------------------

  BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.freeze

  # Encode raw bytes as a Base58 string (no checksum — callers add their own).
  #
  # @param data_bytes [String] binary string
  # @return [String] Base58-encoded string
  def base58_encode(data_bytes)
    num = data_bytes.unpack1('H*').to_i(16)
    result = +''
    while num > 0
      num, remainder = num.divmod(58)
      result.prepend(BASE58_ALPHABET[remainder])
    end
    # Leading zero bytes become '1' characters.
    data_bytes.each_byte do |byte|
      break unless byte == 0

      result.prepend('1')
    end
    result
  end

  # Derive a regtest P2PKH address from a hex pubKeyHash (version byte 0x6f).
  #
  # @param pub_key_hash_hex [String] 20-byte public key hash, hex-encoded
  # @return [String] Base58Check address
  def regtest_address(pub_key_hash_hex)
    version_byte = "\x6f".b
    payload  = version_byte + [pub_key_hash_hex].pack('H*')
    checksum = Digest::SHA256.digest(Digest::SHA256.digest(payload))[0, 4]
    base58_encode(payload + checksum)
  end

  # RIPEMD160(SHA256(data)), returned as hex.
  #
  # @param data_bytes [String] binary string
  # @return [String] 40-character hex string
  def hash160(data_bytes)
    sha  = Digest::SHA256.digest(data_bytes)
    ripe = OpenSSL::Digest::RIPEMD160.digest(sha)
    ripe.unpack1('H*')
  end

  # ---------------------------------------------------------------------------
  # Wallet / Signer creation
  # ---------------------------------------------------------------------------

  # Create a deterministic wallet hash with priv_key_hex, pub_key_hex, pub_key_hash.
  #
  # @return [Hash] with keys :priv_key_hex, :pub_key_hex, :pub_key_hash
  def create_wallet
    @@wallet_counter ||= (Process.pid || 1) * 1000
    @@wallet_counter += 1
    priv_hex = @@wallet_counter.to_s(16).rjust(64, '0')
    local    = Runar::SDK::LocalSigner.new(priv_hex)
    pub_hex  = local.get_public_key
    pkh      = hash160([pub_hex].pack('H*'))

    { priv_key_hex: priv_hex, pub_key_hex: pub_hex, pub_key_hash: pkh }
  end

  # Create a funded wallet with an ExternalSigner suitable for the SDK.
  #
  # @param provider  [Runar::SDK::RPCProvider]
  # @param btc_amount [Float] amount in BTC (default: 1.0)
  # @return [Hash] with keys :priv_key_hex, :pub_key_hex, :pub_key_hash,
  #                :address, :signer
  def create_funded_wallet(provider, btc_amount = 1.0) # rubocop:disable Lint/UnusedMethodArgument
    wallet  = create_wallet
    address = regtest_address(wallet[:pub_key_hash])

    rpc_call('importaddress', address, '', false)
    rpc_call('sendtoaddress', address, btc_amount)
    mine(1)

    local = Runar::SDK::LocalSigner.new(wallet[:priv_key_hex])

    sign_fn = lambda do |tx_hex, input_index, subscript, satoshis, sighash_type|
      local.sign(tx_hex, input_index, subscript, satoshis, sighash_type || 0x41)
    end

    signer = Runar::SDK::ExternalSigner.new(
      pub_key_hex: wallet[:pub_key_hex],
      address: address,
      sign_fn: sign_fn
    )

    wallet.merge(address: address, signer: signer)
  end

  # ---------------------------------------------------------------------------
  # Compilation helper
  # ---------------------------------------------------------------------------

  # Compile a contract from a path relative to the project root.
  #
  # Uses the native Ruby compiler for .runar.rb files and falls back to the
  # TypeScript reference compiler (via Node.js) for all other formats.
  # The Ruby compiler's TS parser has known codegen divergences for complex
  # contracts (e.g. TicTacToe), so the TS compiler remains the gold standard
  # for .runar.ts sources until conformance is verified.
  #
  # @param rel_path [String] path relative to PROJECT_ROOT
  # @return [Runar::SDK::RunarArtifact]
  # @raise [RuntimeError] if compilation fails
  def compile_contract(rel_path)
    abs_path = File.join(PROJECT_ROOT, rel_path)

    if rel_path.end_with?('.runar.rb')
      compiler_bin = File.join(PROJECT_ROOT, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')
      output = `ruby #{Shellwords.escape(compiler_bin)} --source #{Shellwords.escape(abs_path)} 2>&1`
      status = Process.last_status
      raise "Compilation failed for #{rel_path}:\n#{output}" unless status&.success?
    else
      # Use the TypeScript reference compiler for non-Ruby sources.
      # The Ruby compiler's TS parser has known codegen divergences for complex
      # contracts (e.g. TicTacToe), so the TS compiler remains the gold standard
      # for .runar.ts sources until full cross-format conformance is verified.
      file_name = File.basename(rel_path)
      script = <<~JS
        (async () => {
          const { compile } = await import('#{PROJECT_ROOT}/packages/runar-compiler/dist/index.js');
          const fs = await import('fs');
          const source = fs.readFileSync(#{abs_path.inspect}, 'utf-8');
          const result = compile(source, { fileName: #{file_name.inspect} });
          if (!result.success) { console.error(result.diagnostics); process.exit(1); }
          const json = JSON.stringify(result.artifact, (k, v) => typeof v === 'bigint' ? v.toString() + 'n' : v);
          process.stdout.write(json);
        })();
      JS

      node_bin = ENV['NODE_BIN'] || `which node 2>/dev/null`.strip
      node_bin = 'node' if node_bin.empty?
      output = `#{node_bin} -e #{Shellwords.escape(script)} 2>&1`
      status = Process.last_status
      raise "Compilation failed for #{rel_path}:\n#{output}" unless status&.success?
    end

    Runar::SDK::RunarArtifact.from_json(output)
  end

  # ---------------------------------------------------------------------------
  # Provider helper
  # ---------------------------------------------------------------------------

  # Patch ``provider#broadcast`` so each call logs the raw tx size in bytes
  # to STDERR before delegating to the SDK implementation. The SDK gem
  # itself is left untouched — this wrapper lives only in the integration
  # suite to give CI logs a uniform per-broadcast tx-size line.
  #
  # @param provider [Runar::SDK::RPCProvider]
  # @return [Runar::SDK::RPCProvider] same instance, with broadcast patched
  def instrument_broadcast(provider)
    provider.singleton_class.class_eval do
      alias_method :__runar_broadcast_orig, :broadcast unless method_defined?(:__runar_broadcast_orig)
      define_method(:broadcast) do |tx, *rest, **kw|
        tx_hex = if tx.respond_to?(:to_hex)
                   tx.to_hex
                 elsif tx.is_a?(String)
                   tx
                 else
                   ''
                 end
        size_bytes = tx_hex.length / 2
        warn "[runar-integration] tx broadcast: #{size_bytes} bytes"
        __runar_broadcast_orig(tx, *rest, **kw)
      end
    end
    provider
  end

  # Create an RPCProvider configured for regtest.
  #
  # Uses the RPC_URL, RPC_USER, and RPC_PASS environment variables (with
  # localhost:18332/bitcoin/bitcoin defaults).
  #
  # @return [Runar::SDK::RPCProvider]
  def create_provider
    uri = URI.parse(RPC_URL)
    provider = Runar::SDK::RPCProvider.regtest(
      host: uri.host,
      port: uri.port,
      username: RPC_USER,
      password: RPC_PASS
    )
    instrument_broadcast(provider)
  end

  # ---------------------------------------------------------------------------
  # EC scalar helpers (secp256k1) — for EC contract tests
  # ---------------------------------------------------------------------------

  EC_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  EC_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  EC_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  EC_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

  # Modular inverse via Fermat's little theorem (p is prime).
  def mod_inverse(a, m)
    a_mod = ((a % m) + m) % m
    a_mod.pow(m - 2, m)
  end
  private_class_method :mod_inverse

  # Double a point on secp256k1.
  #
  # @param px [Integer] x coordinate
  # @param py [Integer] y coordinate
  # @return [Array<Integer>] [rx, ry]
  def ec_double(px, py)
    s  = (3 * px * px * mod_inverse(2 * py, EC_P)) % EC_P
    rx = ((s * s - 2 * px) % EC_P + EC_P) % EC_P
    ry = ((s * (px - rx) - py) % EC_P + EC_P) % EC_P
    [rx, ry]
  end

  # Add two distinct points on secp256k1.
  #
  # Falls through to ec_double when the two points are equal.
  #
  # @return [Array<Integer>] [rx, ry]
  def ec_add(p1x, p1y, p2x, p2y)
    return ec_double(p1x, p1y) if p1x == p2x && p1y == p2y

    s  = ((p2y - p1y) * mod_inverse(p2x - p1x, EC_P) % EC_P + EC_P) % EC_P
    rx = ((s * s - p1x - p2x) % EC_P + EC_P) % EC_P
    ry = ((s * (p1x - rx) - p1y) % EC_P + EC_P) % EC_P
    [rx, ry]
  end

  # Scalar multiply a point on secp256k1 using double-and-add.
  #
  # @param px [Integer] x coordinate of base point
  # @param py [Integer] y coordinate of base point
  # @param k  [Integer] scalar
  # @return [Array<Integer>] [rx, ry]
  def ec_mul(px, py, k)
    k = ((k % EC_N) + EC_N) % EC_N
    rx = ry = nil
    qx, qy = px, py
    while k > 0
      if k & 1 == 1
        if rx.nil?
          rx, ry = qx, qy
        else
          rx, ry = ec_add(rx, ry, qx, qy)
        end
      end
      qx, qy = ec_double(qx, qy)
      k >>= 1
    end
    [rx, ry]
  end

  # Scalar multiply the secp256k1 generator point.
  #
  # @param k [Integer] scalar
  # @return [Array<Integer>] [rx, ry]
  def ec_mul_gen(k)
    ec_mul(EC_GX, EC_GY, k)
  end

  # Encode a curve point as a 128-character hex string (x || y, 32 bytes each).
  #
  # Matches the Runar +Point+ type: "%064x%064x" % [x, y].
  #
  # @param x [Integer]
  # @param y [Integer]
  # @return [String] 128-character hex string
  def encode_point(x, y)
    format('%064x%064x', x, y)
  end

  # ---------------------------------------------------------------------------
  # WOTS+ helpers
  # ---------------------------------------------------------------------------

  WOTS_W    = 16
  WOTS_N    = 32
  WOTS_LEN1 = 64
  WOTS_LEN2 = 3
  WOTS_LEN  = WOTS_LEN1 + WOTS_LEN2

  # One step of the WOTS+ chain function.
  #
  # F(pubSeed || chainIdx_byte || stepIdx_byte || msg) — matches the on-chain
  # script which uses 1-byte indices in a single 66-byte hash.
  def wots_chain(x, start, steps, pub_seed, chain_idx)
    tmp = x.dup
    (start...(start + steps)).each do |i|
      tmp = Digest::SHA256.digest(pub_seed + chain_idx.chr + i.chr + tmp)
    end
    tmp
  end
  private_class_method :wots_chain

  # Generate a WOTS+ keypair.
  #
  # @param seed     [String] binary seed (any length)
  # @param pub_seed [String] binary public seed (any length)
  # @return [Hash] with keys :sk (Array of binary strings), :pk (hex String),
  #                :pub_seed (binary String)
  def wots_keygen(seed, pub_seed)
    sk = Array.new(WOTS_LEN) do |i|
      Digest::SHA256.digest(seed + [i].pack('N'))
    end

    pk_parts = sk.each_with_index.map do |ski, i|
      wots_chain(ski, 0, WOTS_W - 1, pub_seed, i)
    end

    all_pk   = pk_parts.join
    pk_root  = Digest::SHA256.digest(all_pk)
    pk_bytes = pub_seed + pk_root

    { sk: sk, pk: pk_bytes.unpack1('H*'), pub_seed: pub_seed }
  end

  # Sign a message with WOTS+.
  #
  # @param msg      [String] binary message
  # @param sk       [Array<String>] secret key (array of 32-byte binary strings)
  # @param pub_seed [String] binary public seed
  # @return [String] hex-encoded signature (WOTS_LEN × WOTS_N bytes)
  def wots_sign(msg, sk, pub_seed)
    msg_hash    = Digest::SHA256.digest(msg)
    msg_digits  = wots_extract_digits(msg_hash)
    csum_digits = wots_checksum_digits(msg_digits)
    all_digits  = msg_digits + csum_digits

    sig_parts = sk.each_with_index.map do |ski, i|
      wots_chain(ski, 0, all_digits[i], pub_seed, i)
    end

    sig_parts.join.unpack1('H*')
  end

  def wots_extract_digits(msg_hash)
    digits = []
    msg_hash.each_byte do |byte|
      digits << (byte >> 4)
      digits << (byte & 0x0F)
    end
    digits
  end
  private_class_method :wots_extract_digits

  def wots_checksum_digits(msg_digits)
    csum = msg_digits.sum { |d| WOTS_W - 1 - d }
    digits = Array.new(WOTS_LEN2, 0)
    c = csum
    (WOTS_LEN2 - 1).downto(0) do |i|
      digits[i] = c % WOTS_W
      c /= WOTS_W
    end
    digits
  end
  private_class_method :wots_checksum_digits

  # ---------------------------------------------------------------------------
  # Rabin helpers
  # ---------------------------------------------------------------------------

  # Generate a deterministic Rabin keypair for testing.
  #
  # Uses 130-bit primes matching the TypeScript helper.
  # n must be > 2^256 so (sig² + padding) % n has the same byte width as
  # SHA-256 output — otherwise OP_EQUALVERIFY fails.
  #
  # @return [Hash] with keys :p, :q, :n (integers)
  def generate_rabin_key_pair
    p_val = 1361129467683753853853498429727072846227
    q_val = 1361129467683753853853498429727082846007
    { p: p_val, q: q_val, n: p_val * q_val }
  end

  # Rabin-sign a message.
  #
  # On-chain verification: (sig² + padding) mod n === hash mod n
  #
  # @param msg_bytes [String] binary message
  # @param kp        [Hash]   key pair with :p, :q, :n
  # @return [Hash] with keys :sig (Integer) and :padding (Integer)
  # @raise [RuntimeError] if no valid padding is found within 1000 attempts
  def rabin_sign(msg_bytes, kp)
    p_val, q_val, n = kp[:p], kp[:q], kp[:n]
    h        = Digest::SHA256.digest(msg_bytes)
    hash_bn  = buffer_to_unsigned_le(h)

    1000.times do |padding|
      target = (hash_bn - padding) % n
      target += n if target < 0
      next unless quadratic_residue?(target, p_val) && quadratic_residue?(target, q_val)

      sp  = target.pow((p_val + 1) / 4, p_val)
      sq  = target.pow((q_val + 1) / 4, q_val)
      sig = chinese_remainder(sp, p_val, sq, q_val)

      return { sig: sig, padding: padding } if (sig * sig + padding) % n == hash_bn % n

      sig_alt = n - sig
      return { sig: sig_alt, padding: padding } if (sig_alt * sig_alt + padding) % n == hash_bn % n
    end

    raise 'Rabin sign: no valid padding found within 1000 attempts'
  end

  # Interpret bytes as an unsigned little-endian integer (matches Bitcoin Script).
  def buffer_to_unsigned_le(buf)
    result = 0
    buf.each_byte.with_index { |byte, i| result += byte << (i * 8) }
    result
  end
  private_class_method :buffer_to_unsigned_le

  # Euler criterion: check if a is a quadratic residue mod p.
  def quadratic_residue?(a, p_val)
    return true if a % p_val == 0

    a.pow((p_val - 1) / 2, p_val) == 1
  end
  private_class_method :quadratic_residue?

  # Chinese Remainder Theorem: find x s.t. x ≡ a1 (mod m1) and x ≡ a2 (mod m2).
  def chinese_remainder(a1, m1, a2, m2)
    m  = m1 * m2
    p1 = m2.pow(m1 - 2, m1)
    p2 = m1.pow(m2 - 2, m2)
    (a1 * m2 * p1 + a2 * m1 * p2) % m
  end
  private_class_method :chinese_remainder
end

# ---------------------------------------------------------------------------
# RSpec configuration
# ---------------------------------------------------------------------------

RSpec.configure do |config|
  config.include IntegrationHelpers

  config.before(:suite) do
    unless IntegrationHelpers.node_available?
      raise 'BSV regtest node not available. Integration tests require a live node. ' \
            'Start with: cd integration && ./regtest.sh start'
    end
    info = IntegrationHelpers.rpc_call('getblockchaininfo')
    raise "SAFETY: Connected to #{info['chain']}, not regtest!" unless info['chain'] == 'regtest'
    # Ensure at least 101 blocks exist for coinbase maturity
    count = IntegrationHelpers.rpc_call('getblockcount') rescue 0
    IntegrationHelpers.mine(101 - count) if count < 101
  end
end
