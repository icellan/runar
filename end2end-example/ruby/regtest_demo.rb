#!/usr/bin/env ruby
# frozen_string_literal: true

# PriceBet Regtest Interactive Demo
#
# Walks through the complete lifecycle of a Rúnar smart contract on a real
# BSV regtest node: key generation, funding, compilation, deployment, and
# spending via the SETTLE or CANCEL path.
#
# The user chooses the oracle price (or cancels), determining the winner:
#   price > strike  → Alice wins (settle path)
#   price <= strike → Bob wins (settle path)
#   -1              → Both cancel (cancel path, refund split)
#
# Prerequisites:
#   - BSV regtest node running on localhost:18332
#   - Node wallet loaded and funded (mine some blocks first)
#   - pnpm install && pnpm run build (from project root)
#
# Run:
#   cd end2end-example/ruby && bundle exec ruby regtest_demo.rb
#   # or with a non-interactive price:
#   cd end2end-example/ruby && bundle exec ruby regtest_demo.rb 60000
#   cd end2end-example/ruby && bundle exec ruby regtest_demo.rb -1
#
# Environment variables:
#   RPC_URL   - JSON-RPC endpoint (default: http://localhost:18332)
#   RPC_USER  - RPC username (default: bitcoin)
#   RPC_PASS  - RPC password (default: bitcoin)

$LOAD_PATH.unshift(File.join(__dir__, '../../packages/runar-rb/lib'))

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

# =============================================================================
# Configuration
# =============================================================================

RPC_URL  = ENV.fetch('RPC_URL',  'http://localhost:18332').freeze
RPC_USER = ENV.fetch('RPC_USER', 'bitcoin').freeze
RPC_PASS = ENV.fetch('RPC_PASS', 'bitcoin').freeze

STRIKE       = 50_000
CONTRACT_SATS = 200_000_000  # 2 BSV split 1 BSV each from Alice + Bob

PROJECT_ROOT = File.expand_path('../..', __dir__).freeze
CONTRACT_PATH = File.join(__dir__, 'PriceBet.runar.rb').freeze

# =============================================================================
# ANSI colors
# =============================================================================

C = {
  reset:   "\x1b[0m",
  bold:    "\x1b[1m",
  dim:     "\x1b[2m",
  cyan:    "\x1b[36m",
  green:   "\x1b[32m",
  yellow:  "\x1b[33m",
  red:     "\x1b[31m",
  magenta: "\x1b[35m"
}.freeze

# =============================================================================
# Display helpers
# =============================================================================

def banner(step, title)
  puts
  puts "#{C[:cyan]}#{'═' * 72}#{C[:reset]}"
  puts "#{C[:cyan]}#{C[:bold]}  Step #{step}: #{title}#{C[:reset]}"
  puts "#{C[:cyan]}#{'═' * 72}#{C[:reset]}"
  puts
end

def label(name, value)
  puts "  #{C[:dim]}#{name.ljust(22)}#{C[:reset]} #{value}"
end

def ok(msg)
  puts "  #{C[:green]}✓#{C[:reset]} #{msg}"
end

def heading(msg)
  puts "\n  #{C[:bold]}#{msg}#{C[:reset]}"
end

def err(msg)
  puts "\n  #{C[:red]}#{msg}#{C[:reset]}"
end

# =============================================================================
# Interactive pause
# =============================================================================

def pause(prompt = 'Press Enter to continue...')
  print "\n  #{C[:dim]}#{prompt}#{C[:reset]}"
  $stdin.gets
end

def ask_for_price
  loop do
    print "\n  #{C[:yellow]}Enter the price between 0 and 100000, or -1 to cancel the bet: #{C[:reset]}"
    input = $stdin.gets&.strip
    n = Integer(input, 10)
    return n if n >= -1 && n <= 100_000

    puts "  #{C[:red]}Invalid input. Enter a whole number between 0 and 100000, or -1.#{C[:reset]}"
  rescue ArgumentError
    puts "  #{C[:red]}Invalid input. Enter a whole number between 0 and 100000, or -1.#{C[:reset]}"
  end
end

# =============================================================================
# Crypto helpers
# =============================================================================

def sha256(data)
  Digest::SHA256.digest(data)
end

def hash256(data)
  sha256(sha256(data))
end

def hash160(data)
  sha   = Digest::SHA256.digest(data)
  ripe  = OpenSSL::Digest::RIPEMD160.digest(sha)
  ripe
end

# =============================================================================
# Base58Check encoding
# =============================================================================

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.freeze

def base58_encode(data_bytes)
  num = data_bytes.unpack1('H*').to_i(16)
  result = +''
  while num > 0
    num, rem = num.divmod(58)
    result.prepend(BASE58_ALPHABET[rem])
  end
  data_bytes.each_byte do |byte|
    break unless byte == 0

    result.prepend('1')
  end
  result
end

def to_base58check(payload_bytes, version)
  versioned = [version].pack('C') + payload_bytes
  checksum  = hash256(versioned)[0, 4]
  base58_encode(versioned + checksum)
end

def regtest_address(pub_key_hash_bytes)
  to_base58check(pub_key_hash_bytes, 0x6f)
end

# =============================================================================
# Hex / byte utilities
# =============================================================================

def hex_to_bytes(hex)
  [hex].pack('H*')
end

def bytes_to_hex(bin)
  bin.unpack1('H*')
end

def reverse_hex(hex_str)
  hex_to_bytes(hex_str).reverse.unpack1('H*')
end

# =============================================================================
# Bitcoin wire format helpers
# =============================================================================

def to_le32(n)
  [n].pack('V').unpack1('H*')
end

def to_le64(n)
  [n].pack('Q<').unpack1('H*')
end

def encode_varint(n)
  if n < 0xFD
    format('%02x', n)
  elsif n <= 0xFFFF
    'fd' + [n].pack('v').unpack1('H*')
  elsif n <= 0xFFFFFFFF
    'fe' + [n].pack('V').unpack1('H*')
  else
    'ff' + [n].pack('Q<').unpack1('H*')
  end
end

# =============================================================================
# Script encoding
# =============================================================================

# Wrap a hex-encoded data blob in a minimal push opcode.
def encode_push_data(data_hex)
  len = data_hex.length / 2
  if len <= 75
    format('%02x', len) + data_hex
  elsif len <= 0xFF
    '4c' + format('%02x', len) + data_hex
  elsif len <= 0xFFFF
    '4d' + [len].pack('v').unpack1('H*') + data_hex
  else
    '4e' + [len].pack('V').unpack1('H*') + data_hex
  end
end

# Encode an integer as a minimally-encoded Bitcoin Script number push.
def encode_script_number(n)
  return '00' if n.zero?
  return format('%02x', 0x50 + n) if n >= 1 && n <= 16
  return '4f' if n == -1

  negative = n.negative?
  abs_val  = n.abs
  bytes    = []

  while abs_val > 0
    bytes << (abs_val & 0xFF)
    abs_val >>= 8
  end

  if (bytes.last & 0x80) != 0
    bytes << (negative ? 0x80 : 0x00)
  elsif negative
    bytes[-1] |= 0x80
  end

  hex = bytes.map { |b| format('%02x', b) }.join
  encode_push_data(hex)
end

# =============================================================================
# Raw transaction builder
# =============================================================================

def build_raw_tx(inputs, outputs)
  tx = +''
  tx << to_le32(1)
  tx << encode_varint(inputs.length)

  inputs.each do |inp|
    tx << reverse_hex(inp[:prev_txid])
    tx << to_le32(inp[:prev_vout])
    script_sig = inp.fetch(:script_sig, '')
    tx << encode_varint(script_sig.length / 2)
    tx << script_sig if script_sig.length > 0
    tx << to_le32(inp.fetch(:sequence, 0xFFFFFFFF))
  end

  tx << encode_varint(outputs.length)

  outputs.each do |out|
    tx << to_le64(out[:satoshis])
    script = out[:script]
    tx << encode_varint(script.length / 2)
    tx << script
  end

  tx << to_le32(0)
  tx
end

# =============================================================================
# P2PKH helpers
# =============================================================================

def pub_key_hash_from(compressed_pub_key_hex)
  hash160(hex_to_bytes(compressed_pub_key_hex))
end

def build_p2pkh_script(pub_key_hash_hex)
  "76a914#{pub_key_hash_hex}88ac"
end

# =============================================================================
# JSON-RPC helper
# =============================================================================

@rpc_id = 1

def rpc(method, *params)
  body = JSON.generate(jsonrpc: '1.0', id: (@rpc_id += 1), method: method, params: params)
  auth = ["#{RPC_USER}:#{RPC_PASS}"].pack('m0')

  uri     = URI.parse(RPC_URL)
  request = Net::HTTP::Post.new(uri)
  request['Content-Type']  = 'application/json'
  request['Authorization'] = "Basic #{auth}"
  request.body = body

  response = Net::HTTP.start(uri.host, uri.port, read_timeout: 600) do |http|
    http.request(request)
  end

  data = JSON.parse(response.body)

  if data['error']
    err_obj = data['error']
    msg = err_obj.is_a?(Hash) ? err_obj.fetch('message', err_obj.to_s) : err_obj.to_s
    raise "RPC #{method}: #{msg}"
  end

  data['result']
end

def mine(n_blocks = 1)
  rpc('generate', n_blocks)
rescue RuntimeError
  addr = rpc('getnewaddress')
  rpc('generatetoaddress', n_blocks, addr)
end

# =============================================================================
# UTXO lookup
# =============================================================================

def find_utxo(txid, expected_script)
  tx = rpc('getrawtransaction', txid, true)
  tx['vout'].each do |v|
    next unless v['scriptPubKey']['hex'] == expected_script

    return {
      txid:     txid,
      vout:     v['n'],
      satoshis: (v['value'] * 1e8).round,
      script:   v['scriptPubKey']['hex']
    }
  end
  raise "No output matching expected script in TX #{txid}"
end

# =============================================================================
# Compilation helper (shell-out to TypeScript compiler)
# =============================================================================

def compile_contract(abs_path)
  file_name = File.basename(abs_path)

  # Use the compiler dist directly (avoids ESM/TS import issues with the CLI).
  script = <<~JS
    const { compile } = require('#{PROJECT_ROOT}/packages/runar-compiler/dist/index.js');
    const fs = require('fs');
    const source = fs.readFileSync(#{abs_path.inspect}, 'utf-8');
    const result = compile(source, { fileName: #{file_name.inspect} });
    if (!result.success) {
      console.error(JSON.stringify(result.diagnostics));
      process.exit(1);
    }
    const json = JSON.stringify(
      result.artifact,
      (k, v) => typeof v === 'bigint' ? v.toString() + 'n' : v
    );
    process.stdout.write(json);
  JS

  output = `node -e #{Shellwords.escape(script)} 2>&1`
  status = Process.last_status
  raise "Compilation failed:\n#{output}" unless status&.success?

  Runar::SDK::RunarArtifact.from_json(output)
end

# =============================================================================
# Rabin signature helpers
# =============================================================================

# Interpret bytes as an unsigned little-endian integer (matches Bitcoin Script).
def buffer_to_unsigned_le(bin)
  result = 0
  bin.each_byte.with_index { |byte, i| result += byte << (i * 8) }
  result
end

# Encode an integer as little-endian bytes of the given length.
def num2bin_le(value, length)
  result = "\x00".b * length
  v = value
  length.times do |i|
    result.setbyte(i, v & 0xFF)
    v >>= 8
  end
  result
end

# Euler criterion: check if a is a quadratic residue mod p.
def quadratic_residue?(a, p_val)
  return true if (a % p_val).zero?

  a.pow((p_val - 1) / 2, p_val) == 1
end

# Chinese Remainder Theorem: find x s.t. x ≡ a1 (mod m1) and x ≡ a2 (mod m2).
def chinese_remainder(a1, m1, a2, m2)
  m  = m1 * m2
  p1 = m2.pow(m1 - 2, m1)
  p2 = m1.pow(m2 - 2, m2)
  (a1 * m2 * p1 + a2 * m1 * p2) % m
end

# DEMO ONLY -- DO NOT USE IN PRODUCTION.
# These are 130-bit test primes (~65-bit security). For production, use
# OpenSSL::BN.generate_prime(512, true) for each prime (512-bit primes give
# roughly 128-bit security against factoring attacks).
#
# Uses deterministic test primes (same as the integration test suite) to keep
# prime generation fast in the demo.
# WARNING: Never log, display, or persist oracle_keys[:p] or oracle_keys[:q]
def generate_demo_rabin_key_pair
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
def rabin_sign(msg_bytes, kp)
  p_val = kp[:p]
  q_val = kp[:q]
  n     = kp[:n]
  h     = sha256(msg_bytes)
  hash_bn = buffer_to_unsigned_le(h)

  1000.times do |padding|
    target = (hash_bn - padding) % n
    # Ruby % is always non-negative for positive modulus -- no adjustment needed
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

# Find a valid signable price near the user's target.
#
# The contract's SHA256 hash of num2bin(price, 8) must have its final byte
# in the range 0x01–0x7f (so it can be pushed as a minimal positive script
# number). We search nearby prices until we find one that satisfies this.
def find_valid_price_near(target, min_price, max_price, keypair)
  10_001.times do |offset|
    candidates = offset.zero? ? [target] : [target + offset, target - offset]

    candidates.each do |price|
      next unless price >= min_price && price <= max_price

      msg_bytes = num2bin_le(price, 8)
      h         = sha256(msg_bytes)
      last_byte = h.getbyte(-1)

      next if last_byte == 0 || last_byte >= 0x80

      rabin_sig = rabin_sign(msg_bytes, keypair)
      return { price: price, rabin_sig: rabin_sig }
    rescue RuntimeError
      next
    end
  end

  raise 'Could not find a valid price in range'
end

# =============================================================================
# Main demo
# =============================================================================

def main # rubocop:disable Metrics/MethodLength, Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
  puts
  puts "#{C[:cyan]}#{C[:bold]}"
  puts '  ┌────────────────────────────────────────────────────────────────┐'
  puts '  │            PriceBet Regtest Interactive Demo                   │'
  puts '  │                                                                │'
  puts '  │  Deploys a Rúnar smart contract to a real BSV regtest node     │'
  puts '  │  and spends it via settle or cancel based on your chosen       │'
  puts '  │  price. Price > strike → Alice wins, else → Bob wins.          │'
  puts '  └────────────────────────────────────────────────────────────────┘'
  puts C[:reset]

  label('RPC endpoint', RPC_URL)
  label('RPC auth', 'credentials loaded from environment')

  # Verify regtest connection
  begin
    info = rpc('getblockchaininfo')
    label('Network', info['chain'])
    label('Block height', info['blocks'].to_s)

    unless info['chain'] == 'regtest'
      err("Not connected to regtest (chain=#{info['chain']}). Aborting.")
      exit(1)
    end
    ok('Connected to regtest node')
  rescue StandardError => e
    err("Cannot connect to BSV regtest node at #{RPC_URL}")
    puts "  #{C[:dim]}Make sure the node is running and RPC credentials are correct.#{C[:reset]}"
    puts "  #{C[:dim]}#{e.message}#{C[:reset]}"
    exit(1)
  end

  # Non-interactive mode: price from command line
  non_interactive = !ARGV.empty?
  cli_price = non_interactive ? Integer(ARGV[0], 10) : nil

  pause unless non_interactive

  # ---------------------------------------------------------------------------
  # Step 1: Generate Key Pairs (ECDSA + Rabin Oracle)
  # ---------------------------------------------------------------------------

  banner(1, 'Generate Key Pairs')
  puts '  Creating secp256k1 key pairs for Alice and Bob,'
  puts '  plus a Rabin keypair for the price oracle.'
  puts

  alice_priv_hex = SecureRandom.hex(32)
  bob_priv_hex   = SecureRandom.hex(32)

  alice_signer = Runar::SDK::LocalSigner.new(alice_priv_hex)
  bob_signer   = Runar::SDK::LocalSigner.new(bob_priv_hex)

  alice_pub_key = alice_signer.get_public_key
  bob_pub_key   = bob_signer.get_public_key

  alice_pkh      = pub_key_hash_from(alice_pub_key)
  bob_pkh        = pub_key_hash_from(bob_pub_key)
  alice_pkh_hex  = bytes_to_hex(alice_pkh)
  bob_pkh_hex    = bytes_to_hex(bob_pkh)
  alice_addr     = regtest_address(alice_pkh)
  bob_addr       = regtest_address(bob_pkh)
  alice_p2pkh    = build_p2pkh_script(alice_pkh_hex)
  bob_p2pkh      = build_p2pkh_script(bob_pkh_hex)

  heading('Alice (ECDSA)')
  label('Public key', alice_pub_key)
  label('Address (regtest)', alice_addr)

  heading('Bob (ECDSA)')
  label('Public key', bob_pub_key)
  label('Address (regtest)', bob_addr)

  heading('Oracle (Rabin)')
  puts '  Using deterministic 130-bit test primes (p ≡ q ≡ 3 mod 4)...'
  oracle_keys = generate_demo_rabin_key_pair
  # WARNING: Never log, display, or persist oracle_keys[:p] or oracle_keys[:q]
  label('n bit length', "~#{oracle_keys[:n].to_s(2).length} bits")
  label('n (public key)', oracle_keys[:n].to_s[0, 40] + '...')
  ok('Oracle Rabin keypair generated')

  pause unless non_interactive

  # ---------------------------------------------------------------------------
  # Step 2: Fund Wallets
  # ---------------------------------------------------------------------------

  banner(2, 'Fund Wallets')
  puts '  Sending 1 BSV to each party from the regtest node wallet.'
  puts

  alice_fund_txid = rpc('sendtoaddress', alice_addr, 1.0)
  ok("Sent 1 BSV to Alice  txid: #{alice_fund_txid}")

  bob_fund_txid = rpc('sendtoaddress', bob_addr, 1.0)
  ok("Sent 1 BSV to Bob    txid: #{bob_fund_txid}")

  heading('Mining a block to confirm')
  mine(1)
  ok('Block mined')

  heading('Locating UTXOs')
  alice_utxo = find_utxo(alice_fund_txid, alice_p2pkh)
  bob_utxo   = find_utxo(bob_fund_txid, bob_p2pkh)

  label('Alice UTXO', "#{alice_utxo[:txid]}:#{alice_utxo[:vout]}  #{alice_utxo[:satoshis]} sats")
  label('Bob UTXO',   "#{bob_utxo[:txid]}:#{bob_utxo[:vout]}  #{bob_utxo[:satoshis]} sats")

  pause unless non_interactive

  # ---------------------------------------------------------------------------
  # Step 3: Compile Contract
  # ---------------------------------------------------------------------------

  banner(3, 'Compile Contract')
  puts "  Contract: PriceBet.runar.rb"
  puts "  Strike price: #{STRIKE}"
  puts

  artifact = compile_contract(CONTRACT_PATH)

  ok('Compilation successful')
  label('Contract name', artifact.contract_name)
  label('Script size', "#{artifact.script.length / 2} bytes")
  label('Methods', artifact.abi.methods.map(&:name).join(', '))
  label('Constructor params', artifact.abi.constructor_params.map { |p| "#{p.name}: #{p.type}" }.join(', '))

  pause unless non_interactive

  # ---------------------------------------------------------------------------
  # Step 4: Deploy Contract (Funding TX)
  # ---------------------------------------------------------------------------

  banner(4, 'Deploy Contract (Funding TX)')
  puts '  Building a TX that creates the PriceBet UTXO on-chain.'
  puts '  Alice and Bob each contribute 1 BSV — the full 2 BSV goes to the bet.'
  puts

  # Inject constructor arguments into the compiled script.
  # Args order matches the contract: alicePubKey, bobPubKey, oraclePubKey, strikePrice.
  contract = Runar::SDK::RunarContract.new(artifact, [
    alice_pub_key,
    bob_pub_key,
    oracle_keys[:n],
    STRIKE
  ])

  locking_script = contract.get_locking_script

  heading('Transaction layout')
  label('Input  0', "Alice UTXO (#{alice_utxo[:satoshis]} sats)")
  label('Input  1', "Bob UTXO (#{bob_utxo[:satoshis]} sats)")
  label('Output 0', "PriceBet locking script (#{CONTRACT_SATS} sats)")
  label('Fee', '0 sats (demo — not deducted from inputs)')

  # Build unsigned funding TX manually (two-input, one-output).
  fund_outputs = [{ satoshis: CONTRACT_SATS, script: locking_script }]

  unsigned_fund_tx = build_raw_tx(
    [
      { prev_txid: alice_utxo[:txid], prev_vout: alice_utxo[:vout], script_sig: '' },
      { prev_txid: bob_utxo[:txid],   prev_vout: bob_utxo[:vout],   script_sig: '' }
    ],
    fund_outputs
  )

  heading('Signing (BIP-143 / SIGHASH_ALL|FORKID)')

  alice_fund_sig = alice_signer.sign(unsigned_fund_tx, 0, alice_utxo[:script], alice_utxo[:satoshis])
  ok("Alice signed input 0 (#{alice_fund_sig.length / 2} bytes)")

  bob_fund_sig = bob_signer.sign(unsigned_fund_tx, 1, bob_utxo[:script], bob_utxo[:satoshis])
  ok("Bob signed input 1 (#{bob_fund_sig.length / 2} bytes)")

  alice_unlock = encode_push_data(alice_fund_sig) + encode_push_data(alice_pub_key)
  bob_unlock   = encode_push_data(bob_fund_sig)   + encode_push_data(bob_pub_key)

  signed_fund_tx = build_raw_tx(
    [
      { prev_txid: alice_utxo[:txid], prev_vout: alice_utxo[:vout], script_sig: alice_unlock },
      { prev_txid: bob_utxo[:txid],   prev_vout: bob_utxo[:vout],   script_sig: bob_unlock }
    ],
    fund_outputs
  )

  heading('Broadcasting')
  label('Signed TX size', "#{signed_fund_tx.length / 2} bytes")

  contract_txid = rpc('sendrawtransaction', signed_fund_tx)
  ok("Funding TX accepted: #{contract_txid}")

  mine(1)
  ok('Block mined — contract UTXO confirmed')

  contract_tx_info = rpc('getrawtransaction', contract_txid, true)
  label('Confirmations', contract_tx_info['confirmations'].to_s)
  label('Contract UTXO', "#{contract_txid}:0  #{CONTRACT_SATS} sats")

  pause unless non_interactive

  # ---------------------------------------------------------------------------
  # Step 5: Choose Price (Oracle Signs)
  # ---------------------------------------------------------------------------

  banner(5, 'Choose Price (or Cancel)')
  puts "  The contract is now live on-chain. Strike price: #{STRIKE}"
  puts '  If price > strike → Alice wins via settle.'
  puts '  If price <= strike → Bob wins via settle.'
  puts '  If -1 → both parties cancel the bet.'
  puts

  user_price = non_interactive ? cli_price : ask_for_price
  is_cancel_path = user_price == -1

  price      = 0
  oracle_sig = nil

  unless is_cancel_path
    heading('Oracle signs the price')
    alice_wins = user_price > STRIKE
    min_price  = alice_wins ? STRIKE + 1 : 1
    max_price  = alice_wins ? 100_000 : STRIKE
    puts "  Finding a valid price near #{user_price} (#{alice_wins ? 'above' : 'at or below'} strike)...\n"

    found      = find_valid_price_near(user_price, min_price, max_price, oracle_keys)
    price      = found[:price]
    oracle_sig = found[:rabin_sig]

    ok("Found valid price: #{price}")
    label('Rabin sig', oracle_sig[:sig].to_s[0, 40] + '...')
    label('Rabin padding', oracle_sig[:padding].to_s)

    heading('Verifying Rabin signature offline')
    price_msg_bytes = num2bin_le(price, 8)
    price_hash      = sha256(price_msg_bytes)
    hash_int        = buffer_to_unsigned_le(price_hash)
    computed        = (oracle_sig[:sig] * oracle_sig[:sig] + oracle_sig[:padding]) % oracle_keys[:n]
    label('num2bin(price, 8)', bytes_to_hex(price_msg_bytes))
    label('SHA256(msg)', bytes_to_hex(price_hash))
    label('(sig² + pad) mod n',
          computed == hash_int % oracle_keys[:n] \
            ? "#{C[:green]}matches hash#{C[:reset]}" \
            : "#{C[:red]}MISMATCH#{C[:reset]}")
    last_byte = price_hash.getbyte(-1)
    label('Hash byte[31]', "0x#{format('%02x', last_byte)} (must be 0x01–0x7f)")
  else
    ok('Cancel path selected — no oracle signature needed')
  end

  alice_wins = !is_cancel_path && price > STRIKE

  pause unless non_interactive

  # ---------------------------------------------------------------------------
  # Step 6: Spend Contract
  # ---------------------------------------------------------------------------

  spend_outputs = if is_cancel_path
    banner(6, 'Spend Contract (Cancel TX — Mutual Refund)')
    puts '  Both parties agreed to cancel. Refunding 50/50.'
    puts
    half_sats = CONTRACT_SATS / 2
    heading('Transaction layout')
    label('Input  0', "PriceBet UTXO (#{CONTRACT_SATS} sats)")
    label('Output 0', "Alice P2PKH (#{half_sats} sats)")
    label('Output 1', "Bob P2PKH (#{half_sats} sats)")
    label('Fee', '0 sats')
    [
      { satoshis: half_sats, script: alice_p2pkh },
      { satoshis: half_sats, script: bob_p2pkh }
    ]
  elsif alice_wins
    banner(6, 'Spend Contract (Settle TX — Alice Wins)')
    puts "  Oracle price #{price} > strike #{STRIKE}, so Alice wins!"
    puts
    heading('Transaction layout')
    label('Input  0', "PriceBet UTXO (#{CONTRACT_SATS} sats)")
    label('Output 0', "Alice P2PKH (#{CONTRACT_SATS} sats)")
    label('Fee', '0 sats')
    [{ satoshis: CONTRACT_SATS, script: alice_p2pkh }]
  else
    banner(6, 'Spend Contract (Settle TX — Bob Wins)')
    puts "  Oracle price #{price} <= strike #{STRIKE}, so Bob wins!"
    puts
    heading('Transaction layout')
    label('Input  0', "PriceBet UTXO (#{CONTRACT_SATS} sats)")
    label('Output 0', "Bob P2PKH (#{CONTRACT_SATS} sats)")
    label('Fee', '0 sats')
    [{ satoshis: CONTRACT_SATS, script: bob_p2pkh }]
  end

  unsigned_spend_tx = build_raw_tx(
    [{ prev_txid: contract_txid, prev_vout: 0, script_sig: '' }],
    spend_outputs
  )

  unlock_script = if is_cancel_path
    heading('Signing (both Alice and Bob sign the cancel TX)')
    puts "  #{C[:dim]}subscript = PriceBet locking script (#{locking_script.length / 2} bytes)#{C[:reset]}"
    puts "  #{C[:dim]}value     = #{CONTRACT_SATS} satoshis#{C[:reset]}\n"

    alice_cancel_sig = alice_signer.sign(unsigned_spend_tx, 0, locking_script, CONTRACT_SATS)
    ok("Alice signed (#{alice_cancel_sig.length / 2} bytes DER+hashtype)")

    bob_cancel_sig = bob_signer.sign(unsigned_spend_tx, 0, locking_script, CONTRACT_SATS)
    ok("Bob signed (#{bob_cancel_sig.length / 2} bytes DER+hashtype)")

    heading('Building unlocking script')

    # cancel(alice_sig, bob_sig): method index 1
    encode_push_data(alice_cancel_sig) +
      encode_push_data(bob_cancel_sig) +
      encode_script_number(1)
  else
    winner = alice_wins ? 'Alice' : 'Bob'
    heading("Signing (#{winner} signs the settle TX)")
    puts "  #{C[:dim]}subscript = PriceBet locking script (#{locking_script.length / 2} bytes)#{C[:reset]}"
    puts "  #{C[:dim]}value     = #{CONTRACT_SATS} satoshis#{C[:reset]}\n"

    dummy_sig = '00'

    if alice_wins
      alice_settle_sig = alice_signer.sign(unsigned_spend_tx, 0, locking_script, CONTRACT_SATS)
      ok("Alice signed (#{alice_settle_sig.length / 2} bytes DER+hashtype)")

      heading('Building unlocking script')
      # settle(price, rabin_sig, padding, alice_sig, bob_sig=dummy): method index 0
      encode_script_number(price) +
        encode_script_number(oracle_sig[:sig]) +
        encode_script_number(oracle_sig[:padding]) +
        encode_push_data(alice_settle_sig) +
        encode_push_data(dummy_sig) +
        encode_script_number(0)
    else
      bob_settle_sig = bob_signer.sign(unsigned_spend_tx, 0, locking_script, CONTRACT_SATS)
      ok("Bob signed (#{bob_settle_sig.length / 2} bytes DER+hashtype)")

      heading('Building unlocking script')
      # settle(price, rabin_sig, padding, alice_sig=dummy, bob_sig): method index 0
      encode_script_number(price) +
        encode_script_number(oracle_sig[:sig]) +
        encode_script_number(oracle_sig[:padding]) +
        encode_push_data(dummy_sig) +
        encode_push_data(bob_settle_sig) +
        encode_script_number(0)
    end
  end

  label('Unlocking script', "#{unlock_script.length / 2} bytes")

  if is_cancel_path
    heading('Script execution trace (cancel path)')
    puts '    Stack after scriptSig:       [ aliceSig, bobSig, 1 ]'
    puts '    OP_DUP OP_1 OP_NUMEQUAL:     [ ..., true ]  (1 == 1)'
    puts '    OP_IF (cancel):               enters cancel branch'
    puts "    checkSig(aliceSig, alicePK):  ECDSA verify  #{C[:green]}✓#{C[:reset]}"
    puts "    checkSig(bobSig, bobPK):      ECDSA verify  #{C[:green]}✓#{C[:reset]}"
  else
    heading('Script execution trace (settle path)')
    puts '    Stack after scriptSig:       [ price, rabinSig, padding, aliceSig, bobSig, 0 ]'
    puts '    OP_DUP OP_0 OP_NUMEQUAL:     [ ..., true ]  (0 == 0)'
    puts '    OP_IF (settle):               enters settle branch'
    puts '    OP_DROP:                      [ price, rabinSig, padding, aliceSig, bobSig ]'
    puts '    num2bin(price, 8):            msg on stack'
    puts "    verifyRabinSig:              sig² + pad mod n == SHA256(msg)  #{C[:green]}✓#{C[:reset]}"
    puts "    price > 0:                    #{price} > 0  #{C[:green]}✓#{C[:reset]}"
    if alice_wins
      puts "    price > strike:               #{price} > #{STRIKE}  #{C[:green]}✓#{C[:reset]}"
      puts "    checkSig(aliceSig, alicePK):  ECDSA verify  #{C[:green]}✓#{C[:reset]}"
    else
      puts "    price <= strike:              #{price} <= #{STRIKE}  #{C[:green]}✓#{C[:reset]}"
      puts "    checkSig(bobSig, bobPK):      ECDSA verify  #{C[:green]}✓#{C[:reset]}"
    end
  end

  signed_spend_tx = build_raw_tx(
    [{ prev_txid: contract_txid, prev_vout: 0, script_sig: unlock_script }],
    spend_outputs
  )

  heading('Broadcasting')
  label('Signed TX size', "#{signed_spend_tx.length / 2} bytes")

  spend_txid = rpc('sendrawtransaction', signed_spend_tx)
  ok("#{is_cancel_path ? 'Cancel' : 'Settle'} TX accepted: #{spend_txid}")

  mine(1)
  winner_label = is_cancel_path ? 'Refund' : (alice_wins ? 'Alice payout' : 'Bob payout')
  ok("Block mined — #{winner_label} confirmed")

  spend_tx_info = rpc('getrawtransaction', spend_txid, true)
  label('Confirmations', spend_tx_info['confirmations'].to_s)

  pause unless non_interactive

  # ---------------------------------------------------------------------------
  # Step 7: Verify On-Chain State
  # ---------------------------------------------------------------------------

  banner(7, 'Verify On-Chain State')

  heading('Transaction chain')
  puts
  puts '    Faucet'
  puts "      ├─ 1 BSV → Alice    txid: #{alice_fund_txid}"
  puts "      └─ 1 BSV → Bob      txid: #{bob_fund_txid}"
  puts '              ↓'
  puts "    #{C[:cyan]}Funding TX#{C[:reset]}  (Alice + Bob → PriceBet UTXO)"
  puts "      txid: #{contract_txid}"
  puts "      output 0: PriceBet locking script  #{CONTRACT_SATS} sats"
  puts '              ↓'

  if is_cancel_path
    puts "    #{C[:yellow]}Cancel TX#{C[:reset]}   (Mutual cancel → 50/50 refund)"
  elsif alice_wins
    puts "    #{C[:green]}Settle TX#{C[:reset]}   (Oracle: price=#{price} > strike=#{STRIKE} → Alice wins!)"
  else
    puts "    #{C[:green]}Settle TX#{C[:reset]}   (Oracle: price=#{price} <= strike=#{STRIKE} → Bob wins!)"
  end

  puts "      txid: #{spend_txid}"

  verify_tx = rpc('getrawtransaction', spend_txid, true)
  verify_tx['vout'].each do |v|
    script_hex = v['scriptPubKey']['hex']
    who = if script_hex == alice_p2pkh
      'Alice'
    elsif script_hex == bob_p2pkh
      'Bob'
    else
      'Unknown'
    end
    sats = (v['value'] * 1e8).round
    puts "      output #{v['n']}: #{who.ljust(6)} P2PKH            #{sats} sats"
  end

  outcome_msg = if is_cancel_path
    'Cancel path: Both ECDSA signatures verified. Bet refunded 50/50.'
  elsif alice_wins
    "Settle path: Rabin oracle signature + Alice's ECDSA signature."
  else
    "Settle path: Rabin oracle signature + Bob's ECDSA signature."
  end

  pot_msg = if is_cancel_path
    'Each party received their 1 BSV back.'
  elsif alice_wins
    "Alice won the full #{CONTRACT_SATS / 1e8} BSV pot!"
  else
    "Bob won the full #{CONTRACT_SATS / 1e8} BSV pot!"
  end

  puts
  puts "  #{C[:green]}#{C[:bold]}#{'─' * 62}#{C[:reset]}"
  puts "  #{C[:green]}#{C[:bold]}  Demo complete!#{C[:reset]}"
  puts "  #{C[:green]}#{C[:bold]}  PriceBet was deployed and #{is_cancel_path ? 'cancelled' : 'settled'} on a real BSV regtest node.#{C[:reset]}"
  puts "  #{C[:green]}#{C[:bold]}  #{outcome_msg}#{C[:reset]}"
  puts "  #{C[:green]}#{C[:bold]}  #{pot_msg}#{C[:reset]}"
  puts "  #{C[:green]}#{C[:bold]}#{'─' * 62}#{C[:reset]}"
  puts
end

main
