#!/usr/bin/env ruby
require 'json'

$LOAD_PATH.unshift(File.join(__dir__, '..', '..', '..', 'packages', 'runar-rb', 'lib'))
require 'runar/sdk'

def convert_arg(arg)
  case arg['type']
  when 'bigint', 'int'
    arg['value'].to_i
  # `boolean` is the spelling the compiler's ABI carries; `bool` is the
  # alias some frontends use. Accept both (R-248).
  when 'bool', 'boolean'
    arg['value'] == 'true'
  else
    # ByteString, PubKey, Addr, Sig, Ripemd160, Sha256, Point — hex strings
    arg['value']
  end
end

if ARGV.length < 1
  $stderr.puts 'Usage: rb-sdk-tool.rb <input.json>'
  exit 1
end

# Readback mode (conformance/sdk-vertical): what matches_artifact and
# extract_constructor_args say about scriptHex. args is positional by
# paramIndex as {type, value} (decimal / 'true'|'false' / lowercase hex), nil
# for a param the extraction does not report; error is the message
# extract_constructor_args (or matches_artifact) raised, else nil.
def readback(artifact, script_hex)
  out = { 'matches' => nil, 'args' => nil, 'error' => nil }
  begin
    out['matches'] = Runar::SDK::ScriptUtils.matches_artifact(artifact, script_hex) ? true : false
  rescue StandardError => e
    out['error'] = e.message
  end
  begin
    got = Runar::SDK::ScriptUtils.extract_constructor_args(artifact, script_hex)
  rescue StandardError => e
    out['error'] ||= e.message
    return out
  end
  out['args'] = artifact.abi.constructor_params.map do |p|
    next nil unless got.key?(p.name)

    v = got[p.name]
    value = case v
            when true then 'true'
            when false then 'false'
            when Integer then v.to_s
            else v.to_s.downcase
            end
    { 'type' => p.type, 'value' => value }
  end
  out
end

data = JSON.parse(File.read(ARGV[0]))
artifact = Runar::SDK::RunarArtifact.from_hash(data['artifact'])
if data.key?('scriptHex')
  $stdout.write(JSON.generate(readback(artifact, data['scriptHex'])))
  exit 0
end
args = data['constructorArgs'].map { |a| convert_arg(a) }

contract = Runar::SDK::RunarContract.new(artifact, args)
if data['inscription']
  insc = data['inscription']
  # N-043: a refused attach is a RESULT, not a crash — exit non-zero with the
  # reason on stderr so the runner can compare the refusal verdict across all
  # seven tiers.
  begin
    contract.with_inscription(
      Runar::SDK::Inscription.new(
        content_type: insc['contentType'],
        data: insc['data']
      )
    )
  rescue ArgumentError => e
    $stderr.puts e.message
    exit 1
  end
end
# R-062: the smallest BRC-100 wallet that can fund a deploy.
class StubWallet < Runar::SDK::WalletClient
  def create_action(description:, outputs:)
    { txid: 'ab' * 32 }
  end
end

if data['walletDeploy']
  wd = data['walletDeploy']
  # R-062: a refusal is a RESULT, not a crash — exit non-zero with the reason
  # on stderr so the runner can compare the verdict across all seven tiers.
  wallet = StubWallet.new
  signer = Runar::SDK::MockSigner.new
  contract.connect(
    Runar::SDK::WalletProvider.new(wallet: wallet, signer: signer, basket: 'conformance'),
    signer
  )
  begin
    contract.deploy_with_wallet(
      satoshis: wd['satoshis'] || 1,
      acknowledge_unsound: wd['acknowledgeUnsound'] || []
    )
  rescue StandardError => e
    $stderr.puts e.message
    exit 1
  end
end

$stdout.write(contract.get_locking_script)
