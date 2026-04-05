#!/usr/bin/env ruby
require 'json'

$LOAD_PATH.unshift(File.join(__dir__, '..', '..', '..', 'packages', 'runar-rb', 'lib'))
require 'runar/sdk'

def convert_arg(arg)
  case arg['type']
  when 'bigint', 'int'
    arg['value'].to_i
  when 'bool'
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

data = JSON.parse(File.read(ARGV[0]))
artifact = Runar::SDK::RunarArtifact.from_hash(data['artifact'])
args = data['constructorArgs'].map { |a| convert_arg(a) }

contract = Runar::SDK::RunarContract.new(artifact, args)
$stdout.write(contract.get_locking_script)
