# frozen_string_literal: true

# R3-PY-NEGATIVES (Ruby part): `expect_node_rejected` must refuse an SDK-side
# failure, an unreachable node, an accepted spend and a refusal for another
# reason, and accept a genuine script-verify refusal. Drives the real SDK
# RPCProvider (through NodeRejection.instrument) against a stub JSON-RPC node
# on 127.0.0.1, so no node is needed. The suite's .rspec requires
# spec_helper (which needs a live node); for a node-less run of just this
# file: bundle exec rspec --options /dev/null -I spec spec/node_rejection_helper_spec.rb

require 'json'
require 'socket'
require 'rspec'
require_relative 'node_rejection'

RSpec.describe NodeRejection do # rubocop:disable RSpec/FilePath
  include described_class

  script_failure = 'mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)'

  # One-request-per-connection stub node; answers[method] = [status, body].
  def stub_provider(answers)
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    Thread.new do
      loop do
        client = server.accept
        len = 0
        while (line = client.gets) && line != "\r\n"
          len = line.split(':', 2)[1].to_i if line.downcase.start_with?('content-length')
        end
        method = JSON.parse(client.read(len))['method']
        status, body = answers.fetch(method, [500, { 'result' => nil, 'error' => { 'code' => -32_601, 'message' => 'Method not found' } }])
        out = JSON.generate(body)
        client.write("HTTP/1.1 #{status} X\r\nContent-Type: application/json\r\nContent-Length: #{out.bytesize}\r\nConnection: close\r\n\r\n#{out}")
        client.close
      end
    rescue IOError
      nil
    end
    NodeRejection.instrument(Runar::SDK::RPCProvider.new(host: '127.0.0.1', port: port))
  end

  def ok(result) = [200, { 'result' => result, 'error' => nil, 'id' => 'runar' }]
  def err(code, msg) = [500, { 'result' => nil, 'error' => { 'code' => code, 'message' => msg }, 'id' => 'runar' }]

  it 'refuses an accepted spend' do
    p = stub_provider('sendrawtransaction' => ok('ab' * 32))
    expect { expect_node_rejected(p) { p.broadcast('00') } }
      .to raise_error(RSpec::Expectations::ExpectationNotMetError, /ACCEPTED/)
  end

  it 'refuses an SDK-side failure (nothing broadcast)' do
    p = stub_provider({})
    expect { expect_node_rejected(p) { raise 'safediv: division by zero' } }
      .to raise_error(RSpec::Expectations::ExpectationNotMetError, /never handed a transaction/)
  end

  it 'refuses an unreachable node' do
    s = TCPServer.new('127.0.0.1', 0)
    port = s.addr[1]
    s.close
    p = NodeRejection.instrument(Runar::SDK::RPCProvider.new(host: '127.0.0.1', port: port))
    expect { expect_node_rejected(p) { p.broadcast('00') } }
      .to raise_error(RSpec::Expectations::ExpectationNotMetError, /never ruled/)
  end

  it 'refuses a node refusal for another reason' do
    p = stub_provider('sendrawtransaction' => err(-26, '16: bad-txns-inputs-missingorspent'))
    expect { expect_node_rejected(p) { p.broadcast('00') } }
      .to raise_error(RSpec::Expectations::ExpectationNotMetError, /wrong reason/)
  end

  it 'control: accepts a genuine script-verify refusal' do
    p = stub_provider('sendrawtransaction' => err(-26, script_failure))
    e = expect_node_rejected(p) { p.broadcast('00') }
    expect(e).to be_a(Runar::SDK::RPCNodeError)
    expect(p.broadcast_log).to eq([[:node_rejected, script_failure]])
  end
end
