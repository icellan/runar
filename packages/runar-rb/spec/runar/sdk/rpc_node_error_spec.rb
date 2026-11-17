# frozen_string_literal: true

# R3-PY-NEGATIVES (Ruby part): RPCProvider reports the node's JSON-RPC error as
# a typed RPCNodeError (method, code, node message), so a caller can tell "the
# node said no" from "the node never answered" without parsing message text.
# SV Node answers an error with HTTP 500 and the error object in the body.
# Node-free: a stub JSON-RPC server on 127.0.0.1.

require 'spec_helper'
require 'json'
require 'socket'
require 'runar/sdk'

RSpec.describe 'Runar::SDK::RPCProvider node errors' do
  def stub_node(status, body)
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    thread = Thread.new do
      client = server.accept
      len = 0
      while (line = client.gets) && line != "\r\n"
        len = line.split(':', 2)[1].to_i if line.downcase.start_with?('content-length')
      end
      client.read(len)
      out = JSON.generate(body)
      client.write("HTTP/1.1 #{status} X\r\nContent-Type: application/json\r\nContent-Length: #{out.bytesize}\r\nConnection: close\r\n\r\n#{out}")
      client.close
    end
    [server, port, thread]
  end

  refusal = { 'code' => -26, 'message' => 'mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)' }

  [500, 200].each do |status|
    it "a JSON-RPC error reply (HTTP #{status}) is an RPCNodeError carrying method, code and message" do
      server, port, thread = stub_node(status, { 'result' => nil, 'error' => refusal, 'id' => 'runar' })
      provider = Runar::SDK::RPCProvider.new(host: '127.0.0.1', port: port)
      expect { provider.broadcast('00') }.to raise_error(Runar::SDK::RPCNodeError) { |e|
        expect(e.rpc_method).to eq('sendrawtransaction')
        expect(e.code).to eq(-26)
        expect(e.node_message).to eq(refusal['message'])
        expect(e.message).to eq("RPC error -26: #{refusal['message']}")
        expect(e).to be_a(RuntimeError)
      }
      thread.join
      server.close
    end
  end

  it 'a transport failure is not an RPCNodeError' do
    s = TCPServer.new('127.0.0.1', 0)
    port = s.addr[1]
    s.close
    provider = Runar::SDK::RPCProvider.new(host: '127.0.0.1', port: port)
    expect { provider.broadcast('00') }.to raise_error(StandardError) { |e|
      expect(e).not_to be_a(Runar::SDK::RPCNodeError)
    }
  end
end
