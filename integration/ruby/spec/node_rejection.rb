# frozen_string_literal: true

# A negative spec must prove the NODE refused the spend, and why.
#
# The suite's negatives were bare `expect { call }.to raise_error(StandardError)`,
# which passes on an SDK-side failure (the SDK refusing to build the
# transaction) and on an unreachable node as readily as on a consensus
# rejection. (Unlike the other tiers, this SDK's RPCProvider#broadcast does not
# mine, so GK-BUG-004's accepted-then-mine-failed case cannot arise here; the
# classification still records it, for parity.) `expect_node_rejected` reads
# what each broadcast came to instead.
#
# Kept apart from spec_helper.rb (which needs a live node) so that
# node_rejection_helper_spec.rb can exercise it against a stub node.

require 'runar/sdk'

module NodeRejection
  module_function

  # The reason SV Node gives for a spend whose unlocking script fails (a false
  # assert, a failed checkSig, a script error such as OP_SPLIT out of range).
  # The Rust, Java, Zig, Go, Python and TS suites pin the same text.
  SCRIPT_VERIFY_FAILED = 'mandatory-script-verify-flag-failed'

  # Patch +provider.broadcast+ to record what each broadcast came to in
  # +provider.broadcast_log+ ([kind, detail], one entry per attempt):
  # :accepted / :node_rejected (the node's message) / :other (transport
  # failure, malformed reply). Classified by the SDK's typed RPCNodeError and
  # the RPC method it names, never by message text.
  def instrument(provider)
    provider.instance_variable_set(:@broadcast_log, [])
    provider.singleton_class.class_eval do
      attr_reader :broadcast_log

      alias_method :__runar_broadcast_logged, :broadcast unless method_defined?(:__runar_broadcast_logged)
      define_method(:broadcast) do |tx, *rest, **kw|
        txid = __runar_broadcast_logged(tx, *rest, **kw)
        @broadcast_log << [:accepted, txid.to_s]
        txid
      rescue Runar::SDK::RPCNodeError => e
        @broadcast_log << (e.rpc_method == 'sendrawtransaction' ? [:node_rejected, e.node_message.to_s] : [:other, e.message])
        raise
      rescue StandardError => e
        @broadcast_log << [:other, e.message]
        raise
      end
    end
    provider
  end

  # The pure check behind expect_node_rejected. +added+ is what the call under
  # test broadcast. nil when, and only when: the call broadcast at least once
  # (an error with no broadcast is an SDK-side refusal, not consensus); the
  # node accepted none of those broadcasts; and the last one was refused at
  # sendrawtransaction with a message containing +reason+. Otherwise why not.
  def check_node_rejected(added, reason)
    return 'no rejection reason given' if reason.nil? || reason.empty?
    return 'the call never handed a transaction to the node (SDK-side failure)' if added.empty?

    added.each do |kind, detail|
      return "the node ACCEPTED a transaction from this call (#{kind}: #{detail})" if %i[accepted accepted_then_mine_failed].include?(kind)
    end
    kind, detail = added.last
    return "the node never ruled on the spend (#{kind}: #{detail})" unless kind == :node_rejected
    return "the node rejected the spend for the wrong reason: expected #{reason.inspect}, got #{detail.inspect}" unless detail.include?(reason)

    nil
  end

  # Runs the block and asserts the node refused it for +reason+. Returns the
  # block's error.
  def expect_node_rejected(provider, reason = SCRIPT_VERIFY_FAILED)
    log = provider.broadcast_log
    raise ArgumentError, 'expect_node_rejected: provider is not instrumented' if log.nil?

    before = log.length
    error = nil
    begin
      yield
    rescue StandardError => e
      error = e
    end
    raise RSpec::Expectations::ExpectationNotMetError, 'the spend was ACCEPTED (nothing raised), so nothing was rejected' if error.nil?

    why = check_node_rejected(log[before..], reason)
    raise RSpec::Expectations::ExpectationNotMetError, "not a node rejection: #{why}; call error: #{error.inspect}" if why

    error
  end
end
