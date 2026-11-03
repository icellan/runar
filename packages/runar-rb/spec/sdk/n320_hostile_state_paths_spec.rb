# frozen_string_literal: true

# N-320: the state-reading paths must refuse a hostile script with a typed
# error, never raise an untyped exception, hang or fabricate state.
#
# Replays conformance/sdk-matches-artifact/hostile-state.json — the N-317
# hostile scripts of hostile.json with expected outcomes for
# State.extract_state_from_script, RunarContract.from_utxo and
# RunarContract.from_txid (replayed by all 7 SDKs). from_txid has its own copy
# of the from_utxo body in this tier, so both are replayed.
#
# Proves: for each of the 30 scripts, extract_state_from_script on the
# stateful artifact returns exactly the expected state / nil /
# MalformedScriptError, and from_utxo and from_txid either reconnect or raise
# MalformedScriptError (any other exception fails it) — an odd-length, non-hex
# or non-ASCII script is refused before any reader runs, and a stateful
# artifact over a script with no state section is refused (C10, as in TS)
# instead of carrying constructor-initial state; the replay stays inside a
# process-CPU budget (watchdog thread, as in the N-317 spec).
# Does NOT prove: on-chain spendability of a reconnected contract; artifact
# shapes beyond the fixture's two; the error deserialize_state raises on a
# hex-valid truncated or overlong state section (no case reaches it).

require 'spec_helper'
require 'json'
require 'runar/sdk'

N320_DIR = File.expand_path('../../../../../conformance/sdk-matches-artifact', __FILE__)
N320_FIXTURE = JSON.parse(File.read(File.join(N320_DIR, 'hostile.json'), encoding: 'UTF-8'))
N320_STATE_FIXTURE = JSON.parse(File.read(File.join(N320_DIR, 'hostile-state.json'), encoding: 'UTF-8'))
N320_CPU_BUDGET_SECS = 20.0

# Exception (not StandardError) so no `rescue StandardError` under test swallows it.
class N320OverBudget < Exception; end # rubocop:disable Lint/InheritException

RSpec.describe 'N-320: hostile scripts on the state-reading paths (shared vector)' do
  def n320_script(c)
    c['prefix'] + (c['repeat'] || '') * (c['count'] || 0) + (c['suffix'] || '')
  end

  def n320_outcome
    yield
  rescue Runar::SDK::MalformedScriptError
    'malformed'
  rescue StandardError => e
    "error:#{e.class}: #{e.message}"
  end

  def n320_replay
    artifacts = N320_FIXTURE['artifacts'].transform_values { |a| Runar::SDK::RunarArtifact.from_hash(a) }
    cases = N320_FIXTURE['cases']
    want = N320_STATE_FIXTURE['cases']
    raise 'fixture mismatch' if cases.empty? || cases.length != want.length

    provider = Runar::SDK::MockProvider.new
    diffs = []
    cases.zip(want).each_with_index do |(c, w), i|
      raise 'case order' unless c['name'] == w['name']

      script = n320_script(c)
      txid = format('%02x', i) * 32
      provider.add_transaction(Runar::SDK::TransactionData.new(
                                 txid: txid, outputs: [Runar::SDK::TxOutput.new(satoshis: 1000, script: script)]
                               ))
      got = n320_outcome do
        s = Runar::SDK::State.extract_state_from_script(artifacts['stateful'], script)
        s&.to_h { |k, v| [k.to_s, v.to_s] }
      end
      diffs << "extract_state_from_script #{c['name']}: want #{w['state']}, got #{got}" unless got == w['state']

      artifact = artifacts[c['artifact']]
      got = n320_outcome do
        Runar::SDK::RunarContract.from_utxo(
          artifact, Runar::SDK::Utxo.new(txid: txid, output_index: 0, satoshis: 1000, script: script)
        )
        'ok'
      end
      diffs << "from_utxo #{c['name']}: want #{w['fromUtxo']}, got #{got}" unless got == w['fromUtxo']
      got = n320_outcome do
        Runar::SDK::RunarContract.from_txid(artifact, txid, 0, provider)
        'ok'
      end
      diffs << "from_txid #{c['name']}: want #{w['fromUtxo']}, got #{got}" unless got == w['fromUtxo']
    end
    diffs
  end

  it 'refuses every hostile script with the typed error, inside the CPU budget' do
    start = Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID)
    main = Thread.current
    watchdog = Thread.new do
      loop do
        sleep 0.1
        used = Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID) - start
        next if used < N320_CPU_BUDGET_SECS

        main.raise(N320OverBudget, "replay exceeded #{N320_CPU_BUDGET_SECS} s of CPU")
        break
      end
    end
    begin
      diffs = n320_replay
    ensure
      watchdog.kill
    end
    expect(Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID) - start).to be < N320_CPU_BUDGET_SECS
    expect(diffs).to eq([]), diffs.join("\n")
  end
end
