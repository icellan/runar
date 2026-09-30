# frozen_string_literal: true

require_relative 'types'
require_relative 'provider'
require_relative 'signer'
require_relative 'contract'
require_relative 'calling'
require_relative 'deployment'

# TokenWallet — manages token UTXOs for a fungible token contract.
#
# Assumes the artifact describes a token contract with:
# - A +transfer+ public method.
# - A state field named +balance+, +supply+, or +amount+ of type int/bigint.
#
# This is a higher-level convenience wrapper around RunarContract for the
# common token use-case. Mirrors the TypeScript SDK's TokenWallet class.
#
#   wallet = Runar::SDK::TokenWallet.new(artifact, provider, signer)
#   balance = wallet.get_balance
#   txid = wallet.transfer(recipient_addr, amount)
#   txid = wallet.merge

module Runar
  module SDK
    class TokenWallet
      # @param artifact [RunarArtifact] compiled token contract artifact
      # @param provider [Provider] blockchain provider
      # @param signer   [Signer] signing key
      def initialize(artifact, provider, signer)
        @artifact = artifact
        @provider = provider
        @signer   = signer
      end

      # Get the total token balance across all UTXOs belonging to this wallet.
      #
      # @return [Integer] total balance
      def get_balance
        utxos = get_utxos
        total = 0

        utxos.each do |utxo|
          contract = RunarContract.from_txid(@artifact, utxo.txid, utxo.output_index, @provider)
          state = contract.get_state
          balance_val = state['supply'] || state['balance'] || state['amount'] || 0
          total += balance_val.to_i
        end

        total
      end

      # Transfer the entire balance of a token UTXO to a new address.
      #
      # The FungibleToken.transfer(sig, to) method transfers the full supply
      # held in the UTXO to the given address. The signature is produced by
      # this wallet's signer and passed as the first argument.
      #
      # @param recipient_addr [String] the BSV address (Addr) of the recipient
      # @param amount [Integer] minimum token balance required in the source UTXO
      # @return [String] the txid of the transfer transaction
      def transfer(recipient_addr, amount)
        utxos = get_utxos
        raise 'TokenWallet.transfer: no token UTXOs found' if utxos.empty?

        utxos.each do |utxo|
          contract = RunarContract.from_txid(@artifact, utxo.txid, utxo.output_index, @provider)
          state = contract.get_state
          balance = (state['balance'] || state['supply'] || state['amount'] || 0).to_i

          next unless balance >= amount

          # FungibleToken.transfer(sig: Sig, to: Addr)
          # F-045: pass nil for the Sig so +call+ auto-signs the transaction it
          # actually builds and broadcasts. Signing a locally built preliminary
          # tx covers a different tx and is rejected on-chain.
          # An Addr is a 20-byte hash160: accept a Base58 address (as
          # documented), a raw hash160, or a public key.
          to_pkh = SDK.build_p2pkh_script(recipient_addr)[6, 40]
          contract.connect(@provider, @signer)
          txid, _tx = contract.call('transfer', [nil, to_pkh])
          return txid
        end

        raise "TokenWallet.transfer: insufficient token balance for transfer of #{amount}"
      end

      # Merge two token UTXOs into a single UTXO.
      #
      # FungibleToken.merge(sig, otherSupply, otherHolder) combines the supply
      # from two UTXOs. The second UTXO's supply and holder are read from its
      # on-chain state and passed as arguments.
      #
      # @return [String] the txid of the merge transaction
      def merge
        utxos = get_utxos
        raise 'TokenWallet.merge: need at least 2 UTXOs to merge' if utxos.length < 2

        first_utxo = utxos[0]
        contract = RunarContract.from_txid(@artifact, first_utxo.txid, first_utxo.output_index, @provider)

        second_utxo = utxos[1]
        second_contract = RunarContract.from_txid(@artifact, second_utxo.txid, second_utxo.output_index, @provider)
        second_state = second_contract.get_state

        other_supply = (second_state['supply'] || second_state['balance'] || second_state['amount'] || 0).to_i
        other_holder = (second_state['holder'] || '').to_s

        # FungibleToken.merge(sig: Sig, otherSupply: bigint, otherHolder: PubKey)
        # F-045: spend BOTH token UTXOs in one tx. Each input's unlock carries
        # the OTHER input's supply/holder, and every Sig is nil so +call+ signs
        # each input over the transaction it actually broadcasts.
        first_state = contract.get_state
        first_supply = (first_state['supply'] || first_state['balance'] || first_state['amount'] || 0).to_i
        first_holder = (first_state['holder'] || '').to_s

        contract.connect(@provider, @signer)
        opts = CallOptions.new(
          change_address: @signer.get_address,
          additional_contract_inputs: [second_utxo],
          additional_contract_input_args: [[nil, first_supply, first_holder]]
        )
        txid, _tx = contract.call('merge', [nil, other_supply, other_holder], nil, nil, opts)
        txid
      end

      # Get all token UTXOs associated with this wallet's signer address.
      #
      # Filters UTXOs to only those whose script matches the token contract's
      # locking script prefix (the code portion, before state).
      #
      # @return [Array<Utxo>]
      def get_utxos
        address = @signer.get_address
        all_utxos = @provider.get_utxos(address)

        script_prefix = @artifact.script

        all_utxos.select do |utxo|
          if utxo.script && !utxo.script.empty? && script_prefix && !script_prefix.empty?
            utxo.script.start_with?(script_prefix)
          else
            true
          end
        end
      end
    end
  end
end
