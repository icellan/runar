# frozen_string_literal: true

require_relative 'types'
require_relative 'provider'
require_relative 'signer'
require_relative 'contract'
require_relative 'calling'
require_relative 'deployment'
require_relative 'script_utils'
require_relative 'state'

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
      # N-239 (user decision R92): #merge and #transfer drive an ABI that
      # cannot be made sound, so they are deprecated rather than redesigned or
      # removed. Each warns once per process on first use. Plain +warn+, not
      # +category: :deprecated+, which Ruby >= 2.7.2 suppresses by default.
      MERGE_DEPRECATION =
        'runar-sdk: warning: TokenWallet#merge is deprecated and unsafe. Its ' \
        'merge(sig, otherSupply, otherHolder) ABI cannot authenticate the companion ' \
        'input, so a holder can call merge on ONE input with a made-up otherSupply ' \
        '(supply inflation). Use the token-ft example (FungibleTokenExample, ' \
        'examples/*/token-ft/) instead (N-239).'
      TRANSFER_DEPRECATION =
        'runar-sdk: warning: TokenWallet#transfer is deprecated and unsafe. Its ' \
        'transfer(sig, to: Addr) ABI cannot re-key the PubKey holder from an Addr, ' \
        'so the token stays with the current holder instead of moving to the ' \
        'recipient. Use the token-ft example (FungibleTokenExample, ' \
        'examples/*/token-ft/) instead (N-239).'

      @deprecation_warned = {}

      # @api private
      def self.warn_deprecated_once(key, message)
        return if @deprecation_warned[key]

        @deprecation_warned[key] = true
        warn(message)
      end

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
      # @deprecated Unsafe (N-239): the transfer(sig, to: Addr) ABI cannot
      #   re-key a PubKey holder, so the token does not move to
      #   +recipient_addr+. Use the token-ft example (FungibleTokenExample).
      def transfer(recipient_addr, amount)
        TokenWallet.warn_deprecated_once(:transfer, TRANSFER_DEPRECATION)
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
      # @deprecated Unsafe (N-239): the merge(sig, otherSupply, otherHolder)
      #   ABI cannot authenticate its companion input, so a holder can inflate
      #   supply. Use the token-ft example (FungibleTokenExample).
      def merge
        TokenWallet.warn_deprecated_once(:merge, MERGE_DEPRECATION)
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

        # N-076: the artifact script is the TEMPLATE; every slot (constructor
        # arg, codeSepIndex, code-part length) is a placeholder that deployment
        # replaces, so a raw prefix of it never matches a slotted deployment.
        # With constructor slots, use the slot-aware +matches_artifact+; a
        # template with none is deployed verbatim, so its literal prefix is
        # exact.
        template = @artifact.script
        slotted = !@artifact.constructor_slots.nil? && !@artifact.constructor_slots.empty?
        declares_state = !@artifact.state_fields.nil? && !@artifact.state_fields.empty?

        all_utxos.select do |utxo|
          if utxo.script.nil? || utxo.script.empty? || template.nil? || template.empty?
            true
          elsif !slotted
            utxo.script.start_with?(template)
          else
            # N-317: any UTXO the provider lists is attacker-influenced. A
            # script that is not whole hex bytes, or that fails to parse in any
            # way below, is not an instance of this contract; it must never
            # abort the listing.
            next false unless ScriptUtils.hex_bytes?(utxo.script)

            begin
              # matches_artifact strips the state section only for artifacts
              # that declare state fields; cut it here for the rest.
              code_hex = utxo.script
              unless declares_state
                pos = State.find_last_op_return(code_hex)
                code_hex = code_hex[0, pos] if pos != -1
              end
              ScriptUtils.matches_artifact(@artifact, code_hex)
            rescue StandardError
              # Not well-formed at the artifact's slot offsets (F-238): not an
              # instance of this contract.
              false
            end
          end
        end
      end
    end
  end
end
