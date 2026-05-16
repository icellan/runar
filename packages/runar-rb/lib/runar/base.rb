# frozen_string_literal: true

# Runar base contract classes.

module Runar
  # Base class for stateless Runar smart contracts.
  #
  # All properties are readonly. The contract logic is pure — no state
  # is carried between spending transactions.
  class SmartContract
    include Runar::DSL

    def initialize(*args)
      # Apply property defaults declared with `default:`. Subclasses should
      # call `super(...)` at the beginning of their `initialize` method so
      # that defaults are set before any custom initialization logic runs.
      self.class.runar_defaults.each do |prop_name, default_value|
        instance_variable_set(:"@#{prop_name}", default_value)
      end
    end
  end

  # Base class for stateless Runar contracts that need the raw-script escape
  # hatch (asm). Like SmartContract, all properties must be readonly —
  # UnsafeSmartContract trades the type-checked subset only for the bytes
  # inside asm() calls, not for mutable state. Use StatefulSmartContract for
  # mutable state.
  class UnsafeSmartContract < SmartContract
    # Returns a mock state script (empty bytes in test mode). Mirrors
    # StatefulSmartContract#get_state_script; exposed here so unsafe contracts
    # can still build state-continuation outputs by hand when they wrap them
    # in asm().
    def get_state_script
      ''
    end
  end

  # Structured argument for the asm compiler intrinsic. The Runar frontend
  # intercepts asm(...) calls at parse time and lowers them to a raw_script
  # ANF node; this struct only exists so native Ruby execution of contract
  # source has a stable shape to reference.
  #
  #   body      — even-length hex string of the raw Bitcoin Script opcode
  #               bytes to embed verbatim. The compiler does not re-encode or
  #               validate the semantics of these bytes, only that the string
  #               is valid hex with an even length.
  #   in_arity  — number of stack items the embedded bytes consume on entry.
  #               Defaults to 0.
  #   out_arity — number of stack items the embedded bytes leave on exit.
  #               Defaults to 1 so the common "terminal value of a public
  #               method" case works without ceremony.
  AsmArgs = Struct.new(:body, :in_arity, :out_arity, keyword_init: true) do
    def initialize(body: '', in_arity: 0, out_arity: 1)
      super
    end
  end

  # asm embeds a raw Bitcoin Script byte sequence in a contract method. Only
  # callable from inside a contract that extends UnsafeSmartContract — the
  # compiler enforces this.
  #
  # This runtime stub raises: asm is a compile-time intrinsic and cannot be
  # executed off-chain.
  def self.asm(*)
    raise 'asm() cannot be called at runtime — compile this contract with the Runar compiler'
  end

  # Base class for stateful Runar smart contracts.
  #
  # Mutable properties are carried in the UTXO state. The compiler
  # auto-injects checkPreimage at method entry and state continuation
  # at exit.
  class StatefulSmartContract < SmartContract
    attr_accessor :tx_preimage

    def initialize(*args)
      super
      @_outputs = []
      @_data_outputs = []
      @_raw_outputs = []
      @tx_preimage = ''
    end

    def add_output(satoshis, *state_values)
      @_outputs << { satoshis: satoshis, values: state_values }
    end

    # Add a raw output -- arbitrary script bytes not tied to the contract's
    # state continuation. Included in the continuation hash as a state
    # output alongside addOutput results.
    def add_raw_output(satoshis, script_bytes)
      @_raw_outputs << { satoshis: satoshis, script_bytes: script_bytes }
    end

    # Add a data output -- arbitrary script bytes (e.g. OP_RETURN data)
    # that are NOT a state continuation. The output is included in the
    # auto-computed continuation hash after state outputs and before the
    # change output, preserving declaration order.
    def add_data_output(satoshis, script_bytes)
      @_data_outputs << { satoshis: satoshis, script_bytes: script_bytes }
    end

    def get_state_script
      ''
    end

    def reset_outputs
      @_outputs = []
      @_data_outputs = []
      @_raw_outputs = []
    end

    def outputs
      @_outputs
    end

    def raw_outputs
      @_raw_outputs
    end

    def data_outputs
      @_data_outputs
    end
  end
end
