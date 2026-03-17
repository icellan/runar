# frozen_string_literal: true

# Runar SDK — entry point.
#
# Provides types, provider, and signer abstractions for deploying and
# interacting with compiled Runar contracts on BSV. Require this file to
# load the entire SDK namespace:
#
#   require 'runar/sdk'
#
# Note: this file is intentionally *not* required by the main runar.rb
# entry point. It is wired in separately (see issue #15).

require_relative 'sdk/types'
require_relative 'sdk/provider'
require_relative 'sdk/signer'
require_relative 'sdk/state'
require_relative 'sdk/deployment'
require_relative 'sdk/calling'
require_relative 'sdk/oppushtx'
require_relative 'sdk/local_signer'
require_relative 'sdk/rpc_provider'
require_relative 'sdk/anf_interpreter'
require_relative 'sdk/contract'
