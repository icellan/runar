# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = 'runar-lang'
  spec.version       = '0.4.2'
  spec.authors       = ['Runar Contributors']
  spec.summary       = 'Ruby runtime for Runar Bitcoin Script contracts'
  spec.description   = 'Provides base classes, types, mock crypto, real hashes, and EC operations ' \
                        'for writing and testing Runar smart contracts in Ruby.'
  spec.homepage      = 'https://github.com/icellan/runar'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 3.0'

  spec.files         = Dir['lib/**/*.rb']
  spec.require_paths = ['lib']

  # No external dependencies — stdlib only (digest, openssl)

  spec.add_development_dependency 'ruby-lsp', '~> 0.26'
  spec.add_development_dependency 'ostruct'
end
