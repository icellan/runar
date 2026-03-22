# frozen_string_literal: true

# WARNING: TEST-ONLY KEY MATERIAL
#
# These keys are derived from well-known values (e.g., ALICE's private key is
# SHA-256 of the empty string). They MUST NEVER be used on mainnet or to hold
# real funds. They exist solely for deterministic testing of ECDSA verification.

# Pre-generated deterministic test keys for use across all Ruby test suites.
#
# These keys match the Python reference implementation (runar/test_keys.py)
# exactly. All derived values (public key, pubkey hash, test signature) are
# deterministic and reproducible using RFC 6979.
#
# Usage:
#   require 'runar/test_keys'
#   Runar::TestKeys::ALICE.pub_key   # => hex-encoded compressed public key
#   Runar::TestKeys::ALICE.test_sig  # => hex-encoded DER ECDSA signature

module Runar
  module TestKeys
    # A pre-generated test keypair with all derived values.
    #
    # All fields are hex-encoded strings to match the Ruby convention used
    # throughout the Runar SDK (ByteString values are represented as hex).
    #
    # @attr name          [String] lowercase name of this test identity
    # @attr priv_key      [String] 64-char hex private key scalar
    # @attr pub_key       [String] 66-char hex compressed secp256k1 public key (33 bytes)
    # @attr pub_key_hash  [String] 40-char hex HASH160 of pub_key (20 bytes)
    # @attr test_sig      [String] hex-encoded DER ECDSA signature over TEST_MESSAGE
    TestKeyPair = Struct.new(:name, :priv_key, :pub_key, :pub_key_hash, :test_sig)

    # Named test keys — matching Python test_keys.py and TypeScript test-keys.ts.
    #
    # All pub_key, pub_key_hash, and test_sig values were computed deterministically
    # from their priv_key using:
    #   - ECDSA.pub_key_from_priv_key  (secp256k1 scalar multiplication)
    #   - hash160                       (RIPEMD160(SHA256(pub_key)))
    #   - ECDSA.sign_test_message       (RFC 6979 deterministic signing)

    # TEST-ONLY: private key = SHA-256("") — a well-known value. Never use on mainnet.
    ALICE = TestKeyPair.new(
      'alice',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd',
      '9a1c78a507689f6f54b847ad1cef1e614ee23f1e',
      '3045022100e2aa1265ce57f54b981ffc6a5f3d229e908d7772fceb75a50c8c2d6076313df0' \
      '0220607dbca2f9f695438b49eefea4e445664c740163af8b62b1373f87d50eb64417'
    ).freeze

    # TEST-ONLY: well-known repeating byte pattern private key. Never use on mainnet.
    BOB = TestKeyPair.new(
      'bob',
      'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      '03d6bfe100d1600c0d8f769501676fc74c3809500bd131c8a549f88cf616c21f35',
      '89b460e4e984ef496ff0b135712f3d9b9fc80482',
      '3044022058329072a0f9e6133d93109502ddea833f043f00b460950683fa80c00ca4d98802200328ff8f8c1da673a489c93ed0b8e83b143afbeb3495ae4aad4714c256984608'
    ).freeze

    # TEST-ONLY: well-known "deadbeef" repeating private key. Never use on mainnet.
    CHARLIE = TestKeyPair.new(
      'charlie',
      'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
      '02c6b754b20826eb925e052ee2c25285b162b51fdca732bcf67e39d647fb6830ae',
      '66c1d8577d77be82e3e0e6ac0e14402e3fc67ff3',
      '3043022100aa67cfa7255b90992a8f5d2bc7e9a38f42b12b3a6c7cca7cb654a171e3aefd85' \
      '021e277740c4409c641cfb47370f510b3ecfff752488a855aacfc9913e66d038'
    ).freeze

    # TEST-ONLY: well-known "cafebabe" repeating private key. Never use on mainnet.
    DAVE = TestKeyPair.new(
      'dave',
      'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe',
      '03672a31bfc59d3f04548ec9b7daeeba2f61814e8ccc40448045007f5479f693a3',
      'd88306005f88e2f485f0b36cbbbc19a4690a6937',
      '30440220127bee35050df26cfa366e97e9c02ec33ebff69a204c1dc25aefc8b313976198' \
      '02201a2157c935108716ec41d53b7137238083a331f57e0f8e34953f2a5f54acb7c9'
    ).freeze

    # TEST-ONLY: well-known "abcdef01" repeating private key. Never use on mainnet.
    EVE = TestKeyPair.new(
      'eve',
      'abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01',
      '02f259306ad65e02f6550fb0c21896cb068ff59189124858664287c7b692d7de4f',
      '9fe66d04519c5bb39a5e458d817206e7e0eb80ec',
      '3045022100cfcc9cd4dca3905979c2b2b0c9646459a8cfb8eeec4b476c06ff6e7333a0dbd2' \
      '022029443a9aafa6dc08231043f06940cfcf045c6e3783314ccac252d4333fb7a114'
    ).freeze

    # TEST-ONLY: well-known "1111..." private key. Never use on mainnet.
    FRANK = TestKeyPair.new(
      'frank',
      '1111111111111111111111111111111111111111111111111111111111111111',
      '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa',
      'fc7250a211deddc70ee5a2738de5f07817351cef',
      '3044022053fff242b1c221d510fc062ede923778020171f807a89b582953c15db0bb6f8e' \
      '02207f49fd920e6b947d09a394072b7804900fa81a6d46d86066e217b4ffc3691b3d'
    ).freeze

    # TEST-ONLY: well-known "2222..." private key. Never use on mainnet.
    GRACE = TestKeyPair.new(
      'grace',
      '2222222222222222222222222222222222222222222222222222222222222222',
      '02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27',
      '531260aa2a199e228c537dfa42c82bea2c7c1f4d',
      '3045022100f764889b01cb498c05c4f5c2718bb0cca0c6cd00299ea73a9fe7d01900fbff82' \
      '02204738757bbf407e42cd292375387e38fa53c983a2c75d5eeeaf0512e44b4e9a91'
    ).freeze

    # TEST-ONLY: well-known "3333..." private key. Never use on mainnet.
    HEIDI = TestKeyPair.new(
      'heidi',
      '3333333333333333333333333333333333333333333333333333333333333333',
      '023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1',
      '3bc28d6d92d9073fb5e3adf481795eaf446bceed',
      '3045022100f83d7c0ed0f48f680f40a4b38c9872bb14cb2396af19b4b2713a0bf99b174577' \
      '02205b1f04cac7da387a46e7beb958fa8b523a803ace06148a0d7557960ff2388790'
    ).freeze

    # TEST-ONLY: well-known "4444..." private key. Never use on mainnet.
    IVAN = TestKeyPair.new(
      'ivan',
      '4444444444444444444444444444444444444444444444444444444444444444',
      '032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991',
      'cc1b07838e387deacd0e5232e1e8b49f4c29e484',
      '3045022100d60c57d9501b3fecd50d35be73176eb3dad7506f37e0671d9018bd1de71dd314' \
      '022060b010c949554d8301e09ea42700bffedb2f08f75336ce3aa0f66f955ece6e02'
    ).freeze

    # TEST-ONLY: well-known "5555..." private key. Never use on mainnet.
    JUDY = TestKeyPair.new(
      'judy',
      '5555555555555555555555555555555555555555555555555555555555555555',
      '029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b',
      'e1fae3324e28a4ef5ee01f14dd337ac6c85d1d90',
      '304402207fb1e45b48dd8ffeff9678ecf394d912fd0446bb85532159f44e6b26b701e0c9' \
      '02205a60cb2b2fab76922c52b115843f6843b0a1715f832629ea0d126f9dc663c0f3'
    ).freeze

    TEST_KEYS = [ALICE, BOB, CHARLIE, DAVE, EVE, FRANK, GRACE, HEIDI, IVAN, JUDY].freeze
  end
end
