# frozen_string_literal: true

# EC isolation integration tests -- inline contracts testing individual EC functions.
#
# Each test compiles a minimal stateless contract that exercises a single EC
# built-in, deploys it on regtest, and spends via contract.call().
#
# Inline source is written to a temp file in /tmp/, compiled via the TypeScript
# compiler, then cleaned up.

require 'spec_helper'
require 'tempfile'

# Compile an inline TypeScript source string to a RunarArtifact.
#
# Writes the source to a temp file in /tmp/, shells out to the TS compiler,
# and cleans up afterwards.
#
# @param source    [String] TypeScript contract source
# @param file_name [String] desired file name suffix (e.g. "MyContract.runar.ts")
# @return [Runar::SDK::RunarArtifact]
def compile_source(source, file_name)
  require 'shellwords'

  script = <<~JS
    const { compile } = require('#{PROJECT_ROOT}/packages/runar-compiler/dist/index.js');
    const result = compile(#{source.inspect}, { fileName: #{file_name.inspect} });
    if (!result.success) { console.error(JSON.stringify(result.diagnostics)); process.exit(1); }
    const json = JSON.stringify(result.artifact, (k, v) => typeof v === 'bigint' ? v.toString() + 'n' : v);
    process.stdout.write(json);
  JS

  output = `node -e #{Shellwords.escape(script)} 2>&1`
  status = Process.last_status
  raise "Compilation failed for #{file_name}:\n#{output}" unless status&.success?

  Runar::SDK::RunarArtifact.from_json(output)
end

RSpec.describe 'EC isolation' do # rubocop:disable RSpec/DescribeClass
  it 'compiles and deploys ecOnCurve: contract checking point validity' do
    source = <<~TS
      import { SmartContract, assert, ecOnCurve } from 'runar-lang';
      import type { Point } from 'runar-lang';

      class EcOnCurveTest extends SmartContract {
        readonly p: Point;

        constructor(p: Point) {
          super(p);
          this.p = p;
        }

        public verify() {
          assert(ecOnCurve(this.p));
        }
      }
    TS

    artifact = compile_source(source, 'EcOnCurveTest.runar.ts')
    expect(artifact.contract_name).to eq('EcOnCurveTest')

    gx, gy = ec_mul_gen(42)
    point_hex = encode_point(gx, gy)

    contract = Runar::SDK::RunarContract.new(artifact, [point_hex])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy

    call_txid, _count = contract.call('verify', [], provider, wallet[:signer])
    expect(call_txid).to be_truthy
  end

  it 'compiles and deploys ecMulGen: scalar-multiply-generator contract' do
    source = <<~TS
      import { SmartContract, assert, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
      import type { Point } from 'runar-lang';

      class EcMulGenTest extends SmartContract {
        readonly expected: Point;

        constructor(expected: Point) {
          super(expected);
          this.expected = expected;
        }

        public verify(k: bigint) {
          const result = ecMulGen(k);
          assert(ecPointX(result) === ecPointX(this.expected));
          assert(ecPointY(result) === ecPointY(this.expected));
        }
      }
    TS

    artifact = compile_source(source, 'EcMulGenTest.runar.ts')
    expect(artifact.contract_name).to eq('EcMulGenTest')

    k = 7
    ex, ey = ec_mul_gen(k)
    expected_hex = encode_point(ex, ey)

    contract = Runar::SDK::RunarContract.new(artifact, [expected_hex])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy

    call_txid, _count = contract.call('verify', [k], provider, wallet[:signer])
    expect(call_txid).to be_truthy
  end

  it 'compiles and deploys ecAdd: point addition contract' do
    source = <<~TS
      import { SmartContract, assert, ecAdd, ecPointX, ecPointY } from 'runar-lang';
      import type { Point } from 'runar-lang';

      class EcAddTest extends SmartContract {
        readonly a: Point;
        readonly b: Point;
        readonly expected: Point;

        constructor(a: Point, b: Point, expected: Point) {
          super(a, b, expected);
          this.a = a;
          this.b = b;
          this.expected = expected;
        }

        public verify() {
          const result = ecAdd(this.a, this.b);
          assert(ecPointX(result) === ecPointX(this.expected));
          assert(ecPointY(result) === ecPointY(this.expected));
        }
      }
    TS

    artifact = compile_source(source, 'EcAddTest.runar.ts')
    expect(artifact.contract_name).to eq('EcAddTest')

    ax, ay = ec_mul_gen(3)
    bx, by = ec_mul_gen(5)
    # 3G + 5G = 8G
    ex, ey = ec_mul_gen(8)

    contract = Runar::SDK::RunarContract.new(artifact, [
      encode_point(ax, ay),
      encode_point(bx, by),
      encode_point(ex, ey)
    ])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy

    call_txid, _count = contract.call('verify', [], provider, wallet[:signer])
    expect(call_txid).to be_truthy
  end

  it 'compiles, deploys, and spends ecNegate: point negation contract' do
    source = <<~TS
      import { SmartContract, assert, ecNegate, ecPointY } from 'runar-lang';
      import type { Point } from 'runar-lang';

      class EcNegateTest extends SmartContract {
        readonly pt: Point;

        constructor(pt: Point) {
          super(pt);
          this.pt = pt;
        }

        public check(expectedNegY: bigint) {
          assert(ecPointY(ecNegate(this.pt)) === expectedNegY);
        }
      }
    TS

    artifact = compile_source(source, 'EcNegateTest.runar.ts')
    expect(artifact.contract_name).to eq('EcNegateTest')

    px, py = ec_mul_gen(10)
    contract = Runar::SDK::RunarContract.new(artifact, [encode_point(px, py)])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy

    neg_y = IntegrationHelpers::EC_P - py
    call_txid, _count = contract.call('check', [neg_y], provider, wallet[:signer])
    expect(call_txid).to be_truthy
  end

  it 'compiles and deploys ecPointX: extract the X coordinate of a point' do
    source = <<~TS
      import { SmartContract, assert, ecPointX } from 'runar-lang';
      import type { Point } from 'runar-lang';

      class EcPointXTest extends SmartContract {
        readonly pt: Point;
        constructor(pt: Point) { super(pt); this.pt = pt; }
        public check(expectedX: bigint) { assert(ecPointX(this.pt) === expectedX); }
      }
    TS

    artifact = compile_source(source, 'EcPointXTest.runar.ts')

    # Use generator point
    gx, gy = ec_mul_gen(1)
    point_hex = encode_point(gx, gy)

    contract = Runar::SDK::RunarContract.new(artifact, [point_hex])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # Pass Gx as expected value
    call_txid, _count = contract.call('check', [gx], provider, wallet[:signer])
    expect(call_txid).to be_truthy
  end

  it 'compiles and spends ecOnCurve + ecPointX: verify point and extract X' do
    source = <<~TS
      import { SmartContract, assert, ecOnCurve, ecPointX } from 'runar-lang';
      import type { Point } from 'runar-lang';

      class EcOnCurveTwice extends SmartContract {
        readonly pt: Point;
        constructor(pt: Point) { super(pt); this.pt = pt; }
        public check(expectedX: bigint) {
          assert(ecOnCurve(this.pt));
          assert(ecPointX(this.pt) === expectedX);
        }
      }
    TS

    artifact = compile_source(source, 'EcOnCurveTwice.runar.ts')

    gx, gy = ec_mul_gen(1)
    point_hex = encode_point(gx, gy)

    contract = Runar::SDK::RunarContract.new(artifact, [point_hex])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    call_txid, _count = contract.call('check', [gx], provider, wallet[:signer])
    expect(call_txid).to be_truthy
  end

  it 'compiles and spends the full EC convergence proof pattern' do
    source = <<~TS
      import { SmartContract, assert, ecOnCurve, ecAdd, ecNegate, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
      import type { Point } from 'runar-lang';

      class ConvergencePattern extends SmartContract {
        readonly rA: Point;
        readonly rB: Point;
        constructor(rA: Point, rB: Point) { super(rA, rB); this.rA = rA; this.rB = rB; }
        public proveConvergence(deltaO: bigint) {
          assert(ecOnCurve(this.rA));
          assert(ecOnCurve(this.rB));
          const diff = ecAdd(this.rA, ecNegate(this.rB));
          const expected = ecMulGen(deltaO);
          assert(ecPointX(diff) === ecPointX(expected));
          assert(ecPointY(diff) === ecPointY(expected));
        }
      }
    TS

    artifact = compile_source(source, 'ConvergencePattern.runar.ts')

    a = 142
    b = 37
    delta_o = a - b
    rax, ray = ec_mul_gen(a)
    rbx, rby = ec_mul_gen(b)

    contract = Runar::SDK::RunarContract.new(artifact, [
      encode_point(rax, ray),
      encode_point(rbx, rby)
    ])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 500_000))

    call_txid, _count = contract.call('proveConvergence', [delta_o], provider, wallet[:signer])
    expect(call_txid).to be_truthy
  end

  it 'compiles and spends ecMulGen with large scalar near curve order' do
    source = <<~TS
      import { SmartContract, assert, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
      import type { Point } from 'runar-lang';

      class EcMulGenTest extends SmartContract {
        readonly expected: Point;
        constructor(expected: Point) { super(expected); this.expected = expected; }
        public verify(k: bigint) {
          const result = ecMulGen(k);
          assert(ecPointX(result) === ecPointX(this.expected));
          assert(ecPointY(result) === ecPointY(this.expected));
        }
      }
    TS

    artifact = compile_source(source, 'EcMulGenTest.runar.ts')

    k = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364100
    ex, ey = ec_mul_gen(k)

    contract = Runar::SDK::RunarContract.new(artifact, [encode_point(ex, ey)])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    call_txid, _count = contract.call('verify', [k], provider, wallet[:signer])
    expect(call_txid).to be_truthy
  end
end
