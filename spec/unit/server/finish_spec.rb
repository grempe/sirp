RSpec.describe SIRP::Server::Finish do
  include_context 'precalculated values'

  let(:instance) { described_class.new(proof, mm, group, hash) }

  let(:proof) do
    {
      A: aa,
      B: bb,
      b: b,
      I: username,
      s: salt,
      v: verifier
    }
  end

  let(:mm) { 'f168015612fd8618724ce316a290e7ec8a49c43d8960ee8f4532b1b99675d257' }

  describe '.new' do
    context 'when "M" is an empty string' do
      let(:mm) { '' }

      it 'should fail to initialize' do
        expect { instance }.to raise_error(ArgumentError, 'client M must be a hex string')
      end
    end

    context 'when "M" is not hex string' do
      let(:mm) { '💩' }

      it 'should fail to initialize' do
        expect { instance }.to raise_error(ArgumentError, 'client M must be a hex string')
      end
    end
  end
end
