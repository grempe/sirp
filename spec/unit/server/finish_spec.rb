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

    context 'when "M" is an empty string with whitespace chars' do
      let(:mm) { "\x00\t\n\v\f\r " }

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

    [:A, :B, :b, :I, :s, :v].each do |key|
      context "without proof[:#{key}]" do
        before(:each) do
          proof.delete(key)
        end

        it 'should fail to initialize' do
          expect { instance }.to raise_error(ArgumentError, 'proof must have required hash keys')
        end
      end
    end
  end

  describe '#success?' do
    subject { instance.success? }

    context 'when valid params' do
      it { expect(subject).to be(true) }
    end

    context 'when invalid params' do
      context '"M" not valid' do
        let(:mm) { RbNaCl::Util.bin2hex(RbNaCl::Random.random_bytes(32)) } # I'll laugh a lot when this will fail

        it { expect(subject).to be(false) }
      end

      context 'username not valid' do
        let(:username) { 'resu' }

        it { expect(subject).to be(false) }
      end
    end
  end

  describe '#match' do
    subject { instance.match }

    context 'when valid params' do
      it 'should return expected H(A,M,K)' do
        expect(subject).to eql('02b661acc0c7d5e9354e81c41304df451b8b570227c2cbb7b82197561f980354')
      end
    end

    context 'when invalid params' do
      let(:username) { 'resu' }

      it 'should return empty string' do
        expect(subject).to eql('')
      end
    end
  end

end
