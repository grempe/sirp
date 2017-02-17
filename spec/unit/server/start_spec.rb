RSpec.describe SIRP::Server::Start do
  let(:instance) { described_class.new(user, aa, group, hash) }

  let(:user) do
    {
      username: username,
      verifier: verifier,
      salt:     salt
    }
  end

  let(:username) { 'user' }
  let(:verifier) { 'b20536acc536952df844101d940e8d1dd1f5b10a336fc90c642db1de4b9a0b86cf50c3b7b8a6b857b99f75887fe252be709d797c32072b9446c9f678909313c901a473f9c52b6556993026fa72432d21169dfcffd71c02f8191fb00ac4f8f3b02b9f6f519aeb1b13a902208d26a95766be32a057c726482e103637f31be6e23c' }
  let(:salt)     { 'eb25522cc747e55b31116b427f017fc8' }

  let(:aa)    { '7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2' }
  let(:group) { SIRP::Prime[1024] }
  let(:hash)  { Digest::SHA256 }

  let(:b) { '50fb5a94be79cc0398d1dd94d49aec2e9fc63e63d57d01eb84c521606677d95b' }

  describe '.new' do
    context 'when empty username' do
      let(:username) { '' }

      it 'should fail to initialize' do
        expect { instance }.to raise_error(ArgumentError, 'username must not be an empty string')
      end
    end

    context 'when verifier is an empty string' do
      let(:verifier) { '' }

      it 'should fail to initialize' do
        expect { instance }.to raise_error(ArgumentError, 'verifier must be a hex string')
      end
    end

    context 'when verifier is not hex string' do
      let(:verifier) { '💩' }

      it 'should fail to initialize' do
        expect { instance }.to raise_error(ArgumentError, 'verifier must be a hex string')
      end
    end

    context 'when salt is an empty string' do
      let(:salt) { '' }

      it 'should fail to initialize' do
        expect { instance }.to raise_error(ArgumentError, 'salt must be a hex string')
      end
    end

    context 'when salt is not hex string' do
      let(:salt) { '💩' }

      it 'should fail to initialize' do
        expect { instance }.to raise_error(ArgumentError, 'salt must be a hex string')
      end
    end

    context 'when "A" is an empty string' do
      let(:aa) { '💩' }

      it 'should fail to initialize' do
        expect { instance }.to raise_error(ArgumentError, '"A" must be a hex string')
      end
    end

    context 'when "A" is not hex string' do
      let(:aa) { '💩' }

      it 'should fail to initialize' do
        expect { instance }.to raise_error(ArgumentError, '"A" must be a hex string')
      end
    end

    context 'when A.to_i(16) % N == 0' do
      let(:aa) { group.N.to_s(16) }

      it 'should fail to initialize' do
        expect { instance }.to raise_error(SIRP::SafetyCheckError, 'A.to_i(16) % N cannot equal 0')
      end
    end
  end

  describe '#challenge' do
    subject { instance.challenge }

    it 'should contain B and salt' do
      expect(subject.keys).to contain_exactly(:B, :salt)
    end

    it 'returns salt' do
      expect(subject[:salt]).to equal(salt)
    end

    context 'with predefined b' do
      before(:each) do
        allow(RbNaCl::Util).to receive(:bin2hex).and_return(b)
      end

      it 'should generate expected B' do
        expect(subject[:B]).to eql('b60db854be4edadd3f2e89fabf79aa48306d262ca8ae41d57cba6aa1122b63681f49da88b1d5ddcd753f40b6b9366c16fe476350f56963a72e59ac489ab9295fa6bf1b404d126bf07e093c42e690751bcff51ac18ddb90451f699582378f21d8a2b1a331c36697947889c3d4549c4a91d55e7fe0e376e6335ab27b4ec8490f6b')
      end
    end
  end

  describe '#proof' do
    subject { instance.proof }

    it 'should contain A, B, b, I, s and v' do
      expect(subject.keys).to contain_exactly(:A, :B, :b, :I, :s, :v)
    end

    it 'returns "A"' do
      expect(subject[:A]).to equal(aa)
    end

    it 'returns username as "I"' do
      expect(subject[:I]).to equal(username)
    end

    it 'returns salt as "s"' do
      expect(subject[:s]).to equal(salt)
    end

    it 'returns verifier as "v"' do
      expect(subject[:v]).to equal(verifier)
    end

    context 'with predefined b' do
      before(:each) do
        allow(RbNaCl::Util).to receive(:bin2hex).and_return(b)
      end

      it 'returns B' do
        expect(subject[:B]).to eql('b60db854be4edadd3f2e89fabf79aa48306d262ca8ae41d57cba6aa1122b63681f49da88b1d5ddcd753f40b6b9366c16fe476350f56963a72e59ac489ab9295fa6bf1b404d126bf07e093c42e690751bcff51ac18ddb90451f699582378f21d8a2b1a331c36697947889c3d4549c4a91d55e7fe0e376e6335ab27b4ec8490f6b')
      end

      it 'returns b' do
        expect(subject[:b]).to equal(b)
      end
    end
  end

end
