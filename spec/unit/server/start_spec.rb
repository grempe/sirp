RSpec.describe SIRP::Server::Start do
  include_context 'precalculated values'

  let(:instance) { described_class.new(user, aa, group, hash) }

  let(:user) do
    {
      username: username,
      verifier: verifier,
      salt:     salt
    }
  end

  describe '.new' do
    context 'when username is an empty string' do
      let(:username) { '' }

      it 'should fail to initialize' do
        expect { instance }.to raise_error(ArgumentError, 'username must not be an empty string')
      end
    end

    context 'when username is an empty string with whitespace chars' do
      let(:username) { "\x00\t\n\v\f\r " }

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

    context 'when salt is an empty string with whitespace chars' do
      let(:salt) { "\x00\t\n\v\f\r " }

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
      let(:aa) { '' }

      it 'should fail to initialize' do
        expect { instance }.to raise_error(ArgumentError, '"A" must be a hex string')
      end
    end

    context 'when "A" is an empty string with whitespace chars' do
      let(:aa) { "\x00\t\n\v\f\r " }

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

    context 'when user have string keys' do
      let(:user) do
        {
          "username" => username,
          "verifier" => verifier,
          "salt"     => salt
        }
      end

      it 'should not fails' do
        expect { instance }.to_not raise_error
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

    context 'with predefined "b"' do
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
