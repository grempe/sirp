RSpec.describe SIRP::Client do
  let(:instance) { described_class.new(group, hash) }

  let(:username) { 'user' }
  let(:password) { 'password' }

  let(:group) { SIRP::Prime[1024] }
  let(:hash)  { Digest::SHA256 }

  describe '#start' do
    subject { instance.start }

    let(:a) { '5b23c5d12d41b23f98a11f12a57f85b9' }

    before(:each) do
      allow(RbNaCl::Util).to receive(:bin2hex).and_return(a)
    end

    it 'should return A' do
      expect(subject).to eql('07bf1c86f9ab4be3ec66eefedc377bfde24c812c6bb61dfab45814f440066be74a12dfaa96c58c5cce6649e9c0094f2d6128505393c548fe4b897dd0c14e42ac0df6f46dd66fed42d6bbaeaa8e04696859e45cc93c8e02441579690da8d442b62f54aaeedf967b19c2f51b765fc0ed20bb559ca67e9c2384d792864e3446ad0d')
    end
  end

  describe '#authenticate' do
    subject { instance.authenticate(username, password, challenge) }

    let(:challenge) do
      {
        salt: salt,
        B:    bb
      }
    end

    let(:salt) { '7e5dc1b0b253af9d1b11dc514b5c3a2a' }
    let(:bb)   { '149f99673b11e3cacc4fbb53f695b60502485f596915775254e434a78d6ef879cfa84f76fc065203d5a94e6ee3a4289a071045867b885e6d36667ff90cc77ad003757fd11f919c17739c021318f47fa256b1f542651eca81abfabe7f9ed7aef4a65d3a4d00075694fdfcdf289e98c888b63d01334da3876bfa332c89e73759e4cb4cbf233281609499bc51d22634b9a6d15e1a34f5aac189c6701eacd5a3999a014457038742a20fd00b9502fb957e97b4ed80f858077c55f1dd52c768d33cadf91f7c00dadf6450b3a9464bd1b4aad3b5779361d169c3f9679706ab57dfb2a97d980e22e99e2cd59862684b852dd73647e86a8b74117b02795ae27539a753d2' }

    context 'when username is an empty string' do
      let(:username) { '' }

      it 'should fail' do
        expect { subject }.to raise_error(ArgumentError, 'username must not be an empty string')
      end
    end

    context 'when username is an empty string with whitespace chars' do
      let(:username) { "\x00\t\n\v\f\r " }

      it 'should fail' do
        expect { subject }.to raise_error(ArgumentError, 'username must not be an empty string')
      end
    end

    context 'when password is an empty string' do
      let(:password) { '' }

      it 'should fail' do
        expect { subject }.to raise_error(ArgumentError, 'password must not be an empty string')
      end
    end

    context 'when password is an empty string with whitespace chars' do
      let(:password) { "\x00\t\n\v\f\r " }

      it 'should fail' do
        expect { subject }.to raise_error(ArgumentError, 'password must not be an empty string')
      end
    end

    context 'when salt is an empty string' do
      let(:salt) { '' }

      it 'should fail' do
        expect { subject }.to raise_error(ArgumentError, 'salt must be a hex string')
      end
    end

    context 'when salt is not a hex string' do
      let(:salt) { '💩' }

      it 'should fail' do
        expect { subject }.to raise_error(ArgumentError, 'salt must be a hex string')
      end
    end

    context 'when "B" is an empty string' do
      let(:bb) { '' }

      it 'should fail' do
        expect { subject }.to raise_error(ArgumentError, '"B" must be a hex string')
      end
    end

    context 'when "B" is not a hex string' do
      let(:bb) { '💩' }

      it 'should fail' do
        expect { subject }.to raise_error(ArgumentError, '"B" must be a hex string')
      end
    end

    context 'when B % N == 0' do
      let(:bb) { group.N.to_s(16) }

      it 'should fail' do
        expect { subject }.to raise_error(SIRP::SafetyCheckError, 'B % N cannot equal 0')
      end
    end
  end

  describe '#verify' do
    subject { instance.verify(server_hamk) }

    context 'when server H(AMK) is an empty string' do
      let(:server_hamk) { '' }

      it { expect(subject).to be(false) }
    end

    context 'when server H(AMK) is not a hex string' do
      let(:server_hamk) { '💩' }

      it { expect(subject).to be(false) }
    end
  end

end
