RSpec.describe SIRP::Register do
  let(:instance) { described_class.new(username, password, group, hash) }

  let(:username) { 'user' }
  let(:password) { 'password' }

  let(:group) { SIRP::Prime[1024] }
  let(:hash)  { Digest::SHA256 }

  describe '#credentials' do
    subject { instance.credentials }

    let(:salt) { '5b23c5d12d41b23f98a11f12a57f85b9' }

    before(:each) do
      allow(RbNaCl::Util).to receive(:bin2hex).and_return(salt)
    end

    describe ':username' do
      it 'returns given username' do
        expect(subject[:username]).to equal(username)
      end
    end

    describe ':verifier' do
      it 'returns expected verifier' do
        expect(subject[:verifier]).to eql('cdd1c991ee190f3481e33c24b2b420d3d99d36a224d401e5c78b84062827193878503c90dd9aa47802b47948dab4eec8d5c6c4ddc4711ef4532de7ff0412d0df106d4b377e8b1c8dbf0092c27b40900d34fad913bfa1aac53b1e211766b283817b1bacae5eeca2933ac779cfae83840e8f50b46ea5a23614d9aa24e41fc0740a')
      end
    end

    describe ':salt' do
      it 'returns generated salt' do
        expect(subject[:salt]).to equal(salt)
      end
    end
  end

end
