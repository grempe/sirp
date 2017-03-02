require 'sirp/backend/digest'

RSpec.describe SIRP::Backend::Digest do
  let(:instance) { described_class.new(SIRP::Prime[2048], Digest::SHA1) }

  describe '#calc_x' do
    subject { instance.calc_x(username, password, salt) }

    let(:username) { 'user' }
    let(:password) { 'password' }
    let(:salt)     { '16ccfa081895fe1ed0bb' }

    it 'should calculate expected result' do
      expect('%x' % subject).to eql('bdd0a4e1c9df4082684d8d358b8016301b025375')
    end
  end
end
