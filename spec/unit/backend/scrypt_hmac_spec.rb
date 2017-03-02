require 'sirp/backend/scrypt_hmac'

RSpec.describe SIRP::Backend::SCryptHMAC do
  let(:instance) { described_class.new(SIRP::Prime[2048], Digest::SHA2) }

  describe '#calc_x' do
    subject { instance.calc_x(username, password, salt) }

    let(:username) { 'user' }
    let(:password) { 'password' }
    let(:salt)     { '01ebb2496e4e8d32e6f7967ee9fec64e' }

    it 'should calculate expected result' do
      expect('%x' % subject).to eql('1fbca479f5b4b660a2d5ce1c05193232ba6732377b5072648bae764ce51bb093')
    end
  end
end
