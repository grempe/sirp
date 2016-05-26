# encoding: utf-8
require 'spec_helper'

describe SIRP do
  include SIRP

  context 'hex_to_bytes' do
    it 'should calculate expected results' do
      expect(hex_to_bytes('abcdef0123456789'))
        .to eq [171, 205, 239, 1, 35, 69, 103, 137]
    end
  end

  context 'num_to_hex' do
    it 'should calculate expected results' do
      num = 999_999_999_999
      expect(num_to_hex(num))
        .to eq 'e8d4a50fff'
      expect('e8d4a50fff'.hex).to eq num
    end
  end

  context 'sha_hex' do
    it 'should calculate expected results for SHA1' do
      str = 'foo'
      str_unpacked = str.unpack('H*')[0]
      str_sha = Digest::SHA1.hexdigest(str)
      expect(sha_hex(str_unpacked, Digest::SHA1)).to eq str_sha
    end

    it 'should calculate expected results for SHA256' do
      str = 'foo'
      str_unpacked = str.unpack('H*')[0]
      str_sha = Digest::SHA256.hexdigest(str)
      expect(sha_hex(str_unpacked, Digest::SHA256)).to eq str_sha
    end
  end

  context 'sha_str' do
    it 'should calculate expected results for SHA1' do
      expect(sha_str('foo', Digest::SHA1))
        .to eq '0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33'
    end

    it 'should calculate expected results for SHA256' do
      expect(sha_str('foo', Digest::SHA256))
        .to eq '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
    end
  end

  context 'secure_compare' do
    it 'should return true when string args match' do
      expect(secure_compare('foo', 'foo')).to be true
    end

    it 'should return false when string args do not match' do
      expect(secure_compare('foo', 'bar')).to be false
    end

    it 'should return true when hash string args match' do
      expect(secure_compare(Digest::SHA256.hexdigest('foo'),
        Digest::SHA256.hexdigest('foo'))).to be true
    end

    it 'should return false when hash string args do not match' do
      expect(secure_compare(Digest::SHA256.hexdigest('foo'),
        Digest::SHA256.hexdigest('bar'))).to be false
    end
  end
end
