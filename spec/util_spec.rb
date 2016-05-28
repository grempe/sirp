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

  context 'secure_compare' do
    it 'should return true when string args match' do
      expect(secure_compare('foo', 'foo')).to be true
    end

    it 'should return false when string args do not match' do
      expect(secure_compare('foo', 'bar')).to be false
    end
  end
end
