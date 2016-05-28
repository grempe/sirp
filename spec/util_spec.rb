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

  context 'secure_compare' do
    it 'should return true when string args match' do
      expect(secure_compare('foo', 'foo')).to be true
    end

    it 'should return false when string args do not match' do
      expect(secure_compare('foo', 'bar')).to be false
    end
  end
end
