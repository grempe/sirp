# encoding: utf-8
require 'spec_helper'

describe SIRP do
  include SIRP
  # Test predefined values for N and g.
  # Values are from vectors listed in RFC 5054 Appendix B.
  #
  context 'parameters' do
    it 'should raise an error on unknown verifier group size' do
      expect { Ng(1234) }.to raise_error(ArgumentError, 'must be a known group size')
    end

    before :all do
      @params = [
        { group: 1024, generator: 2, hash: Digest::SHA1, hash_nn: '0995b627385b26f55dc1fe18de984252e0357b9f2c884d8d3f9fd9f2de32f408' },
        { group: 1536, generator: 2, hash: Digest::SHA1, hash_nn: 'ba36a6059669d1d9eb4125d63eeca771bb7bb54efa14cb5ef8efd07ef8bf2094' },
        { group: 2048, generator: 2, hash: Digest::SHA256, hash_nn: 'ef88b43c555c005c89f9c32dbd2ced49b0bb57e2cd1f2b5e9eca181afdf09c56' },
        { group: 3072, generator: 5, hash: Digest::SHA256, hash_nn: '30a45e27c3a0a6f934cd558e88e937625082b19bd435f74f04d7500e5032d88e' },
        { group: 4096, generator: 5, hash: Digest::SHA256, hash_nn: '233836aba654664fc65121b25f1760c0e72456e834bc42315fa21d38ade81cac' },
        { group: 6144, generator: 5, hash: Digest::SHA256, hash_nn: 'b84b67a0c9b0d7870cedf59880bed18dff60d4e965fe0f82ee70618861cc0a07' },
        { group: 8192, generator: 19, hash: Digest::SHA256, hash_nn: 'a408aa7fd5e69ae6886c3b3fd50051efc417d62cf224cebf8d8aeb49654185ed' }
      ]
    end

    it 'should be correct when accessed through a SIRP::Verifier' do
      @params.each do |p|
        v = SIRP::Verifier.new(p[:group])
        expect(('%b' % v.N).length).to eq(p[:group])
        expect(Digest::SHA256.hexdigest(('%x' % v.N))).to eq(p[:hash_nn])
        expect(v.g).to eq(p[:generator])
        expect(v.hash).to eq(p[:hash])
      end
    end

    it 'should be correct when accessed through a Ng' do
      @params.each do |p|
        nn, g, h = Ng(p[:group])
        expect(('%b' % nn).length).to eq(p[:group])
        expect(Digest::SHA256.hexdigest(('%x' % nn))).to eq(p[:hash_nn])
        expect(g).to eq(p[:generator])
        expect(h).to eq(p[:hash])
      end
    end
  end
end
