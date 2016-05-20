# encoding: utf-8
require 'spec_helper'

describe SIRP do
  # From http://srp.stanford.edu/demo/demo.html using 1024 bit SHA1 values.
  context 'client' do
    before :all do
      @username = 'user'
      @password = 'password'
      @salt     = '16ccfa081895fe1ed0bb'
      @a        = '7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2'
      @b        = '8143e2f299852a05717427ea9d87c6146e747d0da6e95f4390264e55a43ae96'
    end

    it 'should fail to initialize with a bad group size' do
      expect { SIRP::Client.new(1234) }.to raise_error(ArgumentError, 'must be a known group size')
    end

    it 'should calculate A from random a' do
      client = SIRP::Client.new(1024)
      aa1 = client.start_authentication
      expect(('%b' % aa1.to_i(16)).length).to be >= 1000

      client = SIRP::Client.new(1024)
      aa2 = client.start_authentication
      expect(('%b' % aa2.to_i(16)).length).to be >= 1000

      expect(aa1).not_to eq aa2
    end

    it 'should calculate A deterministicly from known @a' do
      client = SIRP::Client.new(1024)
      client.set_a(@a.to_i(16))
      aa = client.start_authentication
      expect(aa).to eq '165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2'
    end

    it 'should calculate client session (S) and secret (K)' do
      client = SIRP::Client.new(1024)
      client.set_a(@a.to_i(16))
      aa = client.start_authentication

      # Simulate server B
      bb = '56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510'
      mm = client.process_challenge(@username, @password, @salt, bb)

      # Client keys
      expect(client.S).to eq '8f3ba58c95e2e3b6b99eaed3e46c29f1fc44dbc47411ca24cd4e72998df90ccc8e54ad2c39f45a68d4c3aae2066aaf8f158205d34bc64b4a66623087de9a15f71b3023d5e7bc468a78f0f3b89d6b3ff6259aea0aef2ec0677df83901312305809de71cdf67e260a432d8c195c9a8e24452da2208691723a20fff571e8a5c7e31'
      expect(client.K).to eq 'fe9581d9df8120ab7af338e015a362049a822ad3'
    end

    it 'should verify true with matching server H_AMK' do
      server_HAMK = 'abc123'
      client = SIRP::Client.new(1024)
      client.set_h_amk('abc123')
      expect(client.verify(server_HAMK)).to be true
    end

    it 'should verify false with non-matching server H_AMK' do
      server_HAMK = 'bbaadd'
      client = SIRP::Client.new(1024)
      client.set_h_amk('abc123')
      expect(client.verify(server_HAMK)).to be false
    end
  end
end
