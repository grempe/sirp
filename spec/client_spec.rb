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
      expect(client.S).to eq '7f44592cc616e0d761b2d3309d513b69b386c35f3ed9b11e6d43f15799b673d6dcfa4117b4456af978458d62ad61e1a37be625f46d2a5bd9a50aae359e4541275f0f4bd4b4caed9d2da224b491231f905d47abd9953179aa608854b84a0e0c6195e73715932b41ab8d0d4a2977e7642163be6802c5907fb9e233b8c96e457314'
      expect(client.K).to eq '404bf923682abeeb3c8c9164d2cdb6b6ba21b64d'
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
