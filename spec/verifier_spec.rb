# encoding: utf-8
require 'spec_helper'

# From http://srp.stanford.edu/demo/demo.html using 1024 bit SHA1 values.
describe SIRP do
  before :all do
    @username = 'user'
    @password = 'password'
    @salt = '01ebb2496e4e8d32e6f7967ee9fec64e'
    @a = '7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2'
    @b = '8143e2f299852a05717427ea9d87c6146e747d0da6e95f4390264e55a43ae96'
  end

  context 'initialize' do
    it 'should fail to initialize with a bad group size' do
      expect { SIRP::Verifier.new(1234) }.to raise_error(ArgumentError, 'must be a known group size')
    end

    it 'should calculate k' do
      k = SIRP::Verifier.new(1024).k
      expect(k).to eq '7556aa045aef2cdd07abaf0f665c3e818913186f'.to_i(16)
    end
  end

  context 'generate_userauth' do
    it 'should ' do
      auth = SIRP::Verifier.new(1024).generate_userauth(@username, @password)
      expect(auth[:username]).to eq @username
      expect(auth[:verifier]).to be_truthy
      expect([:salt]).to be_truthy
    end

    it 'should calculate verifier with given salt' do
      verifier = SIRP::Verifier.new(1024)
      verifier.set_salt(@salt)
      auth = verifier.generate_userauth(@username, @password)
      v = auth[:verifier]
      salt = auth[:salt]
      expect(salt).to eq @salt
      expect(v).to eq '4bff0d5c5a5d587c585df736aa50802a347b645a90799c254c166a380d367e34291ddbecc88ab54148d032359c44cd43eb2f85b0eaa545aa54de834b91a0cfceab853189efac6327b1b48095c8aeb17acc1b0b582a56ae2f7a229d2cf60378455dc3082f5283c887c1047f5460016c46a632ae0dac8d934d3a9a7fe5221bd02b'
    end

    it 'should generate salt and calculate verifier' do
      verifier = SIRP::Verifier.new(1024)
      auth = verifier.generate_userauth(@username, @password)
      v = auth[:verifier]
      salt = auth[:salt]
      expect(('%b' % v.to_i(16)).length).to be >= 1000
      expect(('%b' % salt.to_i(16)).length).to be >= 50
    end
  end

  context 'get_challenge_and_proof' do
    it 'SRP6a Safety : should return false if A % N == 0' do
      verifier = SIRP::Verifier.new(1024)
      @auth = verifier.generate_userauth('foo', 'bar')
      nn = verifier.N
      verifier.set_aa(nn.to_s(16))
      expect(verifier.get_challenge_and_proof(@username, @auth[:verifier], @auth[:salt], verifier.A)).to be false
    end

    it 'should return expected results' do
      verifier = SIRP::Verifier.new(1024)
      @auth = verifier.generate_userauth('foo', 'bar')
      cp = verifier.get_challenge_and_proof(@username, @auth[:verifier], @auth[:salt], @auth[:verifier])
      expect(cp).to be_a Hash
      expect(cp.key?(:challenge)).to be true
      expect(cp[:challenge].key?(:B)).to be true
      expect(cp[:challenge].key?(:salt)).to be true
      expect(cp.key?(:proof)).to be true
      expect(cp[:proof].key?(:A)).to be true
      expect(cp[:proof].key?(:B)).to be true
      expect(cp[:proof].key?(:b)).to be true
      expect(cp[:proof].key?(:I)).to be true
      expect(cp[:proof].key?(:s)).to be true
      expect(cp[:proof].key?(:v)).to be true
    end

    it 'should generate expected B with predefined b' do
      v = '321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688'
      verifier = SIRP::Verifier.new(1024)
      @auth = verifier.generate_userauth('foo', 'bar')
      verifier.set_b(@b.to_i(16))
      cp = verifier.get_challenge_and_proof(@username, v, @auth[:salt], @auth[:verifier])
      expect(('%b' % cp[:proof][:b].to_i(16)).length).to be > 200
      expect(('%b' % cp[:challenge][:B].to_i(16)).length).to be >= 1000
      expect(cp[:challenge][:B]).to eq '56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510'
    end
  end

  context 'verify_session' do
    it 'should calculate server session and key' do
      # A is received in phase 1
      aa = '165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2'
      # B and b are saved from phase 1
      bb = '56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510'
      # v is from db
      v = '321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688'
      _proof = { A: aa, B: bb, b: @b, I: @username, s: @salt, v: v }
      verifier = SIRP::Verifier.new(1024)
      verifier.verify_session(_proof, 'abc123')
      expect(verifier.S).to eq '7f44592cc616e0d761b2d3309d513b69b386c35f3ed9b11e6d43f15799b673d6dcfa4117b4456af978458d62ad61e1a37be625f46d2a5bd9a50aae359e4541275f0f4bd4b4caed9d2da224b491231f905d47abd9953179aa608854b84a0e0c6195e73715932b41ab8d0d4a2977e7642163be6802c5907fb9e233b8c96e457314'
      expect(verifier.K).to eq '404bf923682abeeb3c8c9164d2cdb6b6ba21b64d'
    end

    it 'should calculate verifier M and server proof' do
      # A is received in phase 1
      aa = '165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2'
      # B and b are saved from phase 1
      bb = '56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510'
      # v is from db
      v = '321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688'
      # S is validated
      ss = '7f44592cc616e0d761b2d3309d513b69b386c35f3ed9b11e6d43f15799b673d6dcfa4117b4456af978458d62ad61e1a37be625f46d2a5bd9a50aae359e4541275f0f4bd4b4caed9d2da224b491231f905d47abd9953179aa608854b84a0e0c6195e73715932b41ab8d0d4a2977e7642163be6802c5907fb9e233b8c96e457314'

      client_M = 'b2c4a9a9cf40fb2db67bbab4ebe36a50223e51e9'
      _proof = { A: aa, B: bb, b: @b, I: @username, s: @salt, v: v }

      verifier = SIRP::Verifier.new(1024)
      verifier.verify_session(_proof, client_M)
      expect(verifier.M).to eq client_M
      expect(verifier.S).to eq ss
      expect(verifier.H_AMK).to eq 'a93d906ef5c0a15a8e525da6a271692d2e553c72'
    end
  end
end
