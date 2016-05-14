# encoding: utf-8
require 'spec_helper'

describe SIRP do
  ### Test SRP functions.
  ### Values are from http://srp.stanford.edu/demo/demo.html
  ### using 256 bit values.
  ###
  context '@module-functions' do
    before :all do
      @N = '115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3'.to_i(16)
      @g = 2
      @username = 'user'
      @password = 'password'
      @salt = '16ccfa081895fe1ed0bb'
      @a = '7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2'.to_i(16)
      @b = '8143e2f299852a05717427ea9d87c6146e747d0da6e95f4390264e55a43ae96'.to_i(16)
    end

    it 'should calculate modular exponentiation correctly' do
      a = 2988348162058574136915891421498819466320163312926952423791023078876139
      b = 2351399303373464486466122544523690094744975233415544072992656881240319
      m = 10 ** 40
      c = SIRP.mod_exp(a, b, m)
      c.should == 1527229998585248450016808958343740453059
    end

    it 'should hash correctly with H()' do
      a = 2988348162058574136915891421498819466320163312926952423791023078876139
      b = 2351399303373464486466122544523690094744975233415544072992656881240319
      c = SIRP.H(Digest::SHA1, a, b)
      c.should == 870206349645559849154987479939336526106829135959
    end

    it 'should raise an error when h() is given invalid args' do
      expect { SIRP.H(Digest::SHA1, 1, '123456789abcdef') }.to raise_error(RuntimeError, 'Bit width does not match - client uses different prime')
    end

    it 'should calculate k' do
      k = SIRP.calc_k(@N, @g, Digest::SHA1)
      ('%x' % k).should == 'dbe5dfe0704fee4c85ff106ecd38117d33bcfe50'
      ('%b' % k).length.should == 160
    end

    it 'should calculate x' do
      x = SIRP.calc_x(@username, @password, @salt, Digest::SHA1)
      ('%x' % x).should == 'bdd0a4e1c9df4082684d8d358b8016301b025375'
      ('%b' % x).length.should == 160
    end

    it 'should calculate verifier' do
      x = 'bdd0a4e1c9df4082684d8d358b8016301b025375'.to_i(16)
      v = SIRP.calc_v(x, @N, @g)
      ('%x' % v).should == 'ce36e101ed8c37ed98ba4e441274dabd1062f3440763eb98bd6058e5400b6309'
      ('%b' % v).length.should == 256
    end

    it 'should calculate u' do
      aa = 'b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e'
      bb = 'fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68'
      u = SIRP.calc_u(aa, bb, @N, Digest::SHA1)
      ('%x' % u).should == 'c60b17ddf568dd5743d0e3ba5621646b742432c5'
      ('%b' % u).length.should == 160
    end

    it 'should calculate public client value A' do
      aa = SIRP.calc_A(@a, @N, @g)
      ('%x' % aa).should == 'b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e'
      ('%b' % aa).length.should == 256
    end

    it 'should calculate public server value B' do
      k = 'dbe5dfe0704fee4c85ff106ecd38117d33bcfe50'.to_i(16)
      v = 'ce36e101ed8c37ed98ba4e441274dabd1062f3440763eb98bd6058e5400b6309'.to_i(16)
      bb = SIRP.calc_B(@b, k, v, @N, @g)
      ('%x' % bb).should == 'fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68'
      ('%b' % bb).length.should == 256
    end

    it 'should calculate session key from client params' do
      bb = 'fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68'.to_i(16)
      k = 'dbe5dfe0704fee4c85ff106ecd38117d33bcfe50'.to_i(16)
      x = 'bdd0a4e1c9df4082684d8d358b8016301b025375'.to_i(16)
      u = 'c60b17ddf568dd5743d0e3ba5621646b742432c5'.to_i(16)
      a = @a
      ss = SIRP.calc_client_S(bb, a, k, x, u, @N, @g)
      ('%x' % ss).should == 'a606c182e364d2c15f9cdbeeeb63bb00c831d1da65eedc1414f21157d0312a5a'
      ('%b' % ss).length.should == 256
    end

    it 'should calculate session key from server params' do
      aa = 'b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e'.to_i(16)
      v = 'ce36e101ed8c37ed98ba4e441274dabd1062f3440763eb98bd6058e5400b6309'.to_i(16)
      u = 'c60b17ddf568dd5743d0e3ba5621646b742432c5'.to_i(16)
      b = @b
      ss = SIRP.calc_server_S(aa, b, v, u, @N)
      ('%x' % ss).should == 'a606c182e364d2c15f9cdbeeeb63bb00c831d1da65eedc1414f21157d0312a5a'
      ('%b' % ss).length.should == 256
    end

    it 'should calculate M' do
      xaa = 'b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e'
      xbb = 'fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68'
      xss = 'a606c182e364d2c15f9cdbeeeb63bb00c831d1da65eedc1414f21157d0312a5a'
      xkk = SIRP.sha_hex(xss, Digest::SHA1)
      xkk.should == '5844898ea6e5f5d9b737bc0ba2fb9d5edd3f8e67'
      mm = SIRP.calc_M(xaa, xbb, xkk, Digest::SHA1)
      mm.should == '0c6de5c7892a71bf971d733a511c44940e227941'
    end

    it 'should calculate H(AMK)' do
      xaa = 'b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e'
      xmm = 'd597503056af882d5b27b419302ac7b2ea9d7468'
      xkk = '5844898ea6e5f5d9b737bc0ba2fb9d5edd3f8e67'
      h_amk = SIRP.calc_H_AMK(xaa, xmm, xkk, Digest::SHA1)
      ('%x' % h_amk).should == '530fccc1c4aa82ae5c5cdfa8bdec987c6032451d'
    end
  end

  ### Test server-side Verifier.
  ### Values are from http://srp.stanford.edu/demo/demo.html
  ### using 1024 bit values.
  ###
  context '@verifier' do
    before :all do
      @username = 'user'
      @password = 'password'
      @salt = '16ccfa081895fe1ed0bb'
      @a = '7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2'
      @b = '8143e2f299852a05717427ea9d87c6146e747d0da6e95f4390264e55a43ae96'
    end

    it 'should calculate k' do
      k = SIRP::Verifier.new(1024).k
      k.should == '7556aa045aef2cdd07abaf0f665c3e818913186f'.to_i(16)
    end

    it 'should generate salt and verifier' do
      auth = SIRP::Verifier.new(1024).generate_userauth(@username, @password)
      auth[:username].should == @username
      auth[:verifier].should be
      auth[:salt].should be
    end

    it 'should calculate verifier with given salt' do
      verifier = SIRP::Verifier.new(1024)
      verifier.set_salt @salt
      auth = verifier.generate_userauth(@username, @password)
      v = auth[:verifier]
      salt = auth[:salt]
      salt.should == @salt
      v.should == '321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688'
    end

    it 'should generate salt and calculate verifier' do
      verifier = SIRP::Verifier.new(1024)
      auth = verifier.generate_userauth(@username, @password)
      v = auth[:verifier]
      salt = auth[:salt]
      ('%b' % v.to_i(16)).length.should >= 1000
      ('%b' % salt.to_i(16)).length.should >= 50
    end

    it 'should generate B with predefined b' do
      v = '321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688'
      verifier = SIRP::Verifier.new(1024)
      verifier.set_b @b.to_i(16)
      bb = verifier.generate_B(v)
      bb.should == '56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510'
    end

    it 'should generate B' do
      verifier = SIRP::Verifier.new(1024)
      bb = verifier.generate_B('0')
      ('%b' % bb.to_i(16)).length.should >= 1000
      ('%b' % verifier.b).length.should > 200
    end

    it 'should calculate server session and key' do
      # A is received in phase 1
      aa = '165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2'
      # B and b are saved from phase 1
      bb = '56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510'
      # v is from db
      v = '321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688'
      _proof = { A: aa, B: bb, b: @b, I: @username, s: @salt, v: v }
      verifier = SIRP::Verifier.new(1024)
      verifier.verify_session(_proof, 'match insignificant')
      ss = verifier.S
      ss.should == '7f44592cc616e0d761b2d3309d513b69b386c35f3ed9b11e6d43f15799b673d6dcfa4117b4456af978458d62ad61e1a37be625f46d2a5bd9a50aae359e4541275f0f4bd4b4caed9d2da224b491231f905d47abd9953179aa608854b84a0e0c6195e73715932b41ab8d0d4a2977e7642163be6802c5907fb9e233b8c96e457314'
      kk = verifier.K
      kk.should == '404bf923682abeeb3c8c9164d2cdb6b6ba21b64d'
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
      # K = H(S)
      kk = SIRP.sha_hex(ss, Digest::SHA1)
      client_M = 'b2c4a9a9cf40fb2db67bbab4ebe36a50223e51e9'
      _proof = { A: aa, B: bb, b: @b, I: @username, s: @salt, v: v }
      verifier = SIRP::Verifier.new(1024)
      verifier.verify_session(_proof, client_M)
      verifier.M.should == client_M
      verifier.H_AMK.should == 'a93d906ef5c0a15a8e525da6a271692d2e553c72'
    end
  end

  ###
  ### Test Client.
  ### Values are from http://srp.stanford.edu/demo/demo.html
  ### using 1024 bit values.
  ###
  context '@client' do
    before :all do
      @username = 'user'
      @password = 'password'
      @salt = '16ccfa081895fe1ed0bb'
      @a = '7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2'
      @b = '8143e2f299852a05717427ea9d87c6146e747d0da6e95f4390264e55a43ae96'
    end

    it 'should generate A from random a' do
      client = SIRP::Client.new(1024)
      aa1 = client.start_authentication
      ('%b' % aa1.to_i(16)).length.should >= 1000
      ('%b' % client.start_authentication.to_i(16)).length.should >= 200
      client = SIRP::Client.new(1024)
      aa2 = client.start_authentication
      ('%b' % aa2.to_i(16)).length.should >= 1000
      ('%b' % client.start_authentication.to_i(16)).length.should >= 200
      aa1.should_not == aa2
    end

    it 'should calculate A' do
      client = SIRP::Client.new(1024)
      client.set_a @a.to_i(16)
      aa = client.start_authentication
      aa.should == '165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2'
    end

    it 'should calculate client session and key' do
      client = SIRP::Client.new(1024)
      client.set_a @a.to_i(16)
      aa = client.start_authentication # created in phase 1
      bb = '56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510'
      mm = client.process_challenge(@username, @password, @salt, bb)
      ss = client.S
      ss.should == '7f44592cc616e0d761b2d3309d513b69b386c35f3ed9b11e6d43f15799b673d6dcfa4117b4456af978458d62ad61e1a37be625f46d2a5bd9a50aae359e4541275f0f4bd4b4caed9d2da224b491231f905d47abd9953179aa608854b84a0e0c6195e73715932b41ab8d0d4a2977e7642163be6802c5907fb9e233b8c96e457314'
      kk = client.K
      kk.should == '404bf923682abeeb3c8c9164d2cdb6b6ba21b64d'
    end
  end

  ### Simulate actual authentication scenario over HTTP
  ### when the server is RESTful and has to persist authentication
  ### state between challenge and response.
  ###
  context '@authentication' do
    before :all do
      @username = 'leonardo'
      password = 'icnivad'
      @auth = SIRP::Verifier.new(1024).generate_userauth(@username, password)

      # imitate database persistance layer
      @db = {
        @username => {
          verifier: @auth[:verifier],
          salt: @auth[:salt]
        }
      }
    end

    it 'should authenticate' do
      client = SIRP::Client.new(1024)
      verifier = SIRP::Verifier.new(1024)
      # phase 1
      # (client)
      aa = client.start_authentication
      # (server)
      v = @auth[:verifier]
      salt = @auth[:salt]
      bb = verifier.generate_B v
      b = '%x' % verifier.b
      # phase 2
      # (client)
      client_M = client.process_challenge(@username, 'icnivad', salt, bb)
      # (server)
      _proof = { A: aa, B: bb, b: b, I: @username, s: salt, v: v }
      server_H_AMK = verifier.verify_session(_proof, client_M)
      server_H_AMK.should be
      # (client)
      client.H_AMK.should == server_H_AMK
    end

    it 'should not authenticate' do
      client = SIRP::Client.new(1024)
      verifier = SIRP::Verifier.new(1024)
      # phase 1
      # (client)
      aa = client.start_authentication
      # (server)
      v = @auth[:verifier]
      salt = @auth[:salt]
      bb = verifier.generate_B v
      b = '%x' % verifier.b
      # phase 2
      # (client)
      client_M = client.process_challenge(@username, 'wrong password', salt, bb)
      # (server)
      _proof = { A: aa, B: bb, b: b, I: @username, s: salt, v: v }
      verifier.verify_session(_proof, client_M).should == false
      verifier.H_AMK.should_not be
    end

    it 'should be applied in async authentication with stateless server' do
      username = @username

      # client generates A and begins authentication process
      client = SIRP::Client.new(1024)
      aa = client.start_authentication

      #
      # username and A are received  (client --> server)
      #

      # server finds user from "database"
      _user = @db[username]
      _user.should_not be_nil
      v = _user[:verifier]
      salt = _user[:salt]

      # server generates B, saves A and B to database
      verifier = SIRP::Verifier.new(1024)
      _session = verifier.get_challenge_and_proof username, v, salt, aa
      _session[:challenge][:B].should == verifier.B
      _session[:challenge][:salt].should == salt
      # store proof to memory
      _user[:session_proof] = _session[:proof]
      # clear variables to simulate end of phase 1
      verifier = username = v = bb = salt = nil
      # server sends salt and B
      client_response = _session[:challenge]

      # client receives B and salt  (server --> client)
      #
      bb = client_response[:B]
      salt = client_response[:salt]
      # client generates session key
      # at this point _client_srp.a should be persisted!! calculate_client_key is stateful!
      mmc = client.process_challenge @username, 'icnivad', salt, bb
      client.A.should be
      client.M.should == mmc
      client.K.should be
      client.H_AMK.should be
      # client sends M --> server
      client_M = client.M

      #
      # server receives client session key  (client --> server)
      #
      username = @username
      _user = @db[username]
      # retrive session from database
      proof = _user[:session_proof]
      verifier = SIRP::Verifier.new(1024)
      verification = verifier.verify_session(proof, client_M)
      verification.should_not == false

      # Now the two parties have a shared, strong session key K.
      # To complete authentication, they need to prove to each other that their keys match.

      client.verify(verification).should == true
      verification.should == client.H_AMK
    end
  end
end
