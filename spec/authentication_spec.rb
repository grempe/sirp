# encoding: utf-8
require 'spec_helper'

describe SIRP do
  # Simulate actual authentication scenario over HTTP
  # when the server is RESTful and has to persist authentication
  # state between challenge and response.
  #
  context 'simulated authentication' do
    before :all do
      @username = 'leonardo'
      password = 'icnivad'
      @auth = SIRP::Verifier.new(1024).generate_userauth(@username, password)

      # Simulate database persistance layer
      @db = {
        @username => {
          verifier: @auth[:verifier],
          salt: @auth[:salt]
        }
      }
    end

    it 'should authenticate with matching server and client params' do
      client = SIRP::Client.new(1024)
      verifier = SIRP::Verifier.new(1024)

      # phase 1 (client)
      aa = client.start_authentication

      # phaase 1 (server)
      v = @auth[:verifier]
      salt = @auth[:salt]

      cp = verifier.get_challenge_and_proof(@username, v, salt, aa)

      # phase 2 (client)
      client_M = client.process_challenge(@username, 'icnivad', salt, cp[:proof][:B])

      # phase 2 (server)
      proof = { A: aa, B: cp[:proof][:B], b: cp[:proof][:b], I: @username, s: salt, v: v }
      server_H_AMK = verifier.verify_session(proof, client_M)
      expect(server_H_AMK).to be_truthy

      # phase 2 (client)
      expect(client.verify(server_H_AMK)).to be true
    end

    it 'should not authenticate when a bad password is injected in the flow' do
      client = SIRP::Client.new(1024)
      verifier = SIRP::Verifier.new(1024)

      # phase 1 (client)
      aa = client.start_authentication

      # phaase 1 (server)
      v = @auth[:verifier]
      salt = @auth[:salt]
      cp = verifier.get_challenge_and_proof(@username, v, salt, aa)

      # phase 2 (client)
      client_M = client.process_challenge(@username, 'BAD PASSWORD', salt, cp[:proof][:B])

      # phase 2 (server)
      proof = { A: aa, B: cp[:proof][:B], b: cp[:proof][:b], I: @username, s: salt, v: v }
      server_H_AMK = verifier.verify_session(proof, client_M)
      expect(server_H_AMK).to be nil

      # phase 2 (client)
      expect(client.verify(server_H_AMK)).to be false
    end

    it 'should authenticate when simulating a stateless server' do
      username = @username

      # START PHASE 1

      # P1 : client generates A and begins auth
      client = SIRP::Client.new(1024)
      aa = client.start_authentication

      # P1 : username and A are sent (client -> server)

      # P1 : server finds user in DB
      _user = @db[username]
      expect(_user).not_to be_nil
      v = _user[:verifier]
      salt = _user[:salt]

      # P1 : server generates B, saves A and B to DB
      verifier = SIRP::Verifier.new(1024)
      _session = verifier.get_challenge_and_proof(username, v, salt, aa)
      expect(_session[:challenge][:B]).to eq verifier.B
      expect(_session[:challenge][:salt]).to eq salt

      # P1 : store proof to memory
      _user[:session_proof] = _session[:proof]

      # P1 : clear variables to simulate end of phase 1
      verifier = username = v = bb = salt = nil

      # P1 : server sends salt and B to client
      client_response = _session[:challenge]

      # P1 : client receives B and salt (server -> client)
      bb = client_response[:B]
      salt = client_response[:salt]

      # START PHASE 2

      # P2 : client generates session key
      #      at this point _client_srp.a should be persisted!
      #      calculate_client_key is stateful!
      mmc = client.process_challenge(@username, 'icnivad', salt, bb)
      expect(client.A).to be_truthy
      expect(client.M).to eq mmc
      expect(client.K).to be_truthy
      expect(client.H_AMK).to be_truthy

      # P2 : client sends username and M -> server
      client_M = client.M

      # P2 : server receives client M (client -> server)
      _user = @db[@username]

      # P2 : server retrives session from DB
      proof = _user[:session_proof]
      verifier = SIRP::Verifier.new(1024)
      server_H_AMK = verifier.verify_session(proof, client_M)
      expect(server_H_AMK).to be_truthy

      # Now the two parties have a shared, strong session key K.
      # To complete authentication, they need to prove to each other that
      # their keys match.

      expect(client.verify(server_H_AMK)).to be true
      expect(client.K).to eq verifier.K
    end
  end
end
