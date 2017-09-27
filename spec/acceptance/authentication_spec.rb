RSpec.describe SIRP do
  # Simulate actual authentication scenario over HTTP
  # when the server is RESTful and has to persist authentication
  # state between challenge and response.
  #
  context 'simulated authentication' do
    let(:username) { 'leonardo' }
    let(:password) { 'icnivad' }

    context 'when all params matches' do
      it 'should authenticate' do
        # Phase 0: Generate a verifier and salt
        register = SIRP::Register.new(username, password)
        user = register.credentials # This values should be persisted (in DB)

        # Phase 1: Step 1: Start the authentication process by generating the
        # client 'a' and 'A' values.
        client = SIRP::Client.new
        aa = client.start

        # Phase 1: Step 2: Create a challenge for the client, and a proof to be stored
        # on the server for later use when verifying the client response.
        server_start = SIRP::Server::Start.new(user, aa)
        challenge = server_start.challenge
        proof = server_start.proof

        # Phase 2: Step 1: Process the salt and B values provided by the server.
        matcher = client.authenticate(username, password, challenge)

        # Phase 2: Step 2: Use the server stored proof and the client provided 'M' value.
        server_finish = SIRP::Server::Finish.new(proof, matcher)
        expect(server_finish.success?).to be(true)

        # Phase 2: Step 3: Verify that the server provided H(A,M,K) value
        # matches the client generated version.
        server_HAMK = server_finish.match
        expect(client.verify(server_HAMK)).to be(true)
      end
    end

    context 'when params does not match' do

    end
  end
end
