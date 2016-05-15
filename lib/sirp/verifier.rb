module SIRP
  class Verifier
    include SIRP
    attr_reader :N, :g, :k, :A, :B, :b, :S, :K, :M, :H_AMK, :hash

    def initialize(group = 2048)
      # select modulus (N) and generator (g)
      @N, @g, @hash = Ng(group)
      @k = calc_k(@N, @g, hash)
    end

    # Phase 0 ; Generate a verifier and salt client-side. This should be
    # used during the initial user registration process. All three values
    # should be provided as attributes in the user registration process. The
    # verifier and salt should be persisted server-side. The verifier
    # should be protected and never made public or returned to the user.
    # The salt should be returned to the user to start Phase 1 of the
    # authentication process.
    #
    # @param username [String] the authentication username
    # @param password [String] the authentication password
    # @return [Hash] a Hash of the username, verifier, and salt
    def generate_userauth(username, password)
      @salt ||= SecureRandom.hex(10)
      x = calc_x(username, password, @salt, hash)
      v = calc_v(x, @N, @g)
      { username: username, verifier: num_to_hex(v), salt: @salt }
    end

    # Phase 1 - Create a challenge for the client, and a proof to be stored
    # on the server for later use when verifying the client response.
    #
    # @param username [String] the client provided authentication username
    # @param xverifier [String] the server stored verifier for the username in hex
    # @param xsalt [String] the server stored salt for the username in hex
    # @param xaa [String] the client provided 'A' value in hex
    # @return [Hash] a Hash with the challenge for the client and a proof for the server
    def get_challenge_and_proof(username, xverifier, xsalt, xaa)
      # SRP-6a safety check
      return false if (xaa.to_i(16) % @N).zero?

      generate_B(xverifier)

      {
        challenge: { B: @B, salt: xsalt },
        proof: { A: xaa, B: @B, b: num_to_hex(@b), I: username, s: xsalt, v: xverifier }
      }
    end

    # Phase 2 - Use the server stored proof and the client provided 'M' value.
    # Calculates a server 'M' value and compares it to the client provided one,
    # and if they match the client and server have negotiated equal secrets.
    # Returns a H(A, M, K) value on success and false on failure.
    #
    # Sets the @K value, which is the client and server negotiated secret key
    # if verification succeeds. This can be used to derive strong encryption keys
    # for later use. The client independently calculates the same @K value as well.
    #
    # If authentication fails the H_AMK value must not be provided to the client.
    #
    # @param proof [Hash] the server stored proof Hash with keys A, B, b, I, s, v
    # @param client_M [String] the client provided 'M' value in hex
    # @return [String, false] the H_AMK value in hex for the client, or false if verification failed
    def verify_session(proof, client_M)
      @A = proof[:A]
      @B = proof[:B]
      @b = proof[:b].to_i(16)
      v = proof[:v].to_i(16)

      u = calc_u(@A, @B, @N, hash)

      # SRP-6a safety check
      return false if u.zero?

      # calculate session key
      @S = num_to_hex(calc_server_S(@A.to_i(16), @b, v, u, @N))
      @K = sha_hex(@S, hash)

      # calculate match
      @M = calc_M(@A, @B, @K, hash)

      # Secure constant time comparison, hash the params to ensure
      # that both strings being compared are equal length 32 Byte strings.
      if secure_compare(Digest::SHA256.hexdigest(@M), Digest::SHA256.hexdigest(client_M))
        # authentication succeeded
        @H_AMK = num_to_hex(calc_H_AMK(@A, @M, @K, hash))
      else
        false
      end
    end

    # @param xverifier [String] the server stored verifier for the username in hex
    # @return [String] the B value in hex
    def generate_B(xverifier)
      v = xverifier.to_i(16)
      @b ||= SecureRandom.hex(32).hex
      @B = num_to_hex(calc_B(@b, k, v, @N, @g))
    end
  end
end
