module SIRP
  class Verifier
    attr_reader :N, :g, :k, :A, :B, :b, :S, :K, :M, :H_AMK, :hash

    def initialize(group = 2048)
      # select modulus (N) and generator (g)
      @N, @g, @hash = SIRP.Ng(group)
      @k = SIRP.calc_k(@N, @g, hash)
    end

    # Initial user creation for the persistance layer.
    # Not part of the authentication process.
    # Returns { <username>, <password verifier>, <salt> }
    def generate_userauth(username, password)
      @salt ||= SecureRandom.hex(10)
      x = SIRP.calc_x(username, password, @salt, hash)
      v = SIRP.calc_v(x, @N, @g)
      { username: username, verifier: SIRP.num_to_hex(v), salt: @salt }
    end

    # Authentication phase 1 - create challenge.
    # Returns Hash with challenge for client and proof to be stored on server.
    # Parameters should be given in hex.
    def get_challenge_and_proof(username, xverifier, xsalt, xaa)
      # SRP-6a safety check
      return false if (xaa.to_i(16) % @N) == 0
      generate_B(xverifier)

      {
        challenge: { B: @B, salt: xsalt },
        proof: { A: xaa, B: @B, b: SIRP.num_to_hex(@b), I: username, s: xsalt, v: xverifier }
      }
    end

    # returns H_AMK on success, false on failure
    # User -> Host:  M = H(H(N) xor H(g), H(I), s, A, B, K)
    # Host -> User:  H(A, M, K)
    def verify_session(proof, client_M)
      @A = proof[:A]
      @B = proof[:B]
      @b = proof[:b].to_i(16)
      v = proof[:v].to_i(16)

      u = SIRP.calc_u(@A, @B, @N, hash)

      # SRP-6a safety check
      return false if u == 0

      # calculate session key
      @S = SIRP.num_to_hex(SIRP.calc_server_S(@A.to_i(16), @b, v, u, @N))
      @K = SIRP.sha_hex(@S, hash)

      # calculate match
      @M = SIRP.calc_M(@A, @B, @K, hash)

      if @M == client_M
        # authentication succeeded
        @H_AMK = SIRP.num_to_hex(SIRP.calc_H_AMK(@A, @M, @K, hash))
      else
        false
      end
    end

    # generates challenge
    # input verifier in hex
    def generate_B(xverifier)
      v = xverifier.to_i(16)
      @b ||= SecureRandom.hex(32).hex
      @B = SIRP.num_to_hex(SIRP.calc_B(@b, k, v, @N, @g))
    end
  end
end
