module SRP
  class Verifier
    attr_reader :N, :g, :k, :A, :B, :b, :S, :K, :M, :H_AMK

    def initialize(group = 2048)
      # select modulus (N) and generator (g)
      @N, @g = SRP.Ng group
      @k = SRP.calc_k(@N, @g)
    end

    # Initial user creation for the persistance layer.
    # Not part of the authentication process.
    # Returns { <username>, <password verifier>, <salt> }
    def generate_userauth(username, password)
      @salt ||= random_salt
      x = SRP.calc_x(username, password, @salt)
      v = SRP.calc_v(x, @N, @g)
      { username: username, verifier: format('%x', v), salt: @salt }
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
        proof: { A: xaa, B: @B, b: format('%x', @b), I: username, s: xsalt, v: xverifier }
      }
    end

    # returns H_AMK on success, false on failure
    # User -> Host:  M = H(H(N) xor H(g), H(I), s, A, B, K)
    # Host -> User:  H(A, M, K)
    def verify_session(proof, client_M)
      @A = proof[:A]
      @B = proof[:B]
      @b = proof[:b].to_i(16)
      username = proof[:I]
      xsalt = proof[:s]
      v = proof[:v].to_i(16)

      u = SRP.calc_u(@A, @B, @N)
      # SRP-6a safety check
      return false if u == 0

      # calculate session key
      @S = format('%x', SRP.calc_server_S(@A.to_i(16), @b, v, u, @N))
      @K = SRP.sha1_hex(@S)

      # calculate match
      @M = SRP.calc_M(@A, @B, @K)

      if @M == client_M
        # authentication succeeded
        @H_AMK = format('%x', SRP.calc_H_AMK(@A, @M, @K))
        return @H_AMK
      end

      return false
    end

    def random_salt
      format('%x', SRP.bigrand(10).hex)
    end

    def random_bignum
      SRP.bigrand(32).hex
    end

    # generates challenge
    # input verifier in hex
    def generate_B(xverifier)
      v = xverifier.to_i(16)
      @b ||= random_bignum
      @B = format('%x', SRP.calc_B(@b, k, v, @N, @g))
    end
  end
end
