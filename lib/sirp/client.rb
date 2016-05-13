module SIRP
  class Client
    attr_reader :N, :g, :k, :a, :A, :S, :K, :M, :H_AMK, :hash

    def initialize(group = 2048)
      # select modulus (N) and generator (g)
      @N, @g, @hash = SIRP.Ng(group)
      @k = SIRP.calc_k(@N, @g, hash)
    end

    def start_authentication
      # Generate a/A private and public components
      @a ||= SecureRandom.hex(32).hex
      @A = SIRP.num_to_hex(SIRP.calc_A(@a, @N, @g))
    end

    # Process initiated authentication challenge.
    # Returns M if authentication is successful, false otherwise.
    # Salt and B should be given in hex.
    def process_challenge(username, password, xsalt, xbb)
      bb = xbb.to_i(16)

      # SRP-6a safety check
      return false if (bb % @N) == 0

      x = SIRP.calc_x(username, password, xsalt, hash)
      u = SIRP.calc_u(@A, xbb, @N, hash)

      # SRP-6a safety check
      return false if u == 0

      # calculate session key
      @S = SIRP.num_to_hex(SIRP.calc_client_S(bb, @a, @k, x, u, @N, @g))
      @K = SIRP.sha_hex(@S, hash)

      # calculate match
      @M = SIRP.calc_M(@A, xbb, @K, hash)

      # calculate verifier
      @H_AMK = SIRP.num_to_hex(SIRP.calc_H_AMK(@A, @M, @K, hash))

      @M
    end

    def verify(server_HAMK)
      return false unless @H_AMK
      @H_AMK == server_HAMK
    end
  end
end
