module SRP
  class Client
    attr_reader :N, :g, :k, :a, :A, :S, :K, :M, :H_AMK

    def initialize(group = 2048)
      # select modulus (N) and generator (g)
      @N, @g = SRP.Ng group
      @k = SRP.calc_k(@N, @g)
    end

    def start_authentication
      generate_A
    end

    # Process initiated authentication challenge.
    # Returns M if authentication is successful, false otherwise.
    # Salt and B should be given in hex.
    def process_challenge(username, password, xsalt, xbb)
      bb = xbb.to_i(16)
      # SRP-6a safety check
      return false if (bb % @N) == 0

      x = SRP.calc_x(username, password, xsalt)
      u = SRP.calc_u(@A, xbb, @N)

      # SRP-6a safety check
      return false if u == 0

      # calculate session key
      @S = format('%x', SRP.calc_client_S(bb, @a, @k, x, u, @N, @g))
      @K = SRP.sha1_hex(@S)

      # calculate match
      @M = format('%x', SRP.calc_M(username, xsalt, @A, xbb, @K, @N, @g))

      # calculate verifier
      @H_AMK = format('%x', SRP.calc_H_AMK(@A, @M, @K, @N, @g))

      @M
    end

    def verify(server_HAMK)
      return false unless @H_AMK
      @H_AMK == server_HAMK
    end

    def random_bignum
      SRP.bigrand(32).hex
    end

    def generate_A
      @a ||= random_bignum
      @A = format('%x', SRP.calc_A(@a, @N, @g))
    end
  end
end
