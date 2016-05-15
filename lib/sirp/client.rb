module SIRP
  class Client
    include SIRP
    attr_reader :N, :g, :k, :a, :A, :S, :K, :M, :H_AMK, :hash

    def initialize(group = 2048)
      # select modulus (N) and generator (g)
      @N, @g, @hash = Ng(group)
      @k = calc_k(@N, @g, hash)
    end

    def start_authentication
      # Generate a/A private and public components
      @a ||= SecureRandom.hex(32).hex
      @A = num_to_hex(calc_A(@a, @N, @g))
    end

    # Process initiated authentication challenge.
    # Returns M if authentication is successful, false otherwise.
    # Salt and B should be given in hex.
    def process_challenge(username, password, xsalt, xbb)
      bb = xbb.to_i(16)

      # SRP-6a safety check
      return false if (bb % @N) == 0

      x = calc_x(username, password, xsalt, hash)
      u = calc_u(@A, xbb, @N, hash)

      # SRP-6a safety check
      return false if u == 0

      # calculate session key
      @S = num_to_hex(calc_client_S(bb, @a, @k, x, u, @N, @g))
      @K = sha_hex(@S, hash)

      # calculate match
      @M = calc_M(@A, xbb, @K, hash)

      # calculate verifier
      @H_AMK = num_to_hex(calc_H_AMK(@A, @M, @K, hash))

      @M
    end

    def verify(server_HAMK)
      return false unless @H_AMK
      # Secure constant time comparison, hash the params to ensure
      # that both strings being compared are equal length 32 Byte strings.
      secure_compare(Digest::SHA256.hexdigest(@H_AMK), Digest::SHA256.hexdigest(server_HAMK))
    end
  end
end
