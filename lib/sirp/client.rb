module SIRP
  class Client
    include SIRP
    attr_reader :N, :g, :k, :a, :A, :S, :K, :M, :H_AMK, :hash

    # @param group [Integer] the group size in bits
    def initialize(group = 2048)
      # select modulus (N) and generator (g)
      @N, @g, @hash = Ng(group)
      @k = calc_k(@N, @g, hash)
    end

    # Phase 1 : Start the authentication process by generating the 'A' value
    # and send it, along with the username, to the server.
    #
    # @return [String] the value of 'A' in hex
    def start_authentication
      # Generate a/A private and public components
      @a ||= SecureRandom.hex(32).hex
      @A = num_to_hex(calc_A(@a, @N, @g))
    end

    # Phase 1 : Process the salt and B value provided by the server.
    #
    # @param username [String] the client provided authentication username
    # @param password [String] the client provided authentication password
    # @param xsalt [String] the server provided salt for the username in hex
    # @param xbb [String] the server verifier 'B' value in hex
    # @return [String] the client 'M' value in hex
    def process_challenge(username, password, xsalt, xbb)
      bb = xbb.to_i(16)

      # SRP-6a safety check
      return false if (bb % @N).zero?

      x = calc_x(username, password, xsalt, hash)
      u = calc_u(@A, xbb, @N, hash)

      # SRP-6a safety check
      return false if u.zero?

      # calculate session key
      @S = num_to_hex(calc_client_S(bb, @a, @k, x, u, @N, @g))
      @K = sha_hex(@S, hash)

      # calculate match
      @M = calc_M(@A, xbb, @K, hash)

      # calculate verifier
      @H_AMK = num_to_hex(calc_H_AMK(@A, @M, @K, hash))

      @M
    end

    # Phase 2 : Verify that the server provided H(A,M,K) value matches
    # the client generated version. This is the last step of mutual
    # authentication and confirms that the client and server have
    # completed the auth process.
    #
    # @param server_HAMK [String] the server provided H_AMK in hex
    # @return [true,false] returns true if the server and client agree on the
    #   H_AMK value, false if not
    def verify(server_HAMK)
      return false unless @H_AMK
      # Secure constant time comparison, hash the params to ensure
      # that both strings being compared are equal length 32 Byte strings.
      secure_compare(Digest::SHA256.hexdigest(@H_AMK), Digest::SHA256.hexdigest(server_HAMK))
    end
  end
end
