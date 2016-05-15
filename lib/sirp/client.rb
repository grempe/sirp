module SIRP
  class Client
    include SIRP
    attr_reader :N, :g, :k, :a, :A, :S, :K, :M, :H_AMK, :hash

    # Select modulus (N), generator (g), and one-way hash function (SHA1 or SHA256)
    #
    # @param group [Integer] the group size in bits
    def initialize(group = 2048)
      @N, @g, @hash = Ng(group)
      @k = calc_k(@N, @g, hash)
    end

    # Phase 1 : Step 1 : Start the authentication process by generating the
    # client 'a' and 'A' values. Public 'A' should later be sent along with
    # the username, to the server verifier to continue the auth process. The
    # internal secret 'a' value should remain private.
    #
    # @return [String] the value of 'A' in hex
    def start_authentication
      @a ||= SecureRandom.hex(32).hex
      @A = num_to_hex(calc_A(@a, @N, @g))
    end

    #
    # Phase 1 : Step 2 : See Verifier#get_challenge_and_proof(username, xverifier, xsalt, xaa)
    #

    # Phase 2 : Step 1 : Process the salt and B values provided by the server.
    #
    # @param username [String] the client provided authentication username
    # @param password [String] the client provided authentication password
    # @param xsalt [String] the server provided salt for the username in hex
    # @param xbb [String] the server verifier 'B' value in hex
    # @return [String] the client 'M' value in hex
    def process_challenge(username, password, xsalt, xbb)
      # Convert the 'B' hex value to an Integer
      bb = xbb.to_i(16)

      # SRP-6a safety check
      return false if (bb % @N).zero?

      x = calc_x(username, password, xsalt, hash)
      u = calc_u(@A, xbb, @N, hash)

      # SRP-6a safety check
      return false if u.zero?

      # Calculate session key 'S' and secret key 'K'
      @S = num_to_hex(calc_client_S(bb, @a, @k, x, u, @N, @g))
      @K = sha_hex(@S, hash)

      # Calculate the 'M' matcher
      @M = calc_M(@A, xbb, @K, hash)

      # Calculate the H(A,M,K) verifier
      @H_AMK = num_to_hex(calc_H_AMK(@A, @M, @K, hash))

      # Return the 'M' matcher to be sent to the server
      @M
    end

    #
    # Phase 2 : Step 2 : See Verifier#verify_session(proof, client_M)
    #

    # Phase 2 : Step 3 : Verify that the server provided H(A,M,K) value
    # matches the client generated version. This is the last step of mutual
    # authentication and confirms that the client and server have
    # completed the auth process. The comparison of local and server
    # H_AMK values is done using a secure constant-time comparison
    # method so as not to leak information.
    #
    # @param server_HAMK [String] the server provided H_AMK in hex
    # @return [true,false] returns true if the server and client agree on the H_AMK value, false if not
    def verify(server_HAMK)
      return false unless @H_AMK && server_HAMK
      # Hash the comparison params to ensure that both strings
      # being compared are equal length 32 Byte strings.
      secure_compare(Digest::SHA256.hexdigest(@H_AMK), Digest::SHA256.hexdigest(server_HAMK))
    end
  end
end
