module SIRP
  class Client
    include Contracts::Core
    include Contracts::Builtin
    include SIRP

    attr_reader :N       # Bignum
    attr_reader :g       # Fixnum
    attr_reader :k       # Bignum
    attr_reader :a       # Bignum
    attr_reader :A       # String (hex)
    attr_reader :S       # String (hex)
    attr_reader :K       # String (hex)
    attr_reader :M       # String (hex)
    attr_reader :H_AMK   # String (hex)
    attr_reader :hash    # Digest::SHA1 || Digest::SHA256

    # Select modulus (N), generator (g), and one-way hash function (SHA1 or SHA256)
    #
    # @param group [Fixnum] the group size in bits
    Contract Nat => Nat
    def initialize(group = 2048)
      raise ArgumentError, 'must be a known group size' unless [1024, 1536, 2048, 3072, 4096, 6144, 8192].include?(group)

      @N, @g, @hash = Ng(group)
      @k = calc_k(@N, @g, hash)
    end

    # Phase 1 : Step 1 : Start the authentication process by generating the
    # client 'a' and 'A' values. Public 'A' should later be sent along with
    # the username, to the server verifier to continue the auth process. The
    # internal secret 'a' value should remain private.
    #
    # @return [String] the value of 'A' in hex
    Contract None => String
    def start_authentication
      @a ||= RbNaCl::Util.bin2hex(RbNaCl::Random.random_bytes(32)).hex
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
    Contract String, String, String, String => String
    def process_challenge(username, password, xsalt, xbb)
      raise ArgumentError, 'username must not be an empty string' if username.empty?
      raise ArgumentError, 'password must not be an empty string' if password.empty?
      raise ArgumentError, 'xsalt must be a hex string' unless xsalt =~ /^[a-fA-F0-9]+$/
      raise ArgumentError, 'xbb must be a hex string' unless xbb =~ /^[a-fA-F0-9]+$/

      # Convert the 'B' hex value to an Integer
      bb = xbb.to_i(16)

      raise 'SRP-6a Safety Check : B % N cannot equal 0' if (bb % @N).zero?

      x = calc_x(username, password, xsalt)
      u = calc_u(@A, xbb, hash)

      raise 'SRP-6a Safety Check : u cannot equal 0' if u.zero?

      # Calculate session key 'S' and secret key 'K'
      @S = num_to_hex(calc_client_S(bb, @a, @k, x, u, @N, @g))
      @K = hash.hexdigest([@S].pack('H*'))

      # Calculate the 'M' matcher
      @M = calc_M(@A, xbb, @K, hash)

      # Calculate the H(A,M,K) verifier
      @H_AMK = calc_H_AMK(@A, @M, @K, hash)

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
    Contract String => Bool
    def verify(server_HAMK)
      return false unless @H_AMK
      return false unless server_HAMK =~ /^[a-fA-F0-9]+$/
      secure_compare(@H_AMK, server_HAMK)
    end
  end
end
