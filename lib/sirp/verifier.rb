module SIRP
  class Verifier
    include Contracts::Core
    include Contracts::Builtin
    include SIRP

    attr_reader :N       # Bignum
    attr_reader :g       # Fixnum
    attr_reader :k       # Bignum
    attr_reader :A       # String (hex)
    attr_reader :b       # Bignum
    attr_reader :B       # String (hex)
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

    # Phase 0 ; Generate a verifier and salt client-side. This should only be
    # used during the initial user registration process. All three values
    # should be provided as attributes in the user registration process. The
    # verifier and salt should be persisted server-side. The verifier
    # should be protected and never made public or given to any user.
    # The salt should be returned to any user requesting it to start
    # Phase 1 of the authentication process.
    #
    # @param username [String] the authentication username
    # @param password [String] the authentication password
    # @return [Hash] a Hash of the username, verifier, and salt
    Contract String, String => { username: String, verifier: String, salt: String }
    def generate_userauth(username, password)
      raise ArgumentError, 'username must not be an emoty string' if username.empty?
      raise ArgumentError, 'password must not be an emoty string' if password.empty?

      @salt ||= RbNaCl::Util.bin2hex(RbNaCl::Random.random_bytes(16))
      x = calc_x(username, password, @salt)
      v = calc_v(x, @N, @g)
      { username: username, verifier: num_to_hex(v), salt: @salt }
    end

    # Phase 1 : Step 2 : Create a challenge for the client, and a proof to be stored
    # on the server for later use when verifying the client response.
    #
    # @param username [String] the client provided authentication username
    # @param xverifier [String] the server stored verifier for the username in hex
    # @param xsalt [String] the server stored salt for the username in hex
    # @param xaa [String] the client provided 'A' value in hex
    # @return [Hash] a Hash with the challenge for the client and a proof for the server
    Contract String, String, String, String => { challenge: { B: String, salt: String },
      proof: { A: String, B: String, b: String, I: String, s: String, v: String } }
    def get_challenge_and_proof(username, xverifier, xsalt, xaa)
      raise ArgumentError, 'username must not be an empty string' if username.empty?
      raise ArgumentError, 'xverifier must be a hex string' unless xverifier =~ /^[a-fA-F0-9]+$/
      raise ArgumentError, 'xsalt must be a hex string' unless xsalt =~ /^[a-fA-F0-9]+$/
      raise ArgumentError, 'xaa must be a hex string' unless xaa =~ /^[a-fA-F0-9]+$/

      raise 'SRP-6a Safety Check : A.to_i(16) % N cannot equal 0' if (xaa.to_i(16) % @N).zero?

      # Generate b and B
      v = xverifier.to_i(16)
      @b ||= RbNaCl::Util.bin2hex(RbNaCl::Random.random_bytes(32)).hex
      @B = num_to_hex(calc_B(@b, k, v, @N, @g))

      {
        challenge: { B: @B, salt: xsalt },
        proof: { A: xaa, B: @B, b: num_to_hex(@b), I: username, s: xsalt, v: xverifier }
      }
    end

    #
    # Phase 2 : Step 1 : See Client#start_authentication
    #

    # Phase 2 : Step 2 : Use the server stored proof and the client provided 'M' value.
    # Calculates a server 'M' value and compares it to the client provided one,
    # and if they match the client and server have negotiated equal secrets.
    # Returns a H(A, M, K) value on success and nil on failure.
    #
    # Sets the @K value, which is the client and server negotiated secret key
    # if verification succeeds. This can be used to derive strong encryption keys
    # for later use. The client independently calculates the same @K value as well.
    #
    # If authentication fails the H_AMK value must not be provided to the client.
    #
    # @param proof [Hash] the server stored proof Hash with keys A, B, b, I, s, v
    # @param client_M [String] the client provided 'M' value in hex
    # @return [String] the H_AMK value in hex for the client, or empty string if verification failed
    Contract ({A: String, B: String, b: String, I: String, s: String, v: String}), String => String
    def verify_session(proof, client_M)
      raise ArgumentError, 'proof must be a hash' unless proof.is_a?(Hash)
      # gracefully handle string or symbol keys
      Hashie.symbolize_keys!(proof)
      raise ArgumentError, 'proof must have required hash keys' unless proof.keys == [:A, :B, :b, :I, :s, :v]
      raise ArgumentError, 'client_M must be a hex string' unless client_M =~ /^[a-fA-F0-9]+$/

      @A = proof[:A]
      @B = proof[:B]
      @b = proof[:b].to_i(16)
      v = proof[:v].to_i(16)

      u = calc_u(@A, @B, hash)

      raise 'SRP-6a Safety Check : u cannot equal 0' if u.zero?

      # Calculate session key 'S' and secret key 'K'
      @S = num_to_hex(calc_server_S(@A.to_i(16), @b, v, u, @N))
      @K = hash.hexdigest([@S].pack('H*'))

      # Calculate the 'M' matcher
      @M = calc_M(@A, @B, @K, hash)

      if secure_compare(@M, client_M)
        # Authentication succeeded, Calculate the H(A,M,K) verifier
        @H_AMK = calc_H_AMK(@A, @M, @K, hash)
      else
        # Authentication failed : Do not return H_AMK!
        ''
      end
    end
  end
end
