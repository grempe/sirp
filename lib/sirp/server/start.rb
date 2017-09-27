# frozen_string_literal: true

module SIRP
  class Server

    # Host auth: Step 1
    # Create a challenge for the client, and a proof to be stored
    # on the server for later use when verifying the client response.
    #
    #   # Client -> Server: username, A
    #   user = DB[:users].where(username: params[:username]).first
    #   start = SIRP::Server::Start.new(user, params[:A])
    #   # Server stores proof to session
    #   session[:proof] = start.proof
    #   # Server -> Client: B, salt
    #   start.challenge
    #
    class Start
      attr_reader :user, :backend

      # Constructor
      #
      # @param user_attrs [Hash] server stored username, verifier and salt
      # @param aa [String] the client provided 'A' value in hex
      # @param group [SIRP::Prime] defaults to Prime of 2048 length
      # @param hash one-way hash function
      # @param backend_cls subclass of SIRP::Backend, defaults to Backend::SCryptHMAC
      def initialize(user_attrs, aa, group=Prime[2048], hash=Digest::SHA256, backend_cls=Backend::SCryptHMAC)
        @backend = backend_cls.new(group, hash)
        @user = Utils.symbolize_keys(user_attrs)
        @A = aa

        validate_params!

        @b = generate_b
        @v = user[:verifier]
        @B = Utils.num_to_hex(backend.calc_B(@b.hex, @v.to_i(16)))
      end

      # Challenge for client
      #
      # @return [Hash] with B and salt
      def challenge
        { B: @B, salt: user[:salt] }
      end

      def proof
        {
          A: @A,
          B: @B,
          b: @b,
          I: user[:username],
          s: user[:salt],
          v: @v
        }
      end

    private

      def validate_params!
        fail ArgumentError, 'username must not be an empty string' if Utils.empty?(user[:username])
        fail ArgumentError, 'verifier must be a hex string' unless Utils.hex_str?(user[:verifier])
        fail ArgumentError, 'salt must be a hex string' unless Utils.hex_str?(user[:salt])
        fail ArgumentError, '"A" must be a hex string' unless Utils.hex_str?(@A)

        fail SafetyCheckError, 'A.to_i(16) % N cannot equal 0' if (@A.to_i(16) % backend.prime.N).zero?
      end

      def generate_b
        RbNaCl::Util.bin2hex(RbNaCl::Random.random_bytes(32))
      end
    end
  end
end
