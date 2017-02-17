module SIRP
  class Server
    class Start
      attr_reader :user, :backend

      def initialize(user, aa, group, hash)
        @backend = Backend.new(group, hash)
        @user = user
        @A = aa

        validate_params!

        @b = RbNaCl::Util.bin2hex(RbNaCl::Random.random_bytes(32))
        @v = user[:verifier]
        @B = SIRP.num_to_hex(backend.calc_B(@b.hex, @v.to_i(16)))
      end

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
        raise ArgumentError, 'username must not be an empty string' if user[:username].empty?
        raise ArgumentError, 'verifier must be a hex string' unless user[:verifier] =~ /^[a-fA-F0-9]+$/
        raise ArgumentError, 'salt must be a hex string' unless user[:salt] =~ /^[a-fA-F0-9]+$/
        raise ArgumentError, '"A" must be a hex string' unless @A =~ /^[a-fA-F0-9]+$/

        fail SafetyCheckError, 'A.to_i(16) % N cannot equal 0' if (@A.to_i(16) % backend.prime.N).zero?
      end
    end
  end
end
