# frozen_string_literal: true

module SIRP
  class Server
    class Start
      attr_reader :user, :backend

      def initialize(user_attrs, aa, group=Prime[2048], hash=Digest::SHA256, backend_cls=Backend::SCryptHMAC)
        @backend = backend_cls.new(group, hash)
        @user = Utils.symbolize_keys(user_attrs)
        @A = aa

        validate_params!

        @b = generate_b
        @v = user[:verifier]
        @B = Utils.num_to_hex(backend.calc_B(@b.hex, @v.to_i(16)))
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
        raise ArgumentError, 'username must not be an empty string' if Utils.empty?(user[:username])
        raise ArgumentError, 'verifier must be a hex string' unless Utils.hex_str?(user[:verifier])
        raise ArgumentError, 'salt must be a hex string' unless Utils.hex_str?(user[:salt])
        raise ArgumentError, '"A" must be a hex string' unless Utils.hex_str?(@A)

        fail SafetyCheckError, 'A.to_i(16) % N cannot equal 0' if (@A.to_i(16) % backend.prime.N).zero?
      end

      def generate_b
        RbNaCl::Util.bin2hex(RbNaCl::Random.random_bytes(32))
      end
    end
  end
end
