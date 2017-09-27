require 'sirp'

module SIRP
  class Client
    attr_reader :backend

    def initialize(group=Prime[2048], hash=Digest::SHA256, backend_cls=Backend::SCryptHMAC)
      @backend = backend_cls.new(group, hash)

      @a = RbNaCl::Util.bin2hex(RbNaCl::Random.random_bytes(32)).hex
      @A = Utils.num_to_hex(backend.calc_A(@a))
    end

    def start
      @A
    end

    def authenticate(username, password, challenge_attrs)
      challenge = Utils.symbolize_keys(challenge_attrs)

      @username = username
      @password = password

      @salt = challenge[:salt]
      @B    = challenge[:B]

      validate_params!

      @K = backend.calc_K(calc_S)
      @M = backend.calc_M(username, @salt, @A, @B, @K)

      # Calculate the H(A,M,K) verifier
      @H_AMK = backend.calc_H_AMK(@A, @M, @K)

      @M
    end

    def verify(server_H_AMK)
      return false unless @H_AMK
      return false unless Utils.hex_str?(server_H_AMK)

      Utils.secure_compare(@H_AMK, server_H_AMK)
    end

  private

    def validate_params!
      fail ArgumentError, 'username must not be an empty string' if Utils.empty?(@username)
      fail ArgumentError, 'password must not be an empty string' if Utils.empty?(@password)
      fail ArgumentError, 'salt must be a hex string' unless Utils.hex_str?(@salt)
      fail ArgumentError, '"B" must be a hex string' unless Utils.hex_str?(@B)

      fail SafetyCheckError, 'B % N cannot equal 0' if (@B.to_i(16) % backend.prime.N).zero?
    end

    def calc_S
      x = backend.calc_x(@username, @password, @salt)
      u = backend.calc_u(@A, @B)

      fail SafetyCheckError, 'u cannot equal 0' if u.zero?

      Utils.num_to_hex(backend.calc_client_S(@B.to_i(16), @a, x, u))
    end
  end
end
