# frozen_string_literal: true

require 'sirp'

module SIRP
  class Register
    def initialize(username, password, group=Prime[2048], hash=Digest::SHA256, backend_cls=Backend::SCryptHMAC)
      @backend = backend_cls.new(group, hash)

      # TODO: truncate values
      @username = username
      @password = password

      validate_params!

      @salt = generate_salt
      x = @backend.calc_x(@username, @password, @salt)
      @v = Utils.num_to_hex(@backend.calc_v(x))
    end

    def credentials
      { username: @username, verifier: @v, salt: @salt }
    end

  private

    def validate_params!
      fail ArgumentError, 'username must not be an empty string' if Utils.empty?(@username)
      fail ArgumentError, 'password must not be an empty string' if Utils.empty?(@password)
    end

    def generate_salt
      RbNaCl::Util.bin2hex(RbNaCl::Random.random_bytes(16))
    end
  end
end
