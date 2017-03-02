# frozen_string_literal: true

require 'sirp'

module SIRP
  class Register
    def initialize(username, password, group=Prime[2048], hash=Digest::SHA256)
      @backend = Backend.new(group, hash)

      # TODO: truncate values
      @username = username
      @password = password

      validate_params!

      @salt = generate_salt
      x = @backend.calc_x(@username, @password, @salt)
      @v = SIRP.num_to_hex(@backend.calc_v(x))
    end

    def credentials
      { username: @username, verifier: @v, salt: @salt }
    end

  private

    def validate_params!
      raise ArgumentError, 'username must not be an empty string' if @username.empty?
      raise ArgumentError, 'password must not be an empty string' if @password.empty?
    end

    def generate_salt
      RbNaCl::Util.bin2hex(RbNaCl::Random.random_bytes(16))
    end
  end
end
