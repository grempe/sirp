module SIRP
  class Backend
    class Digest < self

      # Private Key (derived from username, password and salt)
      #
      # x = H(salt || H(username || ':' || password))
      #
      # @param username [String] the 'username' (I) as a String
      # @param password [String] the 'password' (p) as a String
      # @param salt [String] the 'salt' in hex
      # @return [Integer] the Scrypt+HMAC stretched 'x' value as an Integer
      Contract String, String, String => Integer
      def calc_x(username, password, salt)
        spad = salt.length.odd? ? '0' : ''
        h = spad + salt + @hash.hexdigest([username, password].join(':'))
        @hash.hexdigest([h].pack('H*')).hex
      end
    end
  end
end
