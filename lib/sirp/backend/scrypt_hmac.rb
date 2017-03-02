module SIRP
  class Backend
    class SCryptHMAC < self
      # Private Key (derived from username, password and salt)
      #
      # The spec calls for calculating 'x' using:
      #
      #   x = H(salt || H(username || ':' || password))
      #
      # However, this can be greatly strengthened against attacks
      # on the verififier. The specified scheme requires only brute
      # forcing 2x SHA1 or SHA256 hashes and a modular exponentiation.
      #
      # The implementation that follows is based on extensive discussion with
      # Dmitry Chestnykh (@dchest). This approach is also informed by
      # the security audit done on the Spider Oak crypton.io project which
      # can be viewed at the link below and talks about the weaknesses in the
      # original SRP spec when considering brute force attacks on the verifier.
      #
      # Security Audit : Page 12:
      # https://web.archive.org/web/20150403175113/http://www.leviathansecurity.com/wp-content/uploads/SpiderOak-Crypton_pentest-Final_report_u.pdf
      #
      # This strengthened version uses SHA256 and HMAC_SHA256 in concert
      # with the scrypt memory and CPU hard key stretching algorithm to
      # derive a much stronger 'x' value. Since the verifier is directly
      # derived from 'x' using Modular Exponentiation this makes brute force
      # attack much less likely. The new algorithm is:
      #
      #   prehash_pw = HMAC_SHA256('srp-x-1', password)
      #   int_key = scrypt(prehash_pw, salt, ...)
      #   HMAC_SHA256('srp-x-2', int_key + username)
      #
      # The scrypt values equate to the 'interactive' use constants in libsodium.
      # The values given to the RbNaCl::PasswordHash.scrypt can be converted for use
      # with https://github.com/dchest/scrypt-async-js using the following conversions:
      #
      #
      # CPU/memory cost parameters
      # Conversion from RbNaCl / libsodium and scrypt-async-js
      # SCRYPT_OPSLIMIT_INTERACTIVE == 2**19 == (2**24 / 32) == 524288 == logN 14
      # SCRYPT_OPSLIMIT_SENSITIVE == 2**25 == (2**30 / 32) == 33554432 == logN 20
      #
      # The value returned should be the final HMAC_SHA256 hex converted to an Integer
      #
      # @param username [String] the 'username' (I) as a String
      # @param password [String] the 'password' (p) as a String
      # @param salt [String] the 'salt' in hex
      # @return [Integer] the Scrypt+HMAC stretched 'x' value as an Integer
      Contract String, String, String => Integer
      def calc_x(username, password, salt)
        prehash_pw = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), 'srp-x-1', password)
        int_key = RbNaCl::PasswordHash.scrypt(prehash_pw, salt.force_encoding('BINARY'), 2**19, 2**24, 32).each_byte.map { |b| b.to_s(16) }.join
        x_hex = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), 'srp-x-2', int_key + username)
        x_hex.hex
      end
    end
  end
end
