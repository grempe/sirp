module SIRP
  class Backend
    include Contracts::Core
    include Contracts::Builtin

    attr_reader :prime

    def initialize(group=Prime[2048], hash=Digest::SHA256)
      @prime = group
      @hash = hash
    end

    # Modular Exponentiation
    # https://en.m.wikipedia.org/wiki/Modular_exponentiation
    # http://rosettacode.org/wiki/Modular_exponentiation#Ruby
    #
    # a^b (mod m)
    #
    # @param a [Integer] the base value as an Integer, depending on size
    # @param b [Integer] the exponent value as an Integer
    # @param m [Integer] the modulus value as an Integer
    # @return [Integer] the solution as an Integer
    Contract Integer, Nat, Nat => Integer
    def mod_pow(a, b, m)
      # Convert type and use OpenSSL::BN#mod_exp to do the calculation
      # Convert back to an Integer so OpenSSL::BN doesn't leak everywhere
      a.to_bn.mod_exp(b, m).to_i
    end

    # One-Way Hash Function
    #
    # @param a [Array] the Array of values to be hashed together
    # @return [Integer] the hexdigest as an Integer
    Contract ArrayOf[Or[String, Nat]] => Integer
    def H(a)
      hasher = @hash.new

      a.compact.map do |v|
        xv = v.is_a?(String) ? v : SIRP.num_to_hex(v)
        hasher.update(xv.downcase)
      end

      digest = hasher.hexdigest
      digest.hex
    end

    # Multiplier Parameter
    # k = H(N, g) (in SRP-6a)
    #
    # @return [Integer] the 'k' value as an Integer
    Contract None => Integer
    def k
      @k ||= H([prime.N, prime.g].map(&:to_s))
    end

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

    # Random Scrambling Parameter
    # u = H(A, B)
    #
    # @param xaa [String] the 'A' value in hex
    # @param xbb [String] the 'B' value in hex
    # @return [Integer] the 'u' value as an Integer
    Contract String, String => Integer
    def calc_u(xaa, xbb)
      u = H([xaa, xbb])

      u.zero? ? fail(SafetyCheckError, 'u cannot equal 0') : u
    end

    # Password Verifier
    # v = g^x (mod N)
    #
    # @param x [Integer] the 'x' value as an Integer
    # @return [Integer] the client 'v' value as an Integer
    Contract Integer => Integer
    def calc_v(x)
      mod_pow(prime.g, x, prime.N)
    end

    # Client Ephemeral Value
    # A = g^a (mod N)
    #
    # @param a [Integer] the 'a' value as an Integer
    # @return [Integer] the client ephemeral 'A' value as an Integer
    Contract Integer, Integer, Integer => Integer
    def calc_A(a)
      mod_pow(prime.g, a, prime.N)
    end

    # Server Ephemeral Value
    # B = kv + g^b % N
    #
    # @param b [Integer] the 'b' value as an Integer
    # @param v [Integer] the 'v' value as an Integer
    # @return [Integer] the verifier ephemeral 'B' value as an Integer
    Contract Integer, Integer => Integer
    def calc_B(b, v)
      (k * v + mod_pow(prime.g, b, prime.N)) % prime.N
    end

    # Client Session Key
    # S = (B - (k * g^x)) ^ (a + (u * x)) % N
    #
    # @param bb [Integer] the 'B' value as an Integer
    # @param a [Integer] the 'a' value as an Integer
    # @param x [Integer] the 'x' value as an Integer
    # @param u [Integer] the 'u' value as an Integer
    # @return [Integer] the client 'S' value as an Integer
    Contract Integer, Integer, Integer, Integer, Integer => Integer
    def calc_client_S(bb, a, x, u)
      mod_pow((bb - k * mod_pow(prime.g, x, prime.N)), a + u * x, prime.N)
    end

    # Server Session Key
    # S = (A * v^u) ^ b % N
    #
    # @param aa [Integer] the 'A' value as a String
    # @param b [Integer] the 'b' value as an Integer
    # @param v [Integer] the 'v' value as an Integer
    # @param u [Integer] the 'u' value as an Integer
    # @return [Integer] the verifier 'S' value as an Integer
    Contract String, Integer, Integer, Integer => Integer
    def calc_server_S(aa, b, v, u)
      mod_pow(aa.to_i(16) * mod_pow(v, u, prime.N), b, prime.N)
    end

    # M = H( H(N) XOR H(g), H(I), s, A, B, K)
    # @param username [String] plain username
    # @param xsalt [String] salt value in hex
    # @param xaa [String] the 'A' value in hex
    # @param xbb [String] the 'B' value in hex
    # @param xkk [String] the 'K' value in hex
    # @return [String] the 'M' value in hex
    Contract String, String, String, String, String => String
    def calc_M(username, xsalt, xaa, xbb, xkk)
      hn = @hash.hexdigest(prime.N.to_s)
      hg = @hash.hexdigest(prime.g.to_s)
      hxor = hn.to_i(16) ^ hg.to_i(16)
      hi = @hash.hexdigest(username)
      SIRP.num_to_hex(H([[hxor, hi.to_i(16), xsalt, xaa.to_i(16), xbb.to_i(16), xkk].map(&:to_s).join]))
    end

    # K = H(S)
    #
    # @param ss [Integer] the 'S' value as an Integer
    # @return [String] the 'K' value in hex
    Contract String => String
    def calc_K(ss)
      @hash.hexdigest(ss.to_i(16).to_s)
    end

    # H(A, M, K)
    #
    # @param xaa [String] the 'A' value in hex
    # @param xmm [String] the 'M' value in hex
    # @param xkk [String] the 'K' value in hex
    # @return [String] the 'H_AMK' value in hex
    Contract String, String, String => String
    def calc_H_AMK(xaa, xmm, xkk)
      @hash.hexdigest(xaa.to_i(16).to_s + xmm + xkk)
    end
  end
end
