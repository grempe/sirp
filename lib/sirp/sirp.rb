module SIRP
  include Contracts::Core
  include Contracts::Builtin

  SafetyCheckError = Class.new(StandardError)

  # Modular Exponentiation
  # https://en.m.wikipedia.org/wiki/Modular_exponentiation
  # http://rosettacode.org/wiki/Modular_exponentiation#Ruby
  #
  # a^b (mod m)
  #
  # @param a [Fixnum, Bignum] the base value as a Fixnum or Bignum, depending on size
  # @param b [Bignum] the exponent value as a Bignum
  # @param m [Bignum] the modulus value as a Bignum
  # @return [Bignum] the solution as a Bignum
  Contract Or[Fixnum, Bignum], Nat, Nat => Bignum
  def mod_pow(a, b, m)
    # Convert type and use OpenSSL::BN#mod_exp to do the calculation
    # Convert back to a Bignum so OpenSSL::BN doesn't leak everywhere
    a.to_bn.mod_exp(b, m).to_i
  end

  # One-Way Hash Function
  #
  # @param hash_klass [Digest::SHA1, Digest::SHA256] The hash class that responds to hexdigest
  # @param a [Array] the Array of values to be hashed together
  # @return [Bignum] the hexdigest as a Bignum
  Contract RespondTo[:hexdigest], ArrayOf[Or[String, Nat]] => Bignum
  def H(hash_klass, a)
    hasher = hash_klass.new

    a.compact.map do |v|
      xv = v.is_a?(String) ? v : num_to_hex(v)
      hasher.update [xv].pack('H*')
    end

    digest = hasher.hexdigest
    digest.hex
  end

  # Multiplier Parameter
  # k = H(N, g) (in SRP-6a)
  #
  # @param nn [Bignum] the 'N' value as a Bignum
  # @param g [Fixnum] the 'g' value as a Fixnum
  # @param hash_klass [Digest::SHA1, Digest::SHA256] The hash class that responds to hexdigest
  # @return [Bignum] the 'k' value as a Bignum
  Contract Bignum, Nat, RespondTo[:hexdigest] => Bignum
  def calc_k(nn, g, hash_klass)
    H(hash_klass, [nn, g])
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
  # @return [Bignum] the Scrypt+HMAC stretched 'x' value as a Bignum
  Contract String, String, String => Bignum
  def calc_x(username, password, salt)
    prehash_pw = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), 'srp-x-1', password)
    int_key = RbNaCl::PasswordHash.scrypt(prehash_pw, salt.force_encoding('BINARY'), 2**19, 2**24, 32)
    x_hex = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), 'srp-x-2', int_key + username)
    x_hex.hex
  end

  # Random Scrambling Parameter
  # u = H(A, B)
  #
  # @param xaa [String] the 'A' value in hex
  # @param xbb [String] the 'B' value in hex
  # @param hash_klass [Digest::SHA1, Digest::SHA256] The hash class that responds to hexdigest
  # @return [Bignum] the 'u' value as a Bignum
  Contract String, String, RespondTo[:hexdigest] => Bignum
  def calc_u(xaa, xbb, hash_klass)
    H(hash_klass, [xaa, xbb])
  end

  # Password Verifier
  # v = g^x (mod N)
  #
  # @param x [Bignum] the 'x' value as a Bignum
  # @param nn [Bignum] the 'N' value as a Bignum
  # @param g [Fixnum] the 'g' value as a Fixnum
  # @return [Bignum] the client 'v' value as a Bignum
  Contract Bignum, Bignum, Fixnum => Bignum
  def calc_v(x, nn, g)
    mod_pow(g, x, nn)
  end

  # Client Ephemeral Value
  # A = g^a (mod N)
  #
  # @param a [Bignum] the 'a' value as a Bignum
  # @param nn [Bignum] the 'N' value as a Bignum
  # @param g [Fixnum] the 'g' value as a Fixnum
  # @return [Bignum] the client ephemeral 'A' value as a Bignum
  Contract Bignum, Bignum, Fixnum => Bignum
  def calc_A(a, nn, g)
    mod_pow(g, a, nn)
  end

  # Server Ephemeral Value
  # B = kv + g^b % N
  #
  # @param b [Bignum] the 'b' value as a Bignum
  # @param k [Bignum] the 'k' value as a Bignum
  # @param v [Bignum] the 'v' value as a Bignum
  # @param nn [Bignum] the 'N' value as a Bignum
  # @param g [Fixnum] the 'g' value as a Fixnum
  # @return [Bignum] the verifier ephemeral 'B' value as a Bignum
  Contract Bignum, Bignum, Bignum, Bignum, Fixnum => Bignum
  def calc_B(b, k, v, nn, g)
    (k * v + mod_pow(g, b, nn)) % nn
  end

  # Client Session Key
  # S = (B - (k * g^x)) ^ (a + (u * x)) % N
  #
  # @param bb [Bignum] the 'B' value as a Bignum
  # @param a [Bignum] the 'a' value as a Bignum
  # @param k [Bignum] the 'k' value as a Bignum
  # @param x [Bignum] the 'x' value as a Bignum
  # @param u [Bignum] the 'u' value as a Bignum
  # @param nn [Bignum] the 'N' value as a Bignum
  # @param g [Fixnum] the 'g' value as a Fixnum
  # @return [Bignum] the client 'S' value as a Bignum
  Contract Bignum, Bignum, Bignum, Bignum, Bignum, Bignum, Fixnum => Bignum
  def calc_client_S(bb, a, k, x, u, nn, g)
    mod_pow((bb - k * mod_pow(g, x, nn)), a + u * x, nn)
  end

  # Server Session Key
  # S = (A * v^u) ^ b % N
  #
  # @param aa [Bignum] the 'A' value as a Bignum
  # @param b [Bignum] the 'b' value as a Bignum
  # @param v [Bignum] the 'v' value as a Bignum
  # @param u [Bignum] the 'u' value as a Bignum
  # @param nn [Bignum] the 'N' value as a Bignum
  # @return [Bignum] the verifier 'S' value as a Bignum
  Contract Bignum, Bignum, Bignum, Bignum, Bignum => Bignum
  def calc_server_S(aa, b, v, u, nn)
    mod_pow(aa * mod_pow(v, u, nn), b, nn)
  end

  # M = H(A, B, K)
  #
  # @param xaa [String] the 'A' value in hex
  # @param xbb [String] the 'B' value in hex
  # @param xkk [String] the 'K' value in hex
  # @param hash_klass [Digest::SHA1, Digest::SHA256] The hash class that responds to hexdigest
  # @return [String] the 'M' value in hex
  Contract String, String, String, RespondTo[:hexdigest] => String
  def calc_M(xaa, xbb, xkk, hash_klass)
    digester = hash_klass.new
    digester << hex_to_bytes(xaa).pack('C*')
    digester << hex_to_bytes(xbb).pack('C*')
    digester << hex_to_bytes(xkk).pack('C*')
    digester.hexdigest
  end

  # H(A, M, K)
  #
  # @param xaa [String] the 'A' value in hex
  # @param xmm [String] the 'M' value in hex
  # @param xkk [String] the 'K' value in hex
  # @param hash_klass [Digest::SHA1, Digest::SHA256] The hash class that responds to hexdigest
  # @return [String] the 'H_AMK' value in hex
  Contract String, String, String, RespondTo[:hexdigest] => String
  def calc_H_AMK(xaa, xmm, xkk, hash_klass)
    byte_string = hex_to_bytes([xaa, xmm, xkk].join('')).pack('C*')
    hash_klass.hexdigest(byte_string)
  end
end
