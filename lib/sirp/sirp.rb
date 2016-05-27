module SIRP
  # Modular Exponentiation
  # https://en.m.wikipedia.org/wiki/Modular_exponentiation
  # http://rosettacode.org/wiki/Modular_exponentiation#Ruby
  #
  # a^b (mod m)
  def mod_exp(a, b, m)
    # Use OpenSSL::BN#mod_exp
    a.to_bn.mod_exp(b, m)
  end

  # Hashing function with padding.
  # Input is prefixed with 0 to meet N hex width.
  def H(hash_klass, n, *a)
    nlen = 2 * ((('%x' % [n]).length * 4 + 7) >> 3)

    hashin = a.map do |s|
      next unless s
      shex = s.is_a?(String) ? s : num_to_hex(s)
      if shex.length > nlen
        raise 'Bit width does not match - client uses different prime'
      end
      '0' * (nlen - shex.length) + shex
    end.join('')

    sha_hex(hashin, hash_klass).hex % n
  end

  # Multiplier parameter
  # k = H(N, g)   (in SRP-6a)
  def calc_k(n, g, hash_klass)
    H(hash_klass, n, n, g)
  end

  # Private key (derived from username, raw password and salt)
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
  def calc_x(username, password, salt)
    prehash_pw = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), 'srp-x-1', password)
    int_key = RbNaCl::PasswordHash.scrypt(prehash_pw, salt.force_encoding('BINARY'), 2**19, 2**24, 32)
    x_hex = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), 'srp-x-2', int_key + username)
    x_hex.hex
  end

  # Random scrambling parameter
  # u = H(A, B)
  def calc_u(xaa, xbb, n, hash_klass)
    H(hash_klass, n, xaa, xbb)
  end

  # Password verifier
  # v = g^x (mod N)
  def calc_v(x, n, g)
    mod_exp(g, x, n)
  end

  # Client Ephemeral Value
  # A = g^a (mod N)
  #
  # @param a [Bignum] the 'a' value as a Bignum
  # @param nn [Bignum] the 'N' value as a Bignum
  # @param g [Bignum] the 'g' value as a Bignum
  # @return [Bignum] the client ephemeral 'A' value as a Bignum
  def calc_A(a, nn, g)
    mod_exp(g, a, nn)
  end

  # Server Ephemeral Value
  # B = kv + g^b % N
  #
  # @param b [Bignum] the 'b' value as a Bignum
  # @param k [Bignum] the 'k' value as a Bignum
  # @param v [Bignum] the 'v' value as a Bignum
  # @param nn [Bignum] the 'N' value as a Bignum
  # @param g [Bignum] the 'g' value as a Bignum
  # @return [Bignum] the verifier ephemeral 'B' value as a Bignum
  def calc_B(b, k, v, nn, g)
    (k * v + mod_exp(g, b, nn)) % nn
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
  # @param g [Bignum] the 'g' value as a Bignum
  # @return [Bignum] the client 'S' value as a Bignum
  def calc_client_S(bb, a, k, x, u, nn, g)
    mod_exp((bb - k * mod_exp(g, x, nn)), a + u * x, nn)
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
  def calc_server_S(aa, b, v, u, nn)
    mod_exp(aa * mod_exp(v, u, nn), b, nn)
  end

  # M = H(A, B, K)
  #
  # @param xaa [String] the 'A' value in hex
  # @param xbb [String] the 'B' value in hex
  # @param xkk [String] the 'K' value in hex
  # @param hash_klass [Digest::SHA1, Digest::SHA256] The hash class that responds to hexdigest
  # @return [String] the 'M' value in hex
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
  def calc_H_AMK(xaa, xmm, xkk, hash_klass)
    byte_string = hex_to_bytes([xaa, xmm, xkk].join('')).pack('C*')
    sha_str(byte_string, hash_klass)
  end
end
