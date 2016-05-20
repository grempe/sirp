module SIRP

  # Convert a hex string to an a array of Integer bytes by first converting
  # the String to hex, and then converting that hex to an Array of Integer bytes.
  #
  # @param str [String] a string to convert
  # @return [Array<Integer>] an Array of Integer bytes
  def hex_to_bytes(str)
    [str].pack('H*').unpack('C*')
  end

  # Convert a number to a downcased hex string, prepending '0' to the
  # hex string if the hex conversion resulted in an odd length string.
  #
  # @param num [Integer] a number to convert to a hex string
  # @return [String] a hex string
  def num_to_hex(num)
    hex_str = num.to_s(16)
    even_hex_str = hex_str.length.odd? ? '0' + hex_str : hex_str
    even_hex_str.downcase
  end

  # Applies a one-way hash function, either SHA1 or SHA256, on an
  # unpacked hex string. It will generate the same
  # one-way hash value for a string that has been unpacked as if the
  # hash function had been applied to the string directly.
  #
  #    'foo'.unpack('H*')
  #    => ["666f6f"]
  #
  #    > sha_hex('foo'.unpack('H*')[0], Digest::SHA256)
  #    => "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
  #    > Digest::SHA256.hexdigest 'foo'
  #    => "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
  #
  # @param h [String] a hex string to hash
  # @param hash_klass [Digest::SHA1, Digest::SHA256] The hash class that responds to hexdigest
  # @return [String] a hex string representing the result of the one way hash function
  def sha_hex(h, hash_klass)
    hash_klass.hexdigest([h].pack('H*'))
  end

  # Applies a one-way hash function, either SHA1 or SHA256, on the string provided.
  #
  # @param s [String] a string to hash
  # @param hash_klass [Digest::SHA1, Digest::SHA256] The hash class that responds to hexdigest
  # @return [String] a hex string representing the result of the one way hash function
  def sha_str(s, hash_klass)
    hash_klass.hexdigest(s)
  end

  # Constant time string comparison.
  # Extracted from Rack::Utils
  # https://github.com/rack/rack/blob/master/lib/rack/utils.rb
  #
  # NOTE: the values compared should be of fixed length, such as strings
  # that have already been processed by HMAC. This should not be used
  # on variable length plaintext strings because it could leak length info
  # via timing attacks. The user provided value should always be passed
  # in as the second parameter so as not to leak info about the secret.
  #
  # @param a [String] the private value
  # @param b [String] the user provided value
  # @return [true, false] whether the strings match or not
  def secure_compare(a, b)
    return false unless a.bytesize == b.bytesize

    l = a.unpack('C*')

    r, i = 0, -1
    b.each_byte { |v| r |= v ^ l[i+=1] }
    r == 0
  end

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
  # can be viewed here and talks about the weaknesses in the original
  # SRP spec when considering brute force attacks on the verifier.
  #
  # See page 12:
  # https://web.archive.org/web/20150403175113/http://www.leviathansecurity.com/wp-content/uploads/SpiderOak-Crypton_pentest-Final_report_u.pdf
  #
  # This strengthened version uses SHA256 and HMAC_SHA256 in concert
  # with the scrypt memory and CPU hard key stretching algorithm to
  # derive a much stronger 'x' value. Since the verifier is directly
  # derived from 'x' using Modular Exponentiation this makes brute force
  # attack much less likely. The new algorithm is:
  #
  #   prehash_pw = HMAC_SHA256('srp-x-1', password)
  #   int_key = scrypt(prehash_pw, SHA256(salt), ...)
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
    int_key = RbNaCl::PasswordHash.scrypt(prehash_pw, Digest::SHA256.digest(salt), 2**19, 2**24, 32)
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

  # A = g^a (mod N)
  def calc_A(a, n, g)
    mod_exp(g, a, n)
  end

  # B = g^b + k v (mod N)
  def calc_B(b, k, v, n, g)
    (mod_exp(g, b, n) + k * v) % n
  end

  # Client secret
  # S = (B - (k * g^x)) ^ (a + (u * x)) % N
  def calc_client_S(bb, a, k, x, u, n, g)
    mod_exp((bb - k * mod_exp(g, x, n)) % n, (a + x * u), n)
  end

  # Server secret
  # S = (A * v^u) ^ b % N
  def calc_server_S(aa, b, v, u, n)
    mod_exp((mod_exp(v, u, n) * aa), b, n)
  end

  # M = H(A, B, K)
  def calc_M(xaa, xbb, xkk, hash_klass)
    digester = hash_klass.new
    digester << hex_to_bytes(xaa).pack('C*')
    digester << hex_to_bytes(xbb).pack('C*')
    digester << hex_to_bytes(xkk).pack('C*')
    digester.hexdigest
  end

  # H(A, M, K)
  def calc_H_AMK(xaa, xmm, xkk, hash_klass)
    byte_string = hex_to_bytes([xaa, xmm, xkk].join('')).pack('C*')
    sha_str(byte_string, hash_klass).hex
  end
end
