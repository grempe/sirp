module SIRP
  # http://stackoverflow.com/questions/3772410/convert-a-string-of-0-f-into-a-byte-array-in-ruby
  def hex_to_bytes(str)
    [str].pack('H*').unpack('C*')
  end

  def num_to_hex(num)
    hex_str = num.to_s(16)
    even_hex_str = hex_str.length.odd? ? '0' + hex_str : hex_str
    even_hex_str.downcase
  end

  def sha_hex(h, hash_klass)
    hash_klass.hexdigest([h].pack('H*'))
  end

  def sha_str(s, hash_klass)
    hash_klass.hexdigest(s)
  end

  # Constant time string comparison.
  #   Extracted from Rack::Utils
  #   https://github.com/rack/rack/blob/master/lib/rack/utils.rb
  #
  #   NOTE: the values compared should be of fixed length, such as strings
  #   that have already been processed by HMAC. This should not be used
  #   on variable length plaintext strings because it could leak length info
  #   via timing attacks. The user provided value should always be passed
  #   in as the second parameter so as not to leak info about the secret.
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
      shex = (s.class == String) ? s : num_to_hex(s)
      if shex.length > nlen
        raise 'Bit width does not match - client uses different prime'
      end
      '0' * (nlen - shex.length) + shex
    end.join('')

    sha_hex(hashin, hash_klass).hex % n
  end

  # Multiplier parameter
  # k = H(N, g)   (in SIRP-6a)
  def calc_k(n, g, hash_klass)
    H(hash_klass, n, n, g)
  end

  # Private key (derived from username, raw password and salt)
  # x = H(salt || H(username || ':' || password))
  def calc_x(username, password, salt, hash_klass)
    spad = salt.length.odd? ? '0' : ''
    sha_hex(spad + salt + sha_str([username, password].join(':'), hash_klass), hash_klass).hex
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
