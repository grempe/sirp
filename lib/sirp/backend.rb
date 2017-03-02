# frozen_string_literal: true

require 'contracts'

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

    # Abstract
    # Private Key (derived from username, password and salt)
    #
    # The spec calls for calculating 'x' using:
    #
    #   x = H(salt || H(username || ':' || password))
    #
    # @param username [String] the 'username' (I) as a String
    # @param password [String] the 'password' (p) as a String
    # @param salt [String] the 'salt' in hex
    # @return [Integer] the Scrypt+HMAC stretched 'x' value as an Integer
    Contract String, String, String => Integer
    def calc_x(username, password, salt)
      fail NotImplementedError
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

require 'sirp/backend/scrypt_hmac'
