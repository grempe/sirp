require 'openssl'
require 'digest/sha2'
require 'rbnacl/libsodium'
require 'rbnacl'
require 'contracts'

module SIRP
  HEX_REG = /^\h+$/.freeze

  SafetyCheckError = Class.new(StandardError)

  # NOTE: fallback to ruby < 2.4 required
  module_function def hex_str?(str)
    HEX_REG.match?(str)
  end

  module_function def num_to_hex(num)
    hex_str = num.to_s(16)
    even_hex_str = hex_str.length.odd? ? '0' + hex_str : hex_str
    even_hex_str.downcase
  end

  module_function def secure_compare(a, b)
    # Do all comparisons on equal length hashes of the inputs
    a = Digest::SHA256.hexdigest(a)
    b = Digest::SHA256.hexdigest(b)
    return false unless a.bytesize == b.bytesize

    l = a.unpack('C*')

    r = 0
    i = -1
    b.each_byte { |v| r |= v ^ l[i+=1] }
    r == 0
  end
end

require 'sirp/parameters'
require 'sirp/backend'
require 'sirp/server/start'
require 'sirp/server/finish'

require 'sirp/version'
