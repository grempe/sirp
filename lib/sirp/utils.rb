module SIRP
  class Utils
    HEX_REG = /^\h+$/.freeze

    class << self
      def empty?(str)
        str.strip.empty?
      end

      # NOTE: fallback to ruby < 2.4 required
      def hex_str?(str)
        HEX_REG.match?(str)
      end

      def num_to_hex(num)
        hex_str = num.to_s(16)
        even_hex_str = hex_str.length.odd? ? '0' + hex_str : hex_str
        even_hex_str.downcase
      end

      def symbolize_keys(hash)
        hash.each_with_object({}) { |(k, v), res| res[k.to_sym] = v }
      end

      def secure_compare(a, b)
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
  end
end
