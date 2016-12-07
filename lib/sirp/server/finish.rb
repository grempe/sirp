module SIRP
  class Server
    class Finish
      attr_reader :backend, :proof

      def initialize(proof, mm, group, hash)
        @backend = Backend.new(group, hash)

        @proof = proof
        @client_M = mm

        validate_params!

        @b = proof[:b].to_i(16)
        @v = proof[:v].to_i(16)

        @K = backend.calc_K(calc_S)
        @M = backend.calc_M(proof[:I], proof[:s], proof[:A], proof[:B], @K)
      end

      def validate_params!
        raise ArgumentError, 'proof must have required hash keys' unless @proof.keys == [:A, :B, :b, :I, :s, :v]
        raise ArgumentError, 'client M must be a hex string' unless @client_M =~ /^[a-fA-F0-9]+$/
      end

      def calc_S
        u = backend.calc_u(proof[:A], proof[:B])
        SIRP.num_to_hex(backend.calc_server_S(proof[:A], @b, @v, u))
      end

      def match
        success? ? backend.calc_H_AMK(proof[:A], @M, @K) : ''
      end

      def success?
        SIRP.secure_compare(@M, @client_M)
      end
    end
  end
end
