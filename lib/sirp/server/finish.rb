# frozen_string_literal: true

module SIRP
  class Server
    class Finish
      attr_reader :backend, :proof

      def initialize(proof_attrs, mm, group=Prime[2048], hash=Digest::SHA256, backend_cls=Backend::SCryptHMAC)
        @backend = backend_cls.new(group, hash)

        @proof = Utils.symbolize_keys(proof_attrs)
        @client_M = mm

        validate_params!

        @b = proof[:b].to_i(16)
        @v = proof[:v].to_i(16)

        @K = backend.calc_K(calc_S)
        @M = backend.calc_M(proof[:I], proof[:s], proof[:A], proof[:B], @K)
      end

      def match
        success? ? backend.calc_H_AMK(proof[:A], @M, @K) : ''
      end

      def success?
        Utils.secure_compare(@M, @client_M)
      end

    private

      def validate_params!
        fail ArgumentError, 'proof must have required hash keys' unless @proof.keys == [:A, :B, :b, :I, :s, :v]
        fail ArgumentError, 'client M must be a hex string' unless Utils.hex_str?(@client_M)
      end

      def calc_S
        u = backend.calc_u(proof[:A], proof[:B])
        Utils.num_to_hex(backend.calc_server_S(proof[:A], @b, @v, u))
      end

    end
  end
end
