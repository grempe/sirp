# encoding: utf-8

# coveralls.io and coco are incompatible. Run each in their own env.
if ENV['TRAVIS'] || ENV['CI'] || ENV['JENKINS_URL'] || ENV['TDDIUM'] || ENV['COVERALLS_RUN_LOCALLY']
  # coveralls.io : web based code coverage
  require 'coveralls'
  Coveralls.wear!
else
  # coco : local code coverage
  require 'coco'
end

require 'srp'

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    # c.syntax = :expect          # disables `should`
    # c.syntax = :should          # disables `expect`
    c.syntax = [:should, :expect] # default, enables both `should` and `expect`
  end
end

# Monkey-patch API to define a, b and salt presetters
module SRP
  class Verifier
    def set_b(val)
      @b = val
    end

    def set_salt(val)
      @salt = val
    end
  end
end

module SRP
  class Client
    def set_a(val)
      @a = val
    end
  end
end
