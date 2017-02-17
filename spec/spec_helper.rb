# coveralls.io and coco are incompatible. Run each in their own env.
if ENV['TRAVIS'] || ENV['CI'] || ENV['JENKINS_URL'] || ENV['TDDIUM'] || ENV['COVERALLS_RUN_LOCALLY']
  # coveralls.io : web based code coverage
  require 'coveralls'
  Coveralls.wear!
else
  # coco : local code coverage
  require 'coco'
end

require 'sirp'

Dir[File.join(Dir.pwd, 'spec/shared/**/*.rb')].each { |f| require f }

RSpec.configure do |config|
  config.filter_run :focus
  config.run_all_when_everything_filtered = true
  config.shared_context_metadata_behavior = :apply_to_host_groups

  if config.files_to_run.one?
    config.full_backtrace = true

    config.default_formatter = 'doc'
  end

  config.order = :random

  Kernel.srand(config.seed)

  config.disable_monkey_patching!
  config.warnings = false

  config.expect_with :rspec do |expectations|
    expectations.syntax = :expect
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.syntax = :expect
    mocks.verify_partial_doubles = true
    mocks.verify_doubled_constant_names = true
  end
end
