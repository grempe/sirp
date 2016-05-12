# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'srp/version'

Gem::Specification.new do |spec|
  spec.name          = 'srp-rb'
  spec.version       = SRP::VERSION
  spec.authors       = ['lamikae']
  spec.email         = ['']

  spec.required_ruby_version = '>= 2.1.0'

  spec.summary       = 'Secure Remote Password protocol SRP-6a'
  spec.description   = <<-EOF
    Ruby implementation of the Secure Remote Password protocol (SRP-6a).
    SRP is a cryptographically strong authentication protocol for
    password-based, mutual authentication over an insecure network connection.
  EOF

  spec.homepage      = 'https://github.com/lamikae/srp-rb'

  # http://spdx.org/licenses/BSD-3-Clause.html
  spec.license       = 'BSD-3-Clause'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  # See : https://bugs.ruby-lang.org/issues/9569
  spec.add_dependency 'rbnacl-libsodium', '~> 1.0'
  spec.add_dependency 'securer_randomer', '~> 0.1.0'

  spec.add_development_dependency 'bundler', '~> 1.12'
  spec.add_development_dependency 'rake', '~> 11.0'
  spec.add_development_dependency 'rspec', '~> 3.4'
  spec.add_development_dependency 'pry', '~> 0.10'
end
