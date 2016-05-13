# SiRP : Secure (interoperable) Remote Password Authentication

[![Gem Version](https://badge.fury.io/rb/sirp.svg)](https://badge.fury.io/rb/sirp)
[![Dependency Status](https://gemnasium.com/badges/github.com/grempe/sirp.svg)](https://gemnasium.com/github.com/grempe/sirp)
[![Build Status](https://travis-ci.org/grempe/sirp.svg?branch=master)](https://travis-ci.org/grempe/sirp)
[![Coverage Status](https://coveralls.io/repos/github/grempe/sirp/badge.svg?branch=master)](https://coveralls.io/github/grempe/sirp?branch=master)
[![Code Climate](https://codeclimate.com/github/grempe/sirp/badges/gpa.svg)](https://codeclimate.com/github/grempe/sirp)
[![Inline docs](http://inch-ci.org/github/grempe/sirp.svg?branch=master)](http://inch-ci.org/github/grempe/sirp)

Ruby Docs : [http://www.rubydoc.info/gems/sirp](http://www.rubydoc.info/gems/sirp)


This is a pure Ruby implementation of the
[Secure Remote Password](http://srp.stanford.edu/) protocol (SRP-6a),
which is a 'zero-knowledge' mutual authentication system.

SiRP is an authentication method that allows the use of user names and passwords
over an insecure network connection without revealing the password. If either the
client lacks the user's password or the server lacks the proper verification
key, the authentication will fail. This approach is much more secure than the
vast majority of authentication systems in daily use since the password is
***never*** sent over the wire, and is therefore impossible to intercept, and
impossible to be revealed in a breach unless the verifier can be reversed. This
attack would be of similar difficulty as deriving a private encryption key from
its public key.

Unlike other common challenge-response authentication protocols, such as
Kerberos and SSL, SiRP does not rely on an external infrastructure of trusted
key servers or complex certificate management.

## Documentation

There is pretty extensive inline documentation. You can view the latest
auto-generated docs at [http://www.rubydoc.info/gems/sirp](http://www.rubydoc.info/gems/sirp)

You can check my documentation quality score at
[http://inch-ci.org/github/grempe/sirp](http://inch-ci.org/github/grempe/sirp?branch=master)

## Supported Platforms

SiRP is continuously integration tested on the following Ruby VMs:

* MRI 2.1, 2.2, 2.3

It may work on others as well.

## Installation

Add this line to your application's `Gemfile`:

```ruby
gem 'sirp', '~> 2.0'
```

And then execute:
```sh
$ bundle
```

Or install it yourself as:

```sh
$ gem install sirp
```

### Installation Security : Signed Ruby Gem

The SiRP gem is cryptographically signed. To be sure the gem you install hasn’t
been tampered with you can install it using the following method:

Add my public key (if you haven’t already) as a trusted certificate

```
# Caveat: Gem certificates are trusted globally, such that adding a
# cert.pem for one gem automatically trusts all gems signed by that cert.
gem cert --add <(curl -Ls https://raw.github.com/grempe/sirp/master/certs/gem-public_cert_grempe.pem)
```

To install, it is possible to specify either `HighSecurity` or `MediumSecurity`
mode. Since the `sirp` gem depends on one or more gems that are not cryptographically
signed you will likely need to use `MediumSecurity`. You should receive a warning
if any signed gem does not match its signature.

```
# All dependent gems must be signed and verified.
gem install sirp -P HighSecurity
```

```
# All signed dependent gems must be verified.
gem install sirp -P MediumSecurity
```

```
# Same as above, except Bundler only recognizes
# the long --trust-policy flag, not the short -P
bundle --trust-policy MediumSecurity
```

You can [learn more about security and signed Ruby Gems](http://guides.rubygems.org/security/).

### Installation Security : Signed Git Commits

Most, if not all, of the commits and tags to the repository for this code are
signed with my PGP/GPG code signing key. I have uploaded my code signing public
keys to GitHub and you can now verify those signatures with the GitHub UI.
See [this list of commits](https://github.com/grempe/sirp/commits/master)
and look for the `Verified` tag next to each commit. You can click on that tag
for additional information.

You can also clone the repository and verify the signatures locally using your
own GnuPG installation. You can find my certificates and read about how to conduct
this verification at [https://www.rempe.us/keys/](https://www.rempe.us/keys/).

## Compatibility

This implementation has been tested for compatibility with the following SRP-6a
compliant third-party libraries:

[JSRP / JavaScript](https://github.com/alax/jsrp)

## Usage Example

In this example the client and server steps are interleaved for demonstration
purposes. See the `examples` dir for simple working client and server
implementations.

``` ruby
require 'sirp'

username     = 'user'
password     = 'password'
prime_length = 2048

# The salt and verifier should be stored on the server database.
@auth = SIRP::Verifier.new(prime_length).generate_userauth(username, password)
# @auth is a hash containing :username, :verifier and :salt

# ~~~ Begin Authentication ~~~

client = SIRP::Client.new(prime_length)
A = client.start_authentication

# Client => Server: username, A

# Server retrieves user's verifier and salt from the database.
v    = @auth[:verifier]
salt = @auth[:salt]

# Server generates challenge for the client.
verifier = SIRP::Verifier.new(prime_length)
session = verifier.get_challenge_and_proof(username, v, salt, A)

# Server has to persist proof to authenticate the client response later.
@proof = session[:proof]

# Server sends the challenge containing salt and B to client.
response = session[:challenge]

# Server => Client: salt, B

# Client calculates M as a response to the challenge.
client_M = client.process_challenge(username, password, salt, B)

# Client => Server: username, M

# Instantiate a new verifier on the server.
verifier = SIRP::Verifier.new(prime_length)

# Verify challenge response M.
# The Verifier state is passed in @proof.
server_H_AMK = verifier.verify_session(@proof, client_M)
# Is false if authentication failed.

# At this point, the client and server should have a common session key
# that is secure (i.e. not known to an outside party).  To finish
# authentication, they must prove to each other that their keys are
# identical.

# Server => Client: H(AMK)

client.verify(server_H_AMK) == true

```

## History

This gem is a fork of the [lamikae/srp-rb](https://github.com/lamikae/srp-rb)
repository created by Mikael Lammentausta [@lamikae](https://github.com/lamikae).
Significant changes were needed for my use-case which demanded breaking changes
for the sake of greater interoperability. With these factors in mind, a hard
fork seemed the most appropriate path to take. Much credit is due to Mikael for
his original implementation.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then,
run `bundle exec rake test` to run the tests. You can also run `bin/console` for an
interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`.

### Contributing

Bug reports and pull requests are welcome on GitHub
at [https://github.com/grempe/sirp](https://github.com/grempe/sirp). This
project is intended to be a safe, welcoming space for collaboration, and
contributors are expected to adhere to the
[Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Legal

### Copyright

(c) 2016 Glenn Rempe <[glenn@rempe.us](mailto:glenn@rempe.us)> ([https://www.rempe.us/](https://www.rempe.us/))

(c) 2012 Mikael Lammentausta

### License

The gem is available as open source under the terms of
the [BSD 3-clause "New" or "Revised" License](https://spdx.org/licenses/BSD-3-Clause.html).

### Warranty

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied. See the LICENSE.txt file for the
specific language governing permissions and limitations under
the License.
