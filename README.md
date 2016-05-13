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
