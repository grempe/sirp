# Secure Remote Password

This is a pure Ruby implementation of the Secure Remote Password
protocol (SRP-6a), a 'zero-knowledge' authentication system.

SRP is an authentication method that allows the use of user names and passwords
over an insecure network connection without revealing the password. If either the
client lacks the user's password or the server lacks the proper verification
key, the authentication will fail.

Unlike other common challenge-response authentication protocols, such as
Kerberos and SSL, SRP does not rely on an external infrastructure of trusted
key servers or complex certificate management.

References

*	[http://srp.stanford.edu/](http://srp.stanford.edu/)

## Usage Example

In this example the client and server steps are interleaved to demonstrate
the responsibilities each side has in the protocol. See the `example` dir for
simple working client and server implementations.

``` ruby
require 'srp'

username     = "user"
password     = "password"
prime_length = 2048

# The salt and verifier should be stored on the server database.
@auth = SRP::Verifier.new(prime_length).generate_userauth(username, password)
# @auth is a hash containing :username, :verifier and :salt

# ~~~ Begin Authentication ~~~

client = SRP::Client.new(prime_length)
A = client.start_authentication

# Client => Server: username, A

# Server retrieves user's verifier and salt from the database.
v    = @auth[:verifier]
salt = @auth[:salt]

# Server generates challenge for the client.
verifier = SRP::Verifier.new(prime_length)
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
verifier = SRP::Verifier.new(prime_length)

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

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then,
run `rake test` to run the tests. You can also run `bin/console` for an
interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`.
