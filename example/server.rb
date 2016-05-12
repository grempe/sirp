#!/usr/bin/env ruby
# encoding: utf-8

require 'rubygems'
require 'bundler/setup'
require 'sinatra'
require 'json'
require 'srp'
require 'logger'
logger = Logger.new $stdout

# Set prime N length - client has to use the same value!
prime_length = 4096

# Simulate a server side user DB
users = {
  leonardo: 'capricciosa',
  raphael: 'quattro formaggi',
  donatello: 'margherita',
  michelangelo: 'tropicana'
}

user_verifiers = users.map do |username, password|
  { username => SRP::Verifier.new(prime_length).generate_userauth(username, password) }
end

user_verifiers.each { |h| users.update h }

before do
  # return all responses with this content type
  content_type 'application/json'
end

# Upon identifying to the server, the client will receive the
# salt stored on the server under the given username.
post '/authenticate' do
  username = params[:username]
  user = users[username.to_sym]

  unless user
    logger.warn "User #{username} not found"
    halt 401
  end

  # Authentication Stage 1
  if params[:A]
    logger.info "#{username} requested authentication challenge A"
    aa = params[:A]
    v = user[:verifier]
    salt = user[:salt]

    # Server generates B, saves A and B to database
    verifier = SRP::Verifier.new(prime_length)
    session = verifier.get_challenge_and_proof(username, v, salt, aa)

    # Server has to persist proof to authenticate the client response later.
    user[:session_proof] = session[:proof]

    # Server sends the challenge containing salt and B to client.
    return JSON.generate(session[:challenge])

  # Authentication Stage 2
  elsif params[:M]
    logger.info "#{username} provided challenge response M"
    client_M = params[:M]
    logger.info "client M: #{client_M}"

    # Retrieve previously stored proof from the database
    proof = user[:session_proof]

    # Instantiate a new verifier on the server.
    verifier = SRP::Verifier.new(prime_length)

    # Verify challenge response M, and store results in verifier instance
    server_H_AMK = verifier.verify_session(proof, client_M)
    logger.info "server M: #{verifier.M}"

    if server_H_AMK
      # Authenticated!
      logger.info "#{username} authenticated"
      logger.info "server H_AMK: #{server_H_AMK}"
      logger.info "Client and server have negotiated shared secret K: #{verifier.K}"
      return JSON.generate(H_AMK: server_H_AMK)
    end
  end

  halt 401
end
