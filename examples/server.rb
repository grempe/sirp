#!/usr/bin/env ruby
# encoding: utf-8

require 'rubygems'
require 'bundler/setup'
require 'sinatra'
require 'json'
require 'sirp'
require 'logger'
logger = Logger.new $stdout

# Sinatra : Use Puma
configure { set :server, :puma }

# Set prime N length - client has to use the same value!
prime_length = 4096

# Simulated DB
users = {
  leonardo: 'capricciosa',
  raphael: 'quattro formaggi',
  donatello: 'margherita',
  michelangelo: 'tropicana'
}

user_verifiers = users.map do |username, password|
  { username => SIRP::Verifier.new(prime_length).generate_userauth(username.to_s, password) }
end

user_verifiers.each { |h| users.update h }

before do
  content_type 'application/json'
  response['Access-Control-Allow-Origin'] = '*'
end

post '/authenticate' do
  username = params[:username]
  user = users[username.to_sym]

  unless user
    logger.warn "User #{username} not found"
    halt 401
  end

  if params[:A]
    logger.info 'P1 : Starting'
    logger.info "P1 : Server received username '#{username}' and A"
    logger.info "P1 : Client A : #{params[:A]}"
    aa = params[:A]
    v = user[:verifier]
    salt = user[:salt]

    # Server generates B, saves A and B to database
    verifier = SIRP::Verifier.new(prime_length)
    session = verifier.get_challenge_and_proof(username, v, salt, aa)

    logger.info 'P1 : Server persisting user verifier (proof)'
    user[:session_proof] = session[:proof]

    logger.info 'P1 : Server sending salt and B'
    logger.info "P1 : Server salt : #{session[:challenge][:salt].length} : #{session[:challenge][:salt]}"
    logger.info "P1 : Server B : #{session[:challenge][:B].length} : #{session[:challenge][:B]}"
    return JSON.generate(session[:challenge])
  elsif params[:M]
    logger.info 'P2 : Starting'
    logger.info "P2 : Server received username '#{username}' and client M"
    client_M = params[:M]
    logger.info "P2 : Client M : #{client_M.length} : #{client_M}"

    logger.info 'P2 : Retrieving verifier from the database'
    proof = user[:session_proof]

    logger.info 'P2 : Verifying client/server M match, generating H_AMK'
    verifier = SIRP::Verifier.new(prime_length)
    server_H_AMK = verifier.verify_session(proof, client_M)
    logger.info "P2 : server M: #{verifier.M}"

    if server_H_AMK
      logger.info "P2 : #{username} Authenticated!"
      logger.info "P2 : Client and server negotiated shared key K : #{verifier.K}"
      logger.info "P2 : Server sending final H_AMK : #{server_H_AMK.length} : #{server_H_AMK}"
      return JSON.generate(H_AMK: server_H_AMK)
    end
  end

  halt 401
end
