#!/usr/bin/env ruby
# encoding: utf-8

require 'rubygems'
require 'bundler/setup'
require 'http'
require 'json'
require 'sirp'
require 'logger'
logger = Logger.new $stdout

server_addr  = 'http://localhost:4567/authenticate'
username     = 'leonardo'
password     = 'capricciosa'
prime_length = 4096

# The salt and verifier should be stored on the server database.
# In this example code these values are hard-coded in server.rb
# @auth = SIRP::Verifier.new(prime_length).generate_userauth(username, password)
# @auth is a hash containing :username, :verifier and :salt

logger.info 'Start authentication'

client = SIRP::Client.new(prime_length)
A = client.start_authentication

logger.info "Sending username: '#{username}' and A: '#{A}' to server"

# Client => Server: username, A
# Server => Client: salt, B
response = HTTP.post(server_addr, form: { username: username, A: A }).parse
logger.info "Server responded with: '#{response}'"

logger.info 'Client is calculating M, from B and salt, as a response to the challenge'
client_M = client.process_challenge(username, password, response['salt'], response['B'])

# Client => Server: username, M
# Server => Client: H(AMK)
logger.info "Client is sending M: '#{client_M}' to server"
response = HTTP.post(server_addr, form: { username: username, M: client_M }).parse
logger.info "Server responded with: #{response}"

if client.verify(response['H_AMK'])
  logger.info 'Client verification of server H_AMK has succeeded! Authenticated!'
  logger.info "Client and server have negotiated shared secret K: '#{client.K}'"
else
  logger.error 'Client verification of server H_AMK has failed!'
end
