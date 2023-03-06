# frozen_string_literal: true

require 'dotenv/load'
require 'logger'
require 'pkce'
require 'sign_in_service'
require 'sinatra'
require 'sinatra/custom_logger'
require 'sinatra/namespace'
require 'sinatra/cookies'
require 'sinatra/cookie_header_helper'
require 'pry' if development?

set :erb, escape_html: true
set :logger, Logger.new($stdout)
set :show_exceptions, :after_handler

set :session_secret, ENV.fetch('SESSION_SECRET', SecureRandom.hex(32))
enable :sessions

get '/' do
  erb :login
end

get '/user' do
  sis_response = SignInService.client.introspect(access_token: cookies[:vagov_access_token])

  sis_response.body
end

namespace '/auth' do
  post '/request' do
    pkce = Pkce.new
    session[:code_verifier] = pkce.code_verifier

    uri = SignInService.client.authorize_uri(type: params[:type], acr: params[:acr],
                                             code_challenge: pkce.code_challenge)

    redirect to uri
  end

  get '/result' do
    sis_response = SignInService.client.get_token(code: params[:code], code_verifier: session[:code_verifier])

    response.headers['set-cookie'] = parse_cookie_header(sis_response.headers['set-cookie'])
    redirect '/user'
  end

  post '/refresh' do
    return unless cookies[:vagov_refresh_token]

    sis_response = SignInService.client.refresh_token(refresh_token: cookies[:vagov_refresh_token],
                                                      anti_csrf_token: cookies[:vagov_anti_csrf_token])

    store_cookie_header(cookie_header: sis_response.headers['set-cookie'])
  end

  get '/logout' do
    sis_response = SignInService.client.logout(access_token: cookies[:vagov_access_token],
                                               anti_csrf_token: cookies[:vagov_anti_csrf_token])
    redirect sis_response.headers['location']

    # TODO: move this to the logout callback once redirect proxy set up
    # session.clear
    # cookies.clear
  end
end

namespace '/api' do
  before do
    content_type 'application/json'
  end

  get '/health' do
    { alive: true }.to_json
  end
end

helpers do
  def parse_cookie_header(cookie_header)
    cookie_header.split(/, (?=[^;]+=[^;]+;)/)
  end
end

error SignInService::Error do
  "Sign In Service Error: #{env['sinatra.error'].message}"
end
