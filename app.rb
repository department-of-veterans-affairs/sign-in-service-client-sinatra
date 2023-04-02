# frozen_string_literal: true

require 'dotenv/load'
require 'logger'
require 'pkce'
require 'jwt'
require 'sign_in_service'
require 'sinatra'
require 'sinatra/custom_logger'
require 'sinatra/namespace'
require 'sinatra/cookies'
require 'sinatra/cookie_header_helper'
require 'sinatra/flash_helper'
require 'pry' if development?

set :erb, escape_html: true
set :logger, Logger.new($stdout)
set :show_exceptions, :after_handler

use Rack::Session::Cookie, key: 'rack.session',
                           path: '/',
                           secret: ENV.fetch('SESSION_SECRET', SecureRandom.hex(32))

get '/' do
  flash[:error] = 'Sign in to access this page' if current_user.nil?

  erb :index
end

namespace '/auth' do
  post '/request' do
    pkce = Pkce.new
    session[:code_verifier] = pkce.code_verifier

    authorize_uri = SignInService.client.authorize_uri(type: params[:type], acr: params[:acr],
                                                       code_challenge: pkce.code_challenge)

    redirect to authorize_uri
  end

  get '/result' do
    sis_response = SignInService.client.get_token(code: params[:code], code_verifier: session[:code_verifier])

    store_tokens(sis_response)

    flash[:notice] = 'You have successfully signed in'
    redirect to '/'
  end

  post '/refresh' do
    refresh_session
  end

  post '/logout' do
    sis_response = SignInService.client.logout(access_token:, anti_csrf_token:)

    flash[:notice] = 'You have successfully signed out'
    clear_session

    redirect to sis_response.headers['location'] if sis_response.status == 302
    redirect to '/'
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
  def current_user
    @current_user = session[:current_user] ||= if session[:current_user] && valid_access_token?
                                                 session[:current_user]
                                               elsif valid_access_token?
                                                 introspect
                                               else
                                                 clear_session
                                                 nil
                                               end
  end

  def introspect
    sis_response = SignInService.client.introspect(access_token:)

    JSON.parse(sis_response.body, symbolize_names: true)[:data][:attributes]
  end

  def access_token
    if cookie_auth?
      cookies[:vagov_access_token]
    else
      session[:vagov_access_token]
    end
  end

  def refresh_token
    if cookie_auth?
      cookies[:vagov_refresh_token]
    else
      session[:vagov_refresh_token]
    end
  end

  def anti_csrf_token
    if cookie_auth?
      cookies[:vagov_anti_csrf_token]
    else
      session[:vagov_anti_csrf_token]
    end
  end

  def info_token
    return unless cookie_auth? && cookies[:vagov_info_token]

    @info_token ||= JSON.parse(cookies[:vagov_info_token], symbolize_names: true)
  end

  def valid_access_token?
    return false if access_token.nil? || access_token_expiration.nil?

    Time.now.utc < access_token_expiration
  end

  def valid_refresh_token?
    return false if refresh_token_expiration.nil?

    Time.now.utc < refresh_token_expiration
  end

  def access_token_expiration
    @access_token_expiration ||= if cookie_auth?
                                   Time.parse(info_token&.fetch(:access_token_expiration)).utc
                                 else
                                   Time.at(JWT.decode(access_token, nil, false).first['exp']).utc
                                 end
  end

  def refresh_token_expiration
    return unless cookie_auth? && info_token

    @refresh_token_expiration ||= Time.parse(info_token&.fetch(:refresh_token_expiration))
  end

  def cookie_auth?
    SignInService.client.cookie_auth?
  end

  def api_auth?
    SignInService.client.api_auth?
  end

  def refresh_api_session
    return if refresh_token.nil?

    sis_response = SignInService.client.refresh_token(refresh_token:, anti_csrf_token:)

    store_tokens(sis_response)
  end

  def store_tokens(sis_response)
    if cookie_auth?
      response.headers['set-cookie'] = parse_cookie_header(sis_response.headers['set-cookie'])
    else
      body = JSON.parse(sis_response.body, symbolize_names: true)[:data]
      session[:vagov_access_token] = body[:access_token]
      session[:vagov_refresh_token] = body[:refresh_token]
    end
  end

  def parse_cookie_header(cookie_header)
    cookie_header.split(/, (?=[^;]+=[^;]+;)/)
  end

  def clear_session
    session.delete(:current_user)
    session.delete(:code_verifier)
    session.delete(:vagov_access_token)
    session.delete(:vagov_refresh_token)
    session.delete(:vagov_anti_csrf_token)
    cookies.delete(:vagov_access_token)
    cookies.delete(:vagov_refresh_token)
    cookies.delete(:vagov_anti_csrf_token)
    cookies.delete(:vagov_info_token)
  end
end

error SignInService::Error do
  error_message = "Sign In Service Error: #{env['sinatra.error'].message}"
  flash[:error] = error_message
  erb :index
end
