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
  flash(:error, 'Sign in to access this page') if !current_user && @current_user.nil?

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

    response.headers['set-cookie'] = parse_cookie_header(sis_response.headers['set-cookie'])
    flash(:notice, 'You have successfully signed in')

    redirect '/'
  end

  post '/refresh' do
    return unless cookies[:vagov_refresh_token]

    sis_response = SignInService.client.refresh_token(refresh_token: cookies[:vagov_refresh_token],
                                                      anti_csrf_token: cookies[:vagov_anti_csrf_token])

    store_cookie_header(cookie_header: sis_response.headers['set-cookie'])
  end

  post '/logout' do
    sis_response = SignInService.client.logout(access_token: cookies[:vagov_access_token],
                                               anti_csrf_token: cookies[:vagov_anti_csrf_token])

    redirect to sis_response.headers['location'] if sis_response.status == 302

    clear_session

    flash(:notice, 'You have successfully signed out')
    redirect to '/'
  end

  get '/logout_callback' do
    clear_session

    flash(:notice, 'You have successfully signed out')
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
    @current_user ||= find_current_user
  end

  def find_current_user
    session[:current_user] = if session[:current_user] && valid_access_token?
                               session[:current_user]
                             elsif valid_access_token?
                               introspect
                             else
                               clear_session
                               nil
                             end
  end

  def introspect
    return if cookies[:vagov_access_token].nil?
    return session[:current_user] unless session[:current_user].nil?

    sis_response = SignInService.client.introspect(access_token: cookies[:vagov_access_token])

    JSON.parse(sis_response.body, symbolize_names: true)[:data][:attributes]
  end

  def parse_cookie_header(cookie_header)
    cookie_header.split(/, (?=[^;]+=[^;]+;)/)
  end

  def flash(type, message)
    return unless session[:flash_error].nil? && session[:flash_notice].nil?

    session[:"flash_#{type}"] = message
  end

  def cookie_auth?
    SignInService.client.cookie_auth?
  end

  def api_auth?
    SignInService.client.api_auth?
  end

  def valid_access_token?
    cookies[:vagov_access_token] && Time.now.utc < access_token_expiration
  end

  def valid_refresh_token?
    return false if refresh_token_expiration.nil?

    Time.now.utc < refresh_token_expiration
  end

  def access_token_expiration
    @access_token_expiration ||= info_token&.fetch(:access_token_expiration)
  end

  def refresh_token_expiration
    @refresh_token_expiration ||= info_token&.fetch(:refresh_token_expiration)
  end

  def info_token
    @info_token ||= parse_info_token_cookie
  end

  # TODO: Replae this once the cookie value is changed to a JSON object
  def parse_info_token_cookie
    return unless cookies[:vagov_info_token]

    info_token = cookies[:vagov_info_token].gsub(
      /\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2}\.\d{6}\d{3} \w{3} \+\d{2}:\d{2}/, &:dump
    )
    info_token_hash = eval(info_token.gsub(/(:\s*)?([a-zA-Z_]+)\s*=>/, '"\2":')) # rubocop:disable Security/Eval
    info_token_hash.transform_values!(&Time.method(:parse))
  end

  def clear_session
    session.delete(:current_user)
    session.delete(:code_verifier)
    cookies.delete(:vagov_access_token)
    cookies.delete(:vagov_refresh_token)
    cookies.delete(:vagov_anti_csrf_token)
    cookies.delete(:vagov_info_token)
  end
end

error SignInService::Error do
  error_message = "Sign In Service Error: #{env['sinatra.error'].message}"
  flash(:error, error_message)
  erb :index
end
