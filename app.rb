# frozen_string_literal: true

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'lib'))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'helpers'))

require_relative 'config/environment'
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
require 'sinatra/reloader' if development?
require 'pry' if development?

ENV['SIS_TEST_MODE'] = 'false' unless development?

set :erb, escape_html: true
set :logger, Logger.new($stdout)
set :show_exceptions, false
set :raise_errors, false
set :vets_api_url, ENV.fetch('VETS_API_URL', 'http://localhost:3000')
set :client_id, ENV.fetch('CLIENT_ID', 'load_test_client')

use Rack::Session::Cookie,
  key: 'rack.session',
  path: '/',
  secret: ENV.fetch('SESSION_SECRET', 'test-session-secret'),
  expire_after: 2592000, # 30 days
  secure: false, # Set to false for local testing
  httponly: true,
  same_site: :lax,
  domain: nil, # Allow cookie to be set for localhost
  sidbits: 128,
  renew: true

configure do
  enable :logging
end

puts "\nSinatra Configuration:"
puts "  Environment: #{settings.environment}"
puts "  Vets API URL: #{settings.vets_api_url}"
puts "  Client ID: #{settings.client_id}"
puts "  Test Mode: #{SignInService::TEST_MODE}"

before '/' do
  refresh_api_session if api_auth?
end

get '/' do
  @current_user = find_current_user
  erb :index
end

get '/sign_in' do
  redirect to '/profile' if session[:current_user]
  erb :sign_in
end

get '/profile' do
  @current_user = find_current_user

  if @current_user.nil?
    flash[:error] = 'Sign in to access this page'
    redirect to '/sign_in'
    return
  end

  @user_info = [
    { label: 'Full name',
      value: "#{@current_user[:first_name]} #{@current_user[:middle_name]} #{@current_user[:last_name]}" },
    { label: 'ICN', value: @current_user[:icn] },
    { label: 'ID.me UUID', value: @current_user[:idme_uuid] },
    { label: 'Login.gov UUID', value: @current_user[:logingov_uuid] },
    { label: 'UUID', value: @current_user[:uuid] },
    { label: 'Birth Date', value: @current_user[:birth_date] },
    { label: 'Email', value: @current_user[:email] },
    { label: 'Gender', value: @current_user[:gender] },
    { label: 'BIRLS ID', value: @current_user[:birls_id] },
    { label: 'EDIPI', value: @current_user[:edipi] },
    { label: 'Active MHV ID', value: @current_user[:active_mhv_ids].join(', ') },
    { label: 'SEC ID', value: @current_user[:sec_id] },
    { label: 'Vet360 ID', value: @current_user[:vet360_id] },
    { label: 'Participant ID', value: @current_user[:participant_id] },
    { label: 'Cerner ID', value: @current_user[:cerner_id] },
    { label: 'Cerner Facility IDs', value: @current_user[:cerner_facility_ids].join(', ') },
    { label: 'VHA Facility IDs', value: @current_user[:vha_facility_ids].join(', ') },
    { label: 'ID Theft Flag', value: @current_user[:id_theft_flag] ? 'Yes' : 'No' },
    { label: 'Verified', value: @current_user[:verified] ? 'Yes' : 'No' }
  ]

  @refreshable = valid_refresh_token?
  @sis_base_url = SignInService.config.base_url
  @auth_type = SignInService.config.auth_type
  @access_token_expiration = access_token_expiration
  @refresh_token_expiration = refresh_token_expiration

  erb :profile
end

namespace '/auth' do
  get '/request' do
    logger.debug "Starting GET /auth/request"
    
    begin
      # Get and validate parameters
      type = params[:type] || 'idme'
      acr = params[:acr] || 'loa3'
      
      # Log request parameters
      logger.info "Auth Request Parameters:"
      logger.info "  Type: #{type}"
      logger.info "  ACR: #{acr}"
      
      # Generate PKCE values
      code_verifier = SecureRandom.urlsafe_base64(32)
      code_challenge = Base64.urlsafe_encode64(
        OpenSSL::Digest::SHA256.digest(code_verifier),
        padding: false
      )
      
      # Store session data
      session[:code_verifier] = code_verifier
      session[:code_challenge] = code_challenge
      session[:auth_type] = type
      session[:auth_acr] = acr
      session[:state] = SecureRandom.hex(16)
      
      # Force session commit and ensure cookie is set
      session.options[:defer] = false
      session.options[:renew] = true
      
      # Log session data for debugging
      logger.info "Session Data:"
      logger.info "  Session ID: #{session.id}"
      logger.info "  Code Verifier Present: #{!session[:code_verifier].nil?}"
      logger.info "  Code Challenge Present: #{!session[:code_challenge].nil?}"
      
      # Get authorize URI from client
      authorize_uri = SignInService.client.authorize_uri(
        type: type,
        acr: acr,
        code_challenge: code_challenge
      )
      
      logger.info "Generated authorize URI: #{authorize_uri}"
      
      # Set response headers
      response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
      response.headers['Pragma'] = 'no-cache'
      
      # Set session cookie with explicit domain and path
      response.set_cookie(
        'rack.session',
        value: session.id,
        path: '/',
        expire_after: 2592000,
        httponly: true,
        secure: false,
        same_site: :lax,
        domain: nil
      )
      
      # Return HTML with meta refresh
      status 200
      content_type 'text/html'
      erb :oauth_form, locals: { authorize_uri: authorize_uri }
    rescue => e
      logger.error "Auth Request Error: #{e.message}"
      logger.error e.backtrace.join("\n")
      halt 500, { error: 'Internal Server Error', message: e.message }.to_json
    end
  end

  get '/callback' do
    begin
      if SignInService::TEST_MODE
        # Create test tokens
        test_tokens = {
          data: {
            access_token: "test_access_token_#{SecureRandom.hex(8)}",
            refresh_token: "test_refresh_token_#{SecureRandom.hex(8)}",
            id_token: "test_id_token_#{SecureRandom.hex(8)}",
            expires_in: 3600,
            token_type: "Bearer",
            type: session[:auth_type],
            acr: session[:auth_acr]
          }
        }

        # Store tokens in session
        session[:access_token] = test_tokens[:data][:access_token]
        session[:refresh_token] = test_tokens[:data][:refresh_token]
        session[:id_token] = test_tokens[:data][:id_token]
        session[:token_type] = test_tokens[:data][:token_type]
        session[:expires_in] = test_tokens[:data][:expires_in]

        # Set mock user data directly in session
        session[:current_user] = {
          first_name: 'Test',
          middle_name: 'E',
          last_name: 'User',
          icn: '123456789V123456',
          idme_uuid: SecureRandom.uuid,
          logingov_uuid: SecureRandom.uuid,
          uuid: SecureRandom.uuid,
          birth_date: '1990-01-01',
          email: 'test.user@example.com',
          gender: 'M',
          birls_id: '123456',
          edipi: '1234567890',
          active_mhv_ids: ['12345'],
          sec_id: '123456789',
          vet360_id: '123456789',
          participant_id: '123456789',
          cerner_id: '123456789',
          cerner_facility_ids: ['123'],
          vha_facility_ids: ['456'],
          id_theft_flag: false,
          verified: true
        }

        # Force session commit
        session.options[:defer] = false
        session.options[:renew] = true

        # Clean up session
        session.delete(:code_verifier)
        session.delete(:code_challenge)
        session.delete(:auth_type)
        session.delete(:auth_acr)
        session.delete(:state)

        flash[:notice] = 'You have successfully signed in'
        redirect to '/profile'
      else
        # Get necessary parameters for token exchange
        code = params[:code]
        code_verifier = session[:code_verifier]
        
        # Log callback parameters for debugging
        logger.info "Callback Parameters:"
        logger.info "  Code: #{code ? '[PRESENT]' : '[MISSING]'}"
        logger.info "  Code Verifier: #{code_verifier ? '[PRESENT]' : '[MISSING]'}"
        logger.info "  Session ID: #{session.id}"
        logger.info "  Auth Flow: #{SignInService.config.auth_flow}"
        
        if code_verifier.nil?
          logger.error "Missing code_verifier in session"
          halt 400, { error: 'Missing code_verifier', message: 'Session data not found' }.to_json
        end

        # Exchange code for tokens via vets-api
        sis_response = SignInService.client.get_token(
          code: code,
          code_verifier: code_verifier,
          client_assertion: nil
        )

        # Store tokens and user data
        store_tokens(sis_response)
        
        # Get and store user data
        user_data = introspect
        session[:current_user] = user_data if user_data

        # Force session commit
        session.options[:defer] = false
        session.options[:renew] = true

        flash[:notice] = 'You have successfully signed in'
        redirect to '/profile'
      end
    rescue => e
      logger.error "Callback Error: #{e.message}"
      logger.error e.backtrace.join("\n")
      status 500
      { error: 'Internal Server Error', message: e.message }.to_json
    end
  end

  post '/refresh' do
    begin
      # Get refresh token from session or cookies
      refresh_token_value = refresh_token
      anti_csrf_token_value = anti_csrf_token

      if refresh_token_value.nil?
        status 401
        return { error: 'No refresh token available' }.to_json
      end

      # Exchange refresh token for new tokens
      sis_response = SignInService.client.refresh_token(
        refresh_token: refresh_token_value,
        anti_csrf_token: anti_csrf_token_value
      )

      # Store new tokens
      store_tokens(sis_response)

      # Return success response
      status 200
      { message: 'Token refreshed successfully' }.to_json
    rescue => e
      logger.error "Refresh Error: #{e.message}"
      logger.error e.backtrace.join("\n")
      status 500
      { error: 'Failed to refresh token', message: e.message }.to_json
    end
  end

  get '/logout' do
    sis_response = SignInService.client.logout(access_token:, anti_csrf_token:)
    clear_session

    flash[:notice] = 'You have successfully signed out'

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
  def find_current_user
    if SignInService::TEST_MODE
      # Return mock user data in test mode if we have a test token or current_user in session
      return session[:current_user] if session[:current_user]
      return nil unless session[:access_token]&.start_with?('test_')

      mock_user = {
        first_name: 'Test',
        middle_name: 'E',
        last_name: 'User',
        icn: '123456789V123456',
        idme_uuid: SecureRandom.uuid,
        logingov_uuid: SecureRandom.uuid,
        uuid: SecureRandom.uuid,
        birth_date: '1990-01-01',
        email: 'test.user@example.com',
        gender: 'M',
        birls_id: '123456',
        edipi: '1234567890',
        active_mhv_ids: ['12345'],
        sec_id: '123456789',
        vet360_id: '123456789',
        participant_id: '123456789',
        cerner_id: '123456789',
        cerner_facility_ids: ['123'],
        vha_facility_ids: ['456'],
        id_theft_flag: false,
        verified: true
      }
      
      session[:current_user] = mock_user
      mock_user
    elsif session[:current_user] && valid_access_token?
      session[:current_user]
    elsif valid_access_token?
      session[:current_user] = introspect
    else
      clear_session
      nil
    end
  end

  def introspect
    if SignInService::TEST_MODE
      # Return mock introspection data in test mode
      {
        first_name: 'Test',
        middle_name: 'E',
        last_name: 'User',
        icn: '123456789V123456',
        idme_uuid: SecureRandom.uuid,
        logingov_uuid: SecureRandom.uuid,
        uuid: SecureRandom.uuid,
        birth_date: '1990-01-01',
        email: 'test.user@example.com',
        gender: 'M',
        birls_id: '123456',
        edipi: '1234567890',
        active_mhv_ids: ['12345'],
        sec_id: '123456789',
        vet360_id: '123456789',
        participant_id: '123456789',
        cerner_id: '123456789',
        cerner_facility_ids: ['123'],
        vha_facility_ids: ['456'],
        id_theft_flag: false,
        verified: true
      }
    else
      sis_response = SignInService.client.introspect(access_token:)
      JSON.parse(sis_response.body, symbolize_names: true)[:data][:attributes]
    end
  end

  def access_token
    if cookie_auth?
      cookies[:vagov_access_token]
    else
      session[:access_token]
    end
  end

  def refresh_token
    if cookie_auth?
      cookies[:vagov_refresh_token]
    else
      session[:refresh_token]
    end
  end

  def anti_csrf_token
    if cookie_auth?
      cookies[:vagov_anti_csrf_token]
    else
      session[:anti_csrf_token]
    end
  end

  def info_token
    return unless cookie_auth? && cookies[:vagov_info_token]
    @info_token ||= JSON.parse(cookies[:vagov_info_token], symbolize_names: true)
  end

  def valid_access_token?
    return false if access_token.nil?
    return true if SignInService::TEST_MODE && access_token.start_with?('test_')
    return false if access_token_expiration.nil?
    Time.now.utc < access_token_expiration
  end

  def valid_refresh_token?
    return false if refresh_token_expiration.nil?
    Time.now.utc < refresh_token_expiration
  end

  def access_token_expiration
    @access_token_expiration ||= if cookie_auth?
                                  Time.parse(info_token&.fetch(:access_token_expiration)).utc
                                elsif SignInService::TEST_MODE && access_token&.start_with?('test_')
                                  Time.now.utc + 3600
                                elsif access_token
                                  Time.at(JWT.decode(access_token, nil, false).first['exp']).utc
                                end
  rescue
    nil
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
    return unless api_auth? && refresh_token
    sis_response = SignInService.client.refresh_token(refresh_token:, anti_csrf_token:)
    store_tokens(sis_response)
  end

  def store_tokens(sis_response)
    if cookie_auth?
      if sis_response.headers['set-cookie']
        response.headers['set-cookie'] = parse_cookie_header(sis_response.headers['set-cookie'])
      else
        # If no set-cookie header but we have a JSON response, try to handle it as API auth
        begin
          body = JSON.parse(sis_response.body, symbolize_names: true)[:data]
          if body && body[:access_token]
            logger.info "No set-cookie header but found token in response body, storing in session"
            session[:access_token] = body[:access_token]
            session[:refresh_token] = body[:refresh_token]
            return
          end
        rescue => e
          logger.error "Failed to parse token response: #{e.message}"
          logger.error "Response body: #{sis_response.body}"
        end
        
        # If we get here, we couldn't handle the response
        halt 500, { error: 'Token exchange failed', message: 'Invalid response format' }.to_json
      end
    else
      begin
        body = JSON.parse(sis_response.body, symbolize_names: true)[:data]
        if body && body[:access_token]
          session[:access_token] = body[:access_token]
          session[:refresh_token] = body[:refresh_token]
        else
          logger.error "No tokens found in response body"
          halt 500, { error: 'Token exchange failed', message: 'No tokens in response' }.to_json
        end
      rescue => e
        logger.error "Failed to parse token response: #{e.message}"
        logger.error "Response body: #{sis_response.body}"
        halt 500, { error: 'Token exchange failed', message: 'Invalid response format' }.to_json
      end
    end
  end

  def parse_cookie_header(cookie_header)
    return [] if cookie_header.nil? || cookie_header.empty?
    cookie_header.split(/, (?=[^;]+=[^;]+;)/)
  end

  def clear_session
    session.clear
  end

  def new_encoded_jwt
    payload = {
      iss: ENV.fetch('SIS_CLIENT_ID'),
      aud: '127.0.0.1:3000/v0/sign_in/token',
      sub: ENV.fetch('SIS_CLIENT_ID'),
      jti: SecureRandom.hex,
      exp: DateTime.now.next_day(30).strftime('%s').to_i
    }

    JWT.encode(payload, OpenSSL::PKey::RSA.new(File.read('sample_client.pem')), 'RS256')
  end
end

error SignInService::Error do
  error_message = "Sign In Service Error: #{env['sinatra.error'].message}"
  flash[:error] = error_message
  erb :index
end
