# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Sinatra::CookieHeaderHelper do
  include Rack::Test::Methods

  let(:app) do
    Class.new(Sinatra::Base) do
      helpers Sinatra::CookieHeaderHelper

      get '/test' do
        store_cookie_header(cookie_header: request.env['HTTP_COOKIE'])
        'Test'
      end
    end
  end

  # Faraday sets multiple cookies in a single
  # header separated by a comma and space
  let(:set_cookie_header) { cookies.join(', ') }
  let(:cookies) do
    [vagov_access_token_cookie, vagov_refresh_token_cookie, vagov_anti_csrf_token_cookie, vagov_info_token]
  end

  let(:vagov_access_token_cookie) do
    "vagov_access_token=#{SecureRandom.hex}; path=/; expires=Tue, 14 Mar 2023 16:43:13 GMT; HttpOnly; SameSite=Lax"
  end

  let(:vagov_refresh_token_cookie) do
    "vagov_refresh_token=#{SecureRandom.hex}; "\
    'path=/auth/refresh; expires=Tue, 14 Mar 2023 16:43:13 GMT; HttpOnly; SameSite=Lax'
  end

  let(:vagov_anti_csrf_token_cookie) do
    "vagov_anti_csrf_token=#{SecureRandom.hex}; path=/; expires=Tue, 14 Mar 2023 16:43:13 GMT; HttpOnly; SameSite=Lax"
  end

  let(:vagov_info_token) do
    'vagov_info_token='\
    "#{CGI.escape({ access_token_expiration: Time.now.utc, refresh_token_expiration: Time.now.utc }.to_json)}; "\
    'domain=localhost; path=/; expires=Tue, 14 Mar 2023 16:43:13 GMT; SameSite=Lax'
  end

  describe '#store_cookie_header' do
    it 'sets the cookies in the response' do
      get '/test', nil, { 'HTTP_COOKIE' => set_cookie_header }

      expect(last_response.headers['Set-Cookie']).to eq(cookies.join("\n"))
    end
  end
end
