# frozen_string_literal: true

require 'sinatra/base'
require 'sinatra/cookies'
require 'sign_in_service'

module Sinatra
  module CookieHeaderHelper
    def store_cookie_header(cookie_header:)
      cookie_header = cookie_header.split(/, (?=[^;]+=[^;]+;)/).map { |c| Rack::Utils.parse_cookies_header(c) }

      cookie_header.each do |cookie|
        name = cookie.keys.first

        options = {
          value: cookie[name],
          domain: cookie['domain'],
          path: name == 'vagov_refresh_token' ? '/auth/refresh' : cookie['path'],
          expires: Time.parse(cookie['expires']),
          httponly: cookie.key?('HttpOnly'),
          same_site: cookie['SameSite']
        }

        response.set_cookie(name, options)
      end
    end
  end
  helpers CookieHeaderHelper
end
