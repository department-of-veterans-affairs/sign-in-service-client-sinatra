# frozen_string_literal: true

require 'faraday'

require_relative 'client/authorize'
require_relative 'client/session'
require_relative 'response/raise_error'

module SignInService
  class Client
    include SignInService::Client::Authorize
    include SignInService::Client::Session

    attr_accessor :base_url, :client_id, :token_type

    def initialize(base_url:, client_id:, token_type: :cookie)
      @base_url = base_url
      @client_id = client_id
      @token_type = token_type
    end

    def grant_type
      'authorization_code'
    end

    def code_challenge_method
      'S256'
    end

    def connection
      @connection ||= Faraday.new(base_url) do |conn|
        conn.request :url_encoded
        conn.adapter Faraday.default_adapter
        conn.use SignInService::Response::RaiseError
      end
    end

    def bearer_token_type?
      token_type.to_sym == BEARER_TOKEN_TYPE
    end

    def cookie_token_type?
      token_type.to_sym == COOKIE_TOKEN_TYPE
    end
  end
end
