# frozen_string_literal: true

module SignInService
  class Config
    AUTH_TYPES = ['cookie', 'api'].freeze
    AUTH_FLOWS = ['pkce'].freeze

    attr_accessor :base_url, :client_id, :auth_type, :auth_flow, :redirect_uri, :test_mode

    def initialize
      @base_url = ENV['VETS_API_URL'] || 'http://localhost:3000'
      @client_id = ENV['CLIENT_ID'] || 'load_test_client'
      @auth_type = ENV['AUTH_TYPE'] || 'cookie'
      @auth_flow = ENV['AUTH_FLOW'] || 'pkce'
      @redirect_uri = ENV['REDIRECT_URI'] || 'http://localhost:4567/auth/callback'
      @test_mode = (ENV['TEST_MODE'] || 'false').downcase == 'true'

      validate_config!
    end

    def to_h
      {
        base_url: base_url,
        client_id: client_id,
        auth_type: auth_type,
        auth_flow: auth_flow,
        redirect_uri: redirect_uri,
        test_mode: test_mode
      }
    end

    private

    def validate_config!
      unless AUTH_TYPES.include?(@auth_type)
        raise ArgumentError, "invalid auth type: #{@auth_type}"
      end

      unless AUTH_FLOWS.include?(@auth_flow)
        raise ArgumentError, "invalid auth flow: #{@auth_flow}"
      end
    end
  end
end
