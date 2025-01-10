# frozen_string_literal: true

module SignInService
  class Config
    DEFAULT_BASE_URL = 'http://localhost:3000'
    DEFAULT_CLIENT_ID = 'load_test_client'
    DEFAULT_AUTH_TYPE = :api
    DEFAULT_AUTH_FLOW = :pkce
    DEFAULT_REDIRECT_URI = 'http://localhost:4567/auth/callback'

    attr_accessor :base_url, :client_id, :redirect_uri
    attr_reader :auth_type, :auth_flow

    def initialize
      load_from_env
    end

    def auth_type=(value)
      raise ArgumentError, "invalid auth type: #{value}" unless AUTH_TYPES.include?(value)
      @auth_type = value
    end

    def auth_flow=(value)
      raise ArgumentError, "invalid auth flow: #{value}" unless AUTH_FLOWS.include?(value)
      @auth_flow = value
    end

    private

    def load_from_env
      require 'dotenv'
      # Load .env first as defaults
      Dotenv.load('.env') if File.exist?('.env')
      # Then load .env.local for local overrides
      Dotenv.load('.env.local') if File.exist?('.env.local')

      # Command line variables take precedence over everything
      @base_url = ENV['SIS_BASE_URL'] || DEFAULT_BASE_URL
      @client_id = ENV['SIS_CLIENT_ID'] || DEFAULT_CLIENT_ID
      @auth_type = (ENV['SIS_AUTH_TYPE'] || DEFAULT_AUTH_TYPE).to_sym
      @auth_flow = (ENV['SIS_AUTH_FLOW'] || DEFAULT_AUTH_FLOW).to_sym
      @redirect_uri = ENV['SIS_REDIRECT_URI'] || DEFAULT_REDIRECT_URI
    end
  end
end
