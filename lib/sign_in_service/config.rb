# frozen_string_literal: true

module SignInService
  class Config
    DEFAULT_BASE_URL = 'http://localhost:3000'
    DEFAULT_CLIENT_ID = 'sample'
    DEFAULT_TOKEN_TYPE = :cookie

    attr_accessor :base_url, :client_id
    attr_reader :token_type

    def initialize
      @base_url = DEFAULT_BASE_URL
      @client_id = DEFAULT_CLIENT_ID
      @token_type = DEFAULT_TOKEN_TYPE
    end

    def token_type=(value)
      raise ArgumentError, "invalid token type: #{value}" unless TOKEN_TYPES.include?(value)

      @token_type = value
    end
  end
end
