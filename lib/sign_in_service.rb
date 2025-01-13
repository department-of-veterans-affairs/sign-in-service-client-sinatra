# frozen_string_literal: true

require_relative 'sign_in_service/error'
require_relative 'sign_in_service/config'
require_relative 'sign_in_service/client'

module SignInService
  COOKIE_TOKEN_PREFIX = 'vagov'
  AUTH_TYPES = [COOKIE_AUTH = :cookie, API_AUTH = :api].freeze
  AUTH_FLOWS = [PKCE_FLOW = :pkce].freeze
  TEST_MODE = (ENV['SIS_TEST_MODE'] || 'false').downcase == 'true'

  class << self
    def configure
      @config = Config.new
      yield(@config) if block_given?
      @config
    end

    def config
      @config ||= Config.new
    end

    def client
      @client ||= Client.new(config)
    end

    def reset!
      @client = nil
      @config = nil
    end
  end
end
