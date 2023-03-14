# frozen_string_literal: true

require 'sign_in_service/client'
require 'sign_in_service/config'

module SignInService
  COOKIE_TOKEN_PREFIX = 'vagov'
  TOKEN_TYPES = [COOKIE_TOKEN_TYPE = :cookie, BEARER_TOKEN_TYPE = :bearer].freeze

  class << self
    attr_accessor :config

    def client
      configure unless config

      return @client if defined?(@client) && same_config?

      @client = SignInService::Client.new(base_url: config.base_url,
                                          client_id: config.client_id,
                                          token_type: config.token_type)
    end

    def configure
      self.config ||= Config.new
      yield(config) if block_given?
    end

    def reset!
      self.config = Config.new
    end

    private

    def same_config?
      instance_variables_hash(@client) == instance_variables_hash(SignInService.config)
    end

    def instance_variables_hash(instance)
      instance.instance_variables.to_h { |k| [k, instance.instance_variable_get(k)] }
    end
  end
end
