# frozen_string_literal: true

module SignInService
  class Error < StandardError; end
  class ConfigurationError < Error; end
  class AuthorizationError < Error; end
  class TokenError < Error; end
end
