require 'dotenv'

# Load environment variables from .env first as defaults
Dotenv.load('.env')

# Then load .env.local, allowing it to override .env but not command line values
Dotenv.overload('.env.local') if File.exist?('.env.local')

# Set the environment
ENV['RACK_ENV'] ||= 'development'

# Configure SignInService
require_relative '../lib/sign_in_service'

SignInService.configure do |config|
  # The Config class now handles environment variables internally
  config.base_url = config.base_url  # This will use the value loaded from environment
  config.client_id = config.client_id
  config.auth_type = config.auth_type
  config.auth_flow = config.auth_flow
  config.redirect_uri = config.redirect_uri
end

# Verify configuration
puts "SignInService Configuration:"
puts "  Base URL: #{SignInService.config.base_url}"
puts "  Client ID: #{SignInService.config.client_id}"
puts "  Auth Type: #{SignInService.config.auth_type}"
puts "  Auth Flow: #{SignInService.config.auth_flow}"
puts "  Redirect URI: #{SignInService.config.redirect_uri}" 