# frozen_string_literal: true

require 'dotenv'
Dotenv.load('.env.local', '.env')

require 'sign_in_service'

# Configure SignInService client
SignInService.configure do |config|
  # Use vets-api URL for the base_url
  config.base_url = ENV.fetch('VETS_API_URL', 'http://localhost:3000')
  config.client_id = ENV.fetch('CLIENT_ID', 'load_test_client')
  config.auth_type = ENV.fetch('AUTH_TYPE', 'api')
  config.auth_flow = ENV.fetch('AUTH_FLOW', 'pkce')
  config.redirect_uri = ENV.fetch('REDIRECT_URI', 'http://localhost:4567/auth/callback')
  config.test_mode = ENV.fetch('SIS_TEST_MODE', 'false') == 'true'
end

# Log configuration for debugging
puts "Test Service Configuration:"
puts "  Environment: #{ENV['RACK_ENV']}"
puts "  Port: #{ENV['PORT']}"
puts "  Test Mode: #{ENV['SIS_TEST_MODE']}"
puts "\nVets API Configuration:"
puts "  Base URL: #{ENV['VETS_API_URL']}"
puts "  Client ID: #{ENV['CLIENT_ID']}"
puts "\nAuthentication Settings:"
puts "  Type: #{ENV['AUTH_TYPE']}"
puts "  Flow: #{ENV['AUTH_FLOW']}"
puts "  CSP Type: #{ENV['CSP_TYPE']}"
puts "  ACR: #{ENV['ACR']}" 