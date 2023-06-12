# frozen_string_literal: true

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'lib'))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'helpers'))

require './app'
require 'sign_in_service'

SignInService.configure do |config|
  config.base_url = ENV.fetch('SIS_BASE_URL')
  config.client_id = ENV.fetch('SIS_CLIENT_ID')
  config.auth_type = ENV.fetch('SIS_AUTH_TYPE').to_sym

  config.auth_flow = ENV.fetch('SIS_AUTH_FLOW').to_sym
end

run Sinatra::Application
