# frozen_string_literal: true

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'lib'))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'helpers'))

require './app'
require 'sign_in_service'
require 'dotenv/load'

SignInService.configure do |config|
  config.base_url = ENV.fetch('SIS_BASE_URL')
  config.client_id = ENV.fetch('SIS_CLIENT_ID')
end

run Sinatra::Application
