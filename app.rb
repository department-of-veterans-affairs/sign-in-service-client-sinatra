# frozen_string_literal: true

# Add lib and helpers to load path
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'lib'))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'helpers'))

require_relative 'config/environment'
require 'logger'
require 'pkce'
require 'jwt'
require 'sign_in_service'
require 'sinatra'
require 'sinatra/custom_logger'
require 'sinatra/namespace'
require 'sinatra/cookies'
require 'sinatra/cookie_header_helper'
require 'sinatra/flash_helper'
require 'sinatra/reloader' if development?
require 'pry' if development?
require 'timeout'

# Enable test mode if TEST_MODE is set
ENV['SIS_TEST_MODE'] = ENV['TEST_MODE'] if ENV['TEST_MODE']

# Rest of the app code...
