# frozen_string_literal: true

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '../helpers'))

require 'rspec'
require 'rack/test'
require 'webmock/rspec'
require 'pry'
require 'sign_in_service'
require_relative '../app'

ENV['APP_ENV'] = 'test'

RSpec.configure(&:disable_monkey_patching!)
