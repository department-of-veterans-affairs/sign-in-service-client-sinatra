# frozen_string_literal: true

require 'rspec'
require 'rack/test'
require 'webmock/rspec'
require 'pry'
require_relative '../app'

ENV['APP_ENV'] = 'test'

module RSpecMixin
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end
end

RSpec.configure do |config|
  config.include RSpecMixin
  config.disable_monkey_patching!
end
