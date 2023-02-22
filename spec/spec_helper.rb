# frozen_string_literal: true

require 'rspec'
require 'rack/test'
require 'webmock/rspec'
require 'pry'

ENV['APP_ENV'] = 'test'

require_relative '../app'

module RSpecMixin
  include Rack::Test::Methods

  def app
    described_class
  end
end

RSpec.configure do |config|
  config.include RSpecMixin
  config.disable_monkey_patching!
end
