# frozen_string_literal: true

require 'dotenv/load'
require 'logger'
require 'sinatra'
require 'sinatra/custom_logger'
require "sinatra/namespace"
require 'pry' if development?

set :erb, escape_html: true
set :logger, Logger.new($stdout)
enable :sessions

get '/' do
  'Sign In Service (SiS) Client'
end

namespace '/api' do
  before do
    content_type 'application/json'
  end

  get '/health' do
    {
      healthy: 'true'
    }.to_json
  end
  rescue StandardError => e
    halt 500, {
      error: e.inspect,
      healthy: false,
    }.to_json
end
