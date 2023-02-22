# frozen_string_literal: true

require 'dotenv/load'
require 'logger'
require 'sinatra'
require 'sinatra/custom_logger'
require 'pry' if development?

set :erb, escape_html: true
set :logger, Logger.new($stdout)
enable :sessions

get '/' do
  'Sign In Service (SiS) Client'
end
