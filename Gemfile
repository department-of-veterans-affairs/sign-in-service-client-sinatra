# frozen_string_literal: true

git_source(:github) { |repo_name| "https://github.com/#{repo_name}.git" }

source 'https://rubygems.org'

gem 'dotenv'
gem 'faraday'
gem 'httparty'
gem 'puma'
gem 'rake'
gem 'sinatra'
gem 'sinatra-contrib'

group :test do
  gem 'rack-test'
  gem 'rspec'
  gem 'webmock'
end

group :development, :test do
  gem 'pry-byebug'
  gem 'rubocop', require: false
  gem 'rubocop-rake', require: false
  gem 'rubocop-rspec', require: false
end
