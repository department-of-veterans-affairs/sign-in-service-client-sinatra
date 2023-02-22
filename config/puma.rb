# frozen_string_literal: true

require 'dotenv/load'

threads_count = ENV.fetch('PUMA_THREADS', 5).to_i

threads threads_count, threads_count
port ENV.fetch('PORT', 4567)
environment ENV.fetch('APP_ENV', 'development')
workers ENV.fetch('WORKERS', 3).to_i
preload_app!
