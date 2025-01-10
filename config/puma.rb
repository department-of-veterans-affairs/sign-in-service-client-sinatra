# frozen_string_literal: true

require 'dotenv'
Dotenv.load('.env.local', '.env')

# Thread configuration
threads_count = ENV.fetch('PUMA_THREADS', 5).to_i
threads threads_count, threads_count

# Server configuration
port = ENV.fetch('PUMA_PORT', 4567)

# Set environment
env = ENV.fetch('APP_ENV', 'development')
environment env

# Development settings
if env == 'development'
  # Use single worker in development for easier debugging
  workers 0
  
  # Enable request logging
  log_requests true
  
  # Debug output
  debug
else
  # Production settings
  workers ENV.fetch('WORKERS', 3).to_i
end

# Preload app for better performance
preload_app!

# Log startup information
puts "Puma starting in #{env} environment"
puts "* Port: #{port}"
puts "* Environment: #{env}"
puts "* Workers: #{env == 'development' ? 0 : ENV.fetch('WORKERS', 3)}"
puts "* Threads: #{threads_count}"

# Bind after everything else is set up
bind "tcp://0.0.0.0:#{port}"
