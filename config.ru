# frozen_string_literal: true

require 'logger'
require './app'

# Simple request logging middleware
class SimpleLogger
  def initialize(app)
    @app = app
    @logger = Logger.new($stdout)
    @logger.level = Logger::DEBUG
  end

  def call(env)
    start = Time.now
    @logger.debug "Starting #{env['REQUEST_METHOD']} #{env['PATH_INFO']}"
    
    status, headers, body = @app.call(env)
    
    duration = ((Time.now - start) * 1000).round(2)
    @logger.debug "Completed #{env['REQUEST_METHOD']} #{env['PATH_INFO']} with #{status} in #{duration}ms"
    
    [status, headers, body]
  rescue => e
    @logger.error "Error processing request: #{e.message}"
    @logger.error e.backtrace.join("\n")
    raise
  end
end

use SimpleLogger
run Sinatra::Application
