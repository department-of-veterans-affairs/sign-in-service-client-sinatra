# frozen_string_literal: true

require 'sinatra/base'

module Sinatra
  module FlashHelper
    def flash
      @flash ||= Flash.new(session)
    end

    class Flash
      attr_reader :session

      def initialize(session)
        @session = session
        @session[:flash] ||= {}
      end

      def [](type)
        message(type)
      end

      def []=(type, message)
        session[:flash][type] ||= message
      end

      def message(type)
        message = session[:flash].delete(type)
        session[:flash] = {} unless message.to_s.empty?
        message
      end
    end
  end
  helpers FlashHelper
end
