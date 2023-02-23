# frozen_string_literal: true

require 'spec_helper'
require_relative '../app'

RSpec.describe 'SiS Client App' do
  describe 'GET /' do
    it 'returns a 200 OK status' do
      get '/'

      expect(last_response).to be_ok
    end
  end

  describe 'GET /api/heath' do
    let(:expected_body) { { alive: true }.to_json }

    context 'when the app is healthy' do
      it 'responds OK with alive body' do
        get '/api/health'

        expect(last_response).to be_ok
        expect(last_response.body).to eq(expected_body)
      end
    end
  end
end
