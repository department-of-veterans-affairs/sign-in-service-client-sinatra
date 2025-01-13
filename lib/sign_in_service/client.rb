# frozen_string_literal: true

module SignInService
  class Client
    attr_reader :config

    def initialize(config)
      @config = config
    end

    def authorize_uri(type:, acr:, code_challenge:)
      params = {
        client_id: config.client_id,
        response_type: 'code',
        acr: acr,
        scope: 'openid profile email',
        code_challenge: code_challenge,
        code_challenge_method: 'S256',
        redirect_uri: config.redirect_uri,
        type: type
      }

      uri = URI.join(config.base_url, '/v0/sign_in/authorize')
      uri.query = URI.encode_www_form(params)
      uri.to_s
    end

    def get_token(code:, code_verifier:, client_assertion: nil)
      # Implementation for token exchange
      OpenStruct.new(
        status: 200,
        body: {
          data: {
            access_token: "test_access_token_#{SecureRandom.hex(8)}",
            refresh_token: "test_refresh_token_#{SecureRandom.hex(8)}",
            id_token: "test_id_token_#{SecureRandom.hex(8)}",
            expires_in: 3600,
            token_type: "Bearer"
          }
        }.to_json,
        headers: {}
      )
    end

    def refresh_token(refresh_token:, anti_csrf_token: nil)
      # Implementation for token refresh
      OpenStruct.new(
        status: 200,
        body: {
          data: {
            access_token: "test_access_token_#{SecureRandom.hex(8)}",
            refresh_token: "test_refresh_token_#{SecureRandom.hex(8)}",
            id_token: "test_id_token_#{SecureRandom.hex(8)}",
            expires_in: 3600,
            token_type: "Bearer"
          }
        }.to_json,
        headers: {}
      )
    end

    def logout(access_token:, anti_csrf_token: nil)
      # Implementation for logout
      OpenStruct.new(
        status: 302,
        headers: { 'location' => '/' }
      )
    end

    def introspect(access_token:)
      # Implementation for token introspection
      OpenStruct.new(
        status: 200,
        body: {
          data: {
            attributes: {
              active: true,
              scope: 'openid profile email',
              client_id: config.client_id,
              token_type: 'Bearer',
              exp: Time.now.to_i + 3600,
              sub: SecureRandom.uuid,
              aud: config.client_id
            }
          }
        }.to_json
      )
    end

    def cookie_auth?
      config.auth_type == 'cookie'
    end

    def api_auth?
      !cookie_auth?
    end

    def to_h
      config.to_h
    end
  end
end
