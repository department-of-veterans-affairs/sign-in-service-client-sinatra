# SignInService Ruby Client

The SignInService Ruby client provides a simple and convenient way to interact with the SignInService API for handling OAuth flows.

## Configuration

Configure the SignInService client with your base URL, client ID, and authentication type in an initializer:

```ruby
require 'sign_in_service'

SignInService.configure do |config|
  config.base_url = 'https://your_sign_in_service_url'
  config.client_id = 'your_client_id'
  config.auth_type = :cookie # or :api
end
```

### Auth Types: Cookie vs API
The SignInService client supports two authentication types: Cookie and API.

#### Cookie Authentication
With Cookie authentication, tokens are returned in the `Set-Cookie` headers of the response. This approach is typically used in web applications where cookies can be stored and managed directly by the browser.

#### API Authentication
With API authentication, tokens are returned in the response body. This approach is typically used in non-web applications or scenarios where the application handles the tokens directly, such as mobile apps, desktop apps, or server-side scripts.

### Endpoints

#### Authorization
- [Authorize](sign_in_service_ruby_client/endpoints/authorize.md) - Initiate the OAuth flow
- [Token](sign_in_service_ruby_client/endpoints/token.md) - Exchange authorization code for session tokens

#### Session Management
- [Refresh](sign_in_service_ruby_client/endpoints/refresh.md) - Refresh session tokens.
- [Introspect](sign_in_service_ruby_client/endpoints/introspect.md) - Retrieve user data associated with an access token.
- [Logout](sign_in_service_ruby_client/endpoints/logout.md) - Log out the user and revoke tokens.
- [Revoke Token](sign_in_service_ruby_client/endpoints/revoke_token.md) - Revoke a sessions tokens.
- [Revoke All Sessions](sign_in_service_ruby_client/endpoints/revoke_all_sessions.md) - Revoke all sessions associated with a user
