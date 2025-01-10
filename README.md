**Note:** This repo is managed by the VSP-Identity team. Please reference our main product page [here](https://github.com/department-of-veterans-affairs/va.gov-team/blob/master/products/identity/README.md) for contact information and questions.

# Sign-in Service Example App

An example app built with Sinatra that interfaces with Sign-in Service.

## Dependencies
- Ruby 3.2.1

## Configuration
### Config the Sign-in Service Server
Currently, SignInService is available as a part of `vets-api`

1. Clone Repo
  ```bash
    git clone git@github.com:department-of-veterans-affairs/vets-api.git
  ```
2. Follow [setup instructions](git@github.com:department-of-veterans-affairs/vets-api.git) for vets-api
3. Ensure your database is properly seeded `rails db:seed` this will add the necessary client configurations

### Creating a New Client Configuration
If you need to create a new client configuration in vets-api:

```ruby
# In vets-api rails console
client = SignIn::ClientConfig.create!(
  client_id: 'sample_client_api',
  authentication: 'api',
  pkce: true,
  redirect_uri: 'http://localhost:4567/auth/callback',
  access_token_duration: 300,
  refresh_token_duration: 1800,
  access_token_audience: 'va.gov',
  anti_csrf: true,
  shared_sessions: true,
  service_levels: ['ial2'],
  access_token_attributes: ['first_name', 'last_name', 'email'],
  description: 'Sign In Service Example Client',
  logout_redirect_uri: 'http://localhost:4567/',
  credential_service_providers: ['idme', 'logingov']
)
```

### Configure the SignInService client
This application uses the [SignInService Ruby Client](docs/sign_in_service_ruby_client.md)

1. You will see the base config in `.env` (these match the default client config in `vets-api`)
```bash
  # .env
  SIS_CLIENT_ID='sample_client_web'
  SIS_BASE_URL='http://localhost:3000'
  SIS_AUTH_TYPE='cookie'
```
2. The default auth type for this app is `cookie`. If you want to use `api` change your config in .env.local to
the correct client and auth_type.
```bash
  # .env.local
  SIS_CLIENT_ID='sample_client_api'
  SIS_BASE_URL='http://localhost:3000'
  SIS_AUTH_TYPE='api'
```

3. Configure the SignInServiceClient in `config.ru`.
```ruby
  # config.ru
  SignInService.configure do |config|
    config.base_url = ENV.fetch('SIS_BASE_URL')
    config.client_id = ENV.fetch('SIS_CLIENT_ID')
    config.auth_type = ENV.fetch('SIS_AUTH_TYPE').to_sym
  end
```

3. Start the Sign-in Service server (`vets-api`)
```bash
  vets-api % rails s
```

## Running the Example app
### Native
Setup the app:
```bash
bin/setup
```
Start the server:
```bash
bin/server
```
By default the server will be running on http://localhost:4567

### Docker
Build image and start container
```bash
bin/up
```
The server will be running on http://localhost:4567

Remove container and cleanup
```bash
bin/down
```

## Development

### Testing
To run the the `rspec` test suite:
```bash
bin/test
```

### Linting
To run the `rubocop` linter:
```bash
bin/lint
```

## Environment Configuration

This application uses environment variables for configuration. To set up your environment:

1. Copy `.env.example` to `.env.local`:
   ```bash
   cp .env.example .env.local
   ```

2. Edit `.env.local` with your specific configuration values.

**Note:** Never edit `.env` directly. Always use `.env.local` for your local development environment. The `.env.local` file is ignored by git to prevent sensitive information from being committed.

Key environment variables:
- `SIS_BASE_URL`: Base URL for the Sign-In Service
- `CLIENT_ID`: Your client identifier
- `AUTH_TYPE`: Authentication type (api/cookie)
- `AUTH_FLOW`: Authentication flow (pkce/client_credentials)
- `TEST_MODE`: Enable/disable test mode

For development, you can enable test mode by setting `TEST_MODE=true` in your `.env.local` file.
