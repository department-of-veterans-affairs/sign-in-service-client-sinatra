**Note:** This repo is managed by the VSP-Identity team. Please reference our main product page [here](https://github.com/department-of-veterans-affairs/va.gov-team/blob/master/products/identity/README.md) for contact information and questions.

# Sign In Service (SiS) Sample App

A sample app built with Sinatra that interfaces with Sign In Service (SiS).

## Dependencies
- Ruby 3.1.2

## Configuration
### Config the SiS Server
Currently, SiS is available as a part of `vets-api`
1. Clone Repo
  ```bash
    git clone git@github.com:department-of-veterans-affairs/vets-api.git
  ```
2. Follow [setup instructions](git@github.com:department-of-veterans-affairs/vets-api.git) for vets-api
3. Ensure your database is prpoerly seeded `rails db:seed` this will add the necessary client configurations

### Configure the SiS client
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
    config.auth_type = ENV.fetch('SIS_AUTH_TYPE')
  end
```
3. Start the `SiS` server (`vets-api`)
```bash
  vets-api % rails s
```

## Running the Sample app
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
