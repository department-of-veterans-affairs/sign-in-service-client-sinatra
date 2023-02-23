**Note:** This repo is managed by the VSP-Identity team. Please reference our main product page [here](https://github.com/department-of-veterans-affairs/va.gov-team/blob/master/products/identity/README.md) for contact information and questions.

# Sign In Service (SiS) Sample App

A sample app built with Sinatra that interfaces with Sign In Service (SiS).

## Dependencies
- Ruby 3.1.2

## Running the app
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
### App Configuration
Default configuration is in the `.env` file. These values can be overridden in a `.env.local` or `.env.{environment}.local`
file.

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
