# TrueLayer datademo
A quick test.

## Setup
### Expose
Create a publicly accessible redirect url. E.g. https output from `ngrok http 0.0.0.0:5000` will do.

### TrueLayer
Make an app for the Data API, generate a client id + secret, point the redirect url to the one exposed above.

## Usage
Create a `.env` file with the following from above:

```sh
export AUTH_SERVER_URI=https://auth.truelayer-sandbox.com
export DATA_API_URI=https://api.truelayer-sandbox.com/data/v1
export CLIENT_ID=sandbox-myid-xxxx
export CLIENT_SECRET=xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxxx
export REDIRECT_URI=https://public_url_of_self/login
export PROVIDERS="uk-ob-all uk-oauth-all uk-cs-mock"
export SCOPE="info accounts transactions offline_access"
```

Then source it and start the app:

```sh
source .env
cargo run
```
