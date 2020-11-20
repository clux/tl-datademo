# TrueLayer datademo
A quick test.

## Usage

Create a `.env` file with the following contents:

```sh
export AUTH_SERVER_URI=https://auth.truelayer-sandbox.com
export DATA_API_URI=https://api.truelayer-sandbox.com/data/v1
export CLIENT_ID=sandbox-myid-xxxx
export CLIENT_SECRET=xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxxx
export REDIRECT_URI=https://public_url_of_self/signin_callback
export PROVIDERS="uk-ob-all uk-oauth-all uk-cs-mock"
export SCOPE="info accounts transactions offline_access"

```

To get a local redirect uri; use `ngrok http 0.0.0.0:5000` and grab the `https` url with an added `signin_callback`. Then enter this evar into the TL console under App Settings as an allowed redirect uri.

Then source it and start the app:

```sh
. .env
cargo run
```
