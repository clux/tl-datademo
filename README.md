# TrueLayer datademo
A quick test.

## Usage

Create a `.env` file with the following contents:

```sh
export CLIENT_ID=sandbox-myid-xxxx
export CLIENT_SECRET=xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxxx
export CALLBACK_URI=https://public_url_of_self/signin_callback
# data-api specific
export PROVIDERS="providers=uk-ob-all uk-oauth-all uk-cs-mock"
export SCOPE="info accounts transactions"
```

Then source it and start the app:

```sh
. .env
cargo run
```
