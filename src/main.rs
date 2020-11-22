#![allow(unused_imports)]
use anyhow::bail;
use jsonwebtoken as jwt;
use log::{error, info, warn};
use serde::Deserialize;

use actix_web::http::{header, Method, StatusCode};
use actix_web::{
    error, get, guard, middleware,
    web::{self, Data, Query},
    App, Error, HttpRequest, HttpResponse, HttpServer, Result,
};
#[derive(Deserialize, Debug, Clone)]
struct Config {
    auth_server_uri: String,
    data_api_uri: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    providers: String,
    scope: String,
}

impl Config {
    fn auth_link(&self) -> anyhow::Result<url::Url> {
        let base_url = format!("{}/?", self.auth_server_uri);
        let mut url = url::Url::parse(&base_url)?;
        let qp = format!(
            "response_type=code&client_id={id}&redirect_uri={redir}&scope={s}&providers={p}",
            id = &self.client_id,
            redir = &self.redirect_uri,
            s = &self.scope,
            p = &self.providers,
        );
        url.set_query(Some(&qp));
        Ok(url)
    }
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}
fn decode_token(t: &str) -> anyhow::Result<jwt::TokenData<Claims>> {
    let header = jwt::decode_header(&t)?;
    let msg = jwt::dangerous_insecure_decode_with_validation::<Claims>(
        &t,
        &jwt::Validation::new(header.alg),
    )?;
    Ok(msg)
}

#[derive(Debug, Clone)]
struct Credentials {
    access_token: String,
    credentials_id: String,
    expiration_date: usize,
    //refresh_token: String,
}

impl Credentials {
    fn new(token: &str, c: Claims) -> Self {
        Self {
            access_token: token.into(),
            credentials_id: c.sub,
            expiration_date: c.exp,
        }
    }
    async fn exchange_code(code: String, cfg: &Config) -> anyhow::Result<Self> {
        #[derive(Debug, Deserialize)]
        struct ExchangeResponse {
            access_token: String,
        }

        let url = url::Url::parse(&format!("{}/connect/token", &cfg.auth_server_uri))?;
        let body = serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": &cfg.client_id,
            "client_secret": &cfg.client_secret,
            "redirect_uri": &cfg.redirect_uri,
            "code": code
        });
        info!("hitting {} with {:?}", url, body);

        let res = reqwest::Client::new().post(url).json(&body).send().await?;

        if !res.status().is_success() {
            let status = res.status().to_owned();
            let text = res.text().await?;
            bail!("Failed to exchange token: {}: {}", status, text);
        }
        let data: ExchangeResponse = res.json().await?;
        info!("successful token exchange: {:?}", data);

        // Decode the jwt
        let msg = decode_token(&data.access_token)?;
        info!("jwt: {:?}", msg);
        Ok(Self::new(&data.access_token, msg.claims))
    }
}

#[get("/")]
async fn index(cfg: Data<Config>) -> HttpResponse {
    let url = cfg.auth_link().expect("invalid config");
    let r = format!("Plz <a href=\"{}\" target=\"_blank\">bank</a>", url);
    HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body(r)
}

#[derive(Deserialize, Debug)]
pub struct AuthResponse {
    code: String,
    scope: Option<String>,
}

#[get("/signin_callback")]
async fn signin_callback(
    cfg: Data<Config>,
    Query(info): Query<AuthResponse>,
) -> Result<HttpResponse> {
    info!("got cb with {:?}", info);
    match Credentials::exchange_code(info.code, &cfg).await {
        Ok(c) => Ok(HttpResponse::build(StatusCode::OK)
            .content_type("text/html; charset=utf-8")
            .body(format!("creds: {:?}", c))),
        Err(e) => Err(ErrorUnauthorized(format!("Token error: {}", e))),
    }
}

use actix_web::error::ErrorUnauthorized;
use actix_web::{dev, FromRequest};
use futures::future::{err, ok, Ready};
impl FromRequest for Credentials {
    type Error = Error;
    type Future = Ready<Result<Credentials, Error>>;
    type Config = ();

    fn from_request(_req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
        let _auth = _req.headers().get("Authorization");
        match _auth {
            Some(_) => {
                let _split: Vec<&str> = _auth.unwrap().to_str().unwrap().split("Bearer").collect();
                let token = _split[1].trim();
                match decode_token(&token) {
                    Ok(msg) => ok(Credentials::new(&token, msg.claims)),
                    Err(_e) => err(ErrorUnauthorized("invalid token")),
                }
            }
            None => err(ErrorUnauthorized("blocked!")),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AccountsResponse {
    results: Vec<AccountResponse>,
}
#[derive(Debug, Deserialize)]
struct AccountResponse {
    account_id: String,
    account_type: String,
    display_name: String,
    currency: String,
}
async fn get_accounts(cfg: &Config, creds: &Credentials) -> anyhow::Result<AccountsResponse> {
    let url = url::Url::parse(&format!("{}/accounts", &cfg.data_api_uri))?;
    info!("hitting {}", url);

    let res = reqwest::Client::new()
        .get(url)
        .bearer_auth(&creds.access_token)
        .send()
        .await?;
    if !res.status().is_success() {
        let status = res.status().to_owned();
        let text = res.text().await?;
        bail!("Failed to GET /accounts: {}: {}", status, text);
    }
    let data: AccountsResponse = res.json().await?;
    info!("Got: {:?}", data);
    Ok(data)
}

#[get("/transactions")]
async fn transactions(cfg: Data<Config>, creds: Credentials) -> Result<HttpResponse> {
    // TODO: use data api to gets all transactions for a user's connected bank accounts
    // cache this in memory
    match get_accounts(&cfg, &creds).await {
        Ok(accs) => Ok(HttpResponse::build(StatusCode::OK)
            .content_type("text/html; charset=utf-8")
            .body(format!("transactions: {:?}", accs))),
        Err(e) => Err(ErrorUnauthorized(format!("Accounts error: {}", e))),
    }
}

#[get("/summary")]
async fn transaction_summary(creds: Credentials) -> HttpResponse {
    // TODO: use data api to get a summary of all their connected bank accounts
    // for each category of transaction, the total amount user has spent in the past week
    // cache the transaction locally
    HttpResponse::Ok().finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "datademo=info,actix_web=info");
    env_logger::init();
    let config = envy::from_env::<Config>().unwrap();
    info!("Configuration: {:?}", config);

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Compress::default())
            .wrap(middleware::Logger::default())
            .data(config.clone())
            .service(index)
            .service(signin_callback)
            .service(transactions)
    })
    .bind("0.0.0.0:5000")?
    .workers(1)
    .run()
    .await
}
