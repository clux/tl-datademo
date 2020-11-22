#![allow(unused_imports)]
use actix_web::http::{header, Method, StatusCode};
use actix_web::{
    error, get, guard, middleware,
    web::{self, Data, Query},
    App, Error, HttpRequest, HttpResponse, HttpServer, Result,
};
use anyhow::bail;
use chrono::{DateTime, Duration, Utc};
use futures::stream::{self, StreamExt};
use jsonwebtoken as jwt;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;
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
        let mut url = Url::parse(&base_url)?;
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

        let url = Url::parse(&format!("{}/connect/token", &cfg.auth_server_uri))?;
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
    HttpResponse::Ok()
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
        Ok(c) => Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8") // TODO: template here!
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
struct ResultsResponse<T> {
    results: Vec<T>,
}
#[derive(Debug, Deserialize, Serialize)]
struct Account {
    account_id: String,
    account_type: String,
    display_name: String,
    currency: String,
}
#[derive(Debug, Deserialize, Serialize, Clone)]
struct Transaction {
    transaction_id: String,
    amount: f64,
    timestamp: DateTime<Utc>,
    description: String,
    transaction_category: String,
}

async fn get_account_transactions(
    acc: String,
    cfg: &Config,
    creds: &Credentials,
) -> anyhow::Result<(String, Vec<Transaction>)> {
    let url = Url::parse(&format!(
        "{}/accounts/{}/transactions",
        &cfg.data_api_uri, acc
    ))?;
    let res = reqwest::Client::new()
        .get(url)
        .bearer_auth(&creds.access_token)
        .send()
        .await?;
    if !res.status().is_success() {
        let status = res.status().to_owned();
        let text = res.text().await?;
        bail!("Failed to GET transactions: {}: {}", status, text);
    }
    let data: ResultsResponse<Transaction> = res.json().await?;
    Ok((acc, data.results))
}

type TransactionCache = HashMap<String, Vec<Transaction>>;
async fn get_transactions(cfg: &Config, creds: &Credentials) -> anyhow::Result<TransactionCache> {
    let url = Url::parse(&format!("{}/accounts", &cfg.data_api_uri))?;
    let res = reqwest::Client::new()
        .get(url)
        .bearer_auth(&creds.access_token)
        .send()
        .await?;
    if !res.status().is_success() {
        let status = res.status().to_owned();
        let text = res.text().await?;
        bail!("Failed to GET accounts: {}: {}", status, text);
    }
    let accounts: ResultsResponse<Account> = res.json().await?;

    // loop over all accounts in parallel and collect transactions
    let mut data = HashMap::new();
    let mut buffered = stream::iter(accounts.results)
        .map(move |acc| get_account_transactions(acc.account_id, cfg, creds))
        .buffer_unordered(10);
    while let Some(next) = buffered.next().await {
        let t = next?; // TODO: better error handling
        data.insert(t.0, t.1);
    }
    Ok(data)
}

fn summarize_transactions(cache: TransactionCache) -> HashMap<String, f64> {
    // map of category -> spending
    let mut res: HashMap<String, f64> = HashMap::new(); // across all accounts
    for acctrans in cache.values() {
        for t in acctrans {
            let diff: Duration = Utc::now() - t.timestamp;
            if diff.num_days() < 7 {
                *res.entry(t.transaction_category.clone()).or_default() += t.amount;
            }
        }
    }
    res
}

#[get("/transactions")]
async fn transactions(cfg: Data<Config>, creds: Credentials) -> Result<HttpResponse> {
    // TODO: cache this in memory
    match get_transactions(&cfg, &creds).await {
        Ok(data) => Ok(HttpResponse::Ok().json(data)),
        Err(e) => Err(ErrorUnauthorized(format!("Accounts error: {}", e))),
    }
}

#[get("/summary")]
async fn transaction_summary(cfg: Data<Config>, creds: Credentials) -> Result<HttpResponse> {
    // TODO: cache this in memory
    match get_transactions(&cfg, &creds).await {
        Ok(data) => Ok(HttpResponse::Ok().json(&summarize_transactions(data))),
        Err(e) => Err(ErrorUnauthorized(format!("Accounts error: {}", e))),
    }
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
            .service(transaction_summary)
    })
    .bind("0.0.0.0:5000")?
    .workers(1)
    .run()
    .await
}
