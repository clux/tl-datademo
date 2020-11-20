#![allow(unused_imports)]
use anyhow::bail;
use log::{error, info, warn};
use serde::Deserialize;
use jsonwebtoken as jwt;

use actix_web::http::{header, Method, StatusCode};
use actix_web::{
    error, get, guard, middleware,
    web::{self, Data, Query},
    App, Error, HttpRequest, HttpResponse, HttpServer, Result,
};
#[derive(Deserialize, Debug, Clone)]
struct Config {
    auth_server_uri: String,
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

#[derive(Debug, Clone)]
struct Credentials {
    code: String,
    cfg: Config,
    access_token: String,
    credentials_id: String,
    expiration_date: usize,
    //refresh_token: String,
}

impl Credentials {
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
            error!("Failed to exchange token: {}: {}", status, text);
            bail!("Failed to exchange token: {}: {}", status, text);
        }
        let data: ExchangeResponse = res.json().await?;
        info!("successful token exchange: {:?}", data);

        // Decode the jwt
        let t = &data.access_token;
        #[derive(Debug, Deserialize)]
        struct Claims {
            sub: String,
            exp: usize,
        }
        let header = jwt::decode_header(&t)?;
        let msg = jwt::dangerous_insecure_decode_with_validation::<Claims>(&t, &jwt::Validation::new(header.alg))?;
        info!("jwt: {:?}", msg);
        Ok(Self {
            code: code,
            cfg: cfg.clone(),
            access_token: data.access_token,
            credentials_id: msg.claims.sub,
            expiration_date: msg.claims.exp,
        })
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
async fn signin_callback(cfg: Data<Config>, Query(info): Query<AuthResponse>) -> HttpResponse {
    info!("got cb with {:?}", info);
    let creds = Credentials::exchange_code(info.code, &cfg).await; //.unwrap();
    info!("got creds: {:?}", creds);
    HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body("hi")
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
    })
    .bind("0.0.0.0:5000")?
    .workers(1)
    .run()
    .await
}
