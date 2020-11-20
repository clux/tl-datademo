use serde::Deserialize;
use log::{info};

use actix_web::http::{header, Method, StatusCode};
use actix_web::{
    error, get, guard, middleware, web::{self, Data, Query}, App, Error, HttpRequest, HttpResponse,
    HttpServer, Result,
};
#[derive(Deserialize, Debug, Clone)]
struct Config {
    client_id: String,
    client_secret: String,
    callback_uri: String,
    providers: String,
    scope: String,
}

impl Config {
    fn auth_link(&self) -> anyhow::Result<url::Url> {
        let base_url = "https://auth.truelayer-sandbox.com/?".to_string();
        let mut url = url::Url::parse(&base_url)?;
        let qp = format!("response_type=code&client_id={id}&redirect_uri={redir}&scope={s}&providers={p}",
            id=&self.client_id,
            redir=&self.callback_uri,
            s=&self.scope,
            p=&self.providers,
        );
        url.set_query(Some(&qp));
        Ok(url)
    }
}

struct Credentials {
    code: String,
}

impl Credentials {
    fn from_code(code: String) -> Self {
        Self { code }
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
    HttpResponse::build(StatusCode::OK)
            .content_type("text/html; charset=utf-8")
            .body(info.code)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "datademo=info,actix_web=info");
    env_logger::init();
    let config = envy::from_env::<Config>().unwrap();
    info!("Configuration: {:?}", config);

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::DefaultHeaders::new().header("X-Version", "0.2"))
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
