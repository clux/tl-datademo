use serde::Deserialize;
use anyhow::{Context, Result};
use log::{info};

use actix_web::http::{header, Method, StatusCode};
use actix_web::{
    error, get, guard, middleware, web, App, Error, HttpRequest, HttpResponse,
    HttpServer,
};
#[derive(Deserialize, Debug, Clone)]
struct Config {
    client_id: String,
    client_secret: String,
    providers: String,
}

#[get("/")]
async fn index() -> &'static str {
    "Hello world!\r\n"
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
    })
    .bind("0.0.0.0:5000")?
    .workers(1)
    .run()
    .await
}
