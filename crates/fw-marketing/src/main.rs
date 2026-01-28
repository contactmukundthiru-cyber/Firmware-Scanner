//! Firmware Scanner Marketing Site
//!
//! A Leptos SSR marketing website.

use axum::{
    Router,
    routing::get,
};
use leptos::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use tower_http::services::ServeDir;

mod app;
mod pages;
mod components;

use app::App;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let conf = get_configuration(None).await.unwrap();
    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    let routes = generate_route_list(App);

    let app = Router::new()
        .leptos_routes(&leptos_options, routes, App)
        .fallback(leptos_axum::file_and_error_handler(App))
        .nest_service("/assets", ServeDir::new("assets"))
        .with_state(leptos_options);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("Marketing site listening on http://{}", addr);
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
