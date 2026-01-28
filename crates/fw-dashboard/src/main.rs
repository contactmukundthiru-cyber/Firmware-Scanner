//! Firmware Scanner Admin Dashboard

mod app;
mod components;
mod pages;

use leptos::*;

fn main() {
    // Initialize logging
    _ = console_log::init_with_level(log::Level::Debug);

    mount_to_body(|| {
        view! {
            <app::App/>
        }
    });
}
