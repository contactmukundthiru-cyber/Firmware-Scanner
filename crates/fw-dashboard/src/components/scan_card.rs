//! Scan card component

use leptos::*;

#[component]
pub fn ScanCard(
    id: String,
    name: String,
    status: String,
    findings: i64,
) -> impl IntoView {
    view! {
        <div class="bg-white rounded-lg shadow p-4 hover:shadow-md transition-shadow">
            <a href=format!("/scans/{}", id) class="block">
                <h3 class="font-medium text-gray-900">{name}</h3>
                <div class="mt-2 flex justify-between text-sm">
                    <span class="text-gray-500">{status}</span>
                    <span class="text-gray-500">{findings} " findings"</span>
                </div>
            </a>
        </div>
    }
}
