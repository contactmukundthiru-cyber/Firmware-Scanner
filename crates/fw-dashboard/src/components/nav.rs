//! Navigation component

use leptos::*;

#[component]
pub fn Nav() -> impl IntoView {
    view! {
        <nav class="bg-white shadow">
            <div class="container mx-auto px-4">
                <div class="flex justify-between h-16">
                    <div class="flex items-center">
                        <a href="/" class="text-xl font-bold text-gray-900">
                            "Firmware Scanner"
                        </a>
                        <div class="hidden md:flex ml-10 space-x-4">
                            <a href="/" class="text-gray-600 hover:text-gray-900 px-3 py-2">"Dashboard"</a>
                            <a href="/scans" class="text-gray-600 hover:text-gray-900 px-3 py-2">"Scans"</a>
                            <a href="/reports" class="text-gray-600 hover:text-gray-900 px-3 py-2">"Reports"</a>
                            <a href="/settings" class="text-gray-600 hover:text-gray-900 px-3 py-2">"Settings"</a>
                        </div>
                    </div>
                    <div class="flex items-center">
                        <span class="text-gray-600">"admin@example.com"</span>
                    </div>
                </div>
            </div>
        </nav>
    }
}
