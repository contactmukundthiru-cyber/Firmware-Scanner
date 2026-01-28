//! Settings page

use leptos::*;

#[component]
pub fn SettingsPage() -> impl IntoView {
    view! {
        <div class="space-y-6">
            <h1 class="text-3xl font-bold text-gray-900">"Settings"</h1>

            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-xl font-semibold mb-4">"General Settings"</h2>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">"Max Upload Size"</label>
                        <input type="text" value="1 GB" class="mt-1 block w-full px-3 py-2 border rounded-md"/>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">"Default Claims"</label>
                        <select class="mt-1 block w-full px-3 py-2 border rounded-md">
                            <option>"All standard claims"</option>
                            <option>"Offline only"</option>
                            <option>"Custom"</option>
                        </select>
                    </div>
                </div>
            </div>
        </div>
    }
}
