//! Marketing navigation component

use leptos::*;

#[component]
pub fn MarketingNav() -> impl IntoView {
    let (mobile_open, set_mobile_open) = create_signal(false);

    view! {
        <nav class="bg-white shadow-sm sticky top-0 z-50">
            <div class="container mx-auto px-4">
                <div class="flex justify-between h-16">
                    // Logo
                    <div class="flex items-center">
                        <a href="/" class="flex items-center">
                            <span class="text-2xl mr-2">"🔬"</span>
                            <span class="text-xl font-bold text-gray-900">"Firmware Scanner"</span>
                        </a>
                    </div>

                    // Desktop Nav
                    <div class="hidden md:flex items-center space-x-8">
                        <a href="/features" class="text-gray-600 hover:text-gray-900 transition">"Features"</a>
                        <a href="/pricing" class="text-gray-600 hover:text-gray-900 transition">"Pricing"</a>
                        <a href="/docs" class="text-gray-600 hover:text-gray-900 transition">"Docs"</a>
                        <a href="/contact" class="text-gray-600 hover:text-gray-900 transition">"Contact"</a>
                        <div class="flex items-center space-x-4 ml-4">
                            <a href="/login" class="text-gray-600 hover:text-gray-900 transition">"Sign In"</a>
                            <a href="/contact" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-medium rounded-lg transition">
                                "Get Demo"
                            </a>
                        </div>
                    </div>

                    // Mobile menu button
                    <div class="md:hidden flex items-center">
                        <button
                            class="p-2 rounded-md text-gray-600 hover:text-gray-900 hover:bg-gray-100"
                            on:click=move |_| set_mobile_open.update(|v| *v = !*v)
                        >
                            <Show
                                when=move || mobile_open.get()
                                fallback=|| view! {
                                    <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>
                                    </svg>
                                }
                            >
                                <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                                </svg>
                            </Show>
                        </button>
                    </div>
                </div>
            </div>

            // Mobile menu
            <Show when=move || mobile_open.get()>
                <div class="md:hidden border-t border-gray-200">
                    <div class="px-4 py-4 space-y-3">
                        <a href="/features" class="block text-gray-600 hover:text-gray-900">"Features"</a>
                        <a href="/pricing" class="block text-gray-600 hover:text-gray-900">"Pricing"</a>
                        <a href="/docs" class="block text-gray-600 hover:text-gray-900">"Docs"</a>
                        <a href="/contact" class="block text-gray-600 hover:text-gray-900">"Contact"</a>
                        <div class="pt-4 border-t border-gray-200 space-y-3">
                            <a href="/login" class="block text-gray-600 hover:text-gray-900">"Sign In"</a>
                            <a href="/contact" class="block w-full text-center px-4 py-2 bg-indigo-600 text-white font-medium rounded-lg">
                                "Get Demo"
                            </a>
                        </div>
                    </div>
                </div>
            </Show>
        </nav>
    }
}
