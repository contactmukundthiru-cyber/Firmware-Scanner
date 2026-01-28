//! Contact page

use leptos::*;

#[component]
pub fn ContactPage() -> impl IntoView {
    let (name, set_name) = create_signal(String::new());
    let (email, set_email) = create_signal(String::new());
    let (company, set_company) = create_signal(String::new());
    let (message, set_message) = create_signal(String::new());
    let (interest, set_interest) = create_signal(String::from("demo"));
    let (submitted, set_submitted) = create_signal(false);

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        // In production, this would send to an API endpoint
        set_submitted.set(true);
    };

    view! {
        <div>
            // Hero
            <section class="bg-gradient-to-br from-gray-900 to-gray-800 text-white py-20">
                <div class="container mx-auto px-4">
                    <div class="max-w-3xl mx-auto text-center">
                        <h1 class="text-4xl md:text-5xl font-bold mb-6">"Get in Touch"</h1>
                        <p class="text-xl text-gray-300">
                            "Ready to see what's really in your firmware? Let's talk."
                        </p>
                    </div>
                </div>
            </section>

            // Contact Form
            <section class="py-20 bg-gray-50">
                <div class="container mx-auto px-4">
                    <div class="grid md:grid-cols-2 gap-12 max-w-5xl mx-auto">
                        // Form
                        <div class="bg-white rounded-xl shadow-lg p-8">
                            <Show
                                when=move || !submitted.get()
                                fallback=move || view! {
                                    <div class="text-center py-12">
                                        <div class="text-5xl mb-4">"✓"</div>
                                        <h3 class="text-2xl font-bold text-gray-900 mb-2">"Thank You!"</h3>
                                        <p class="text-gray-600">"We'll be in touch within 24 hours."</p>
                                    </div>
                                }
                            >
                                <form on:submit=on_submit class="space-y-6">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">"Name"</label>
                                        <input
                                            type="text"
                                            required
                                            class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                                            placeholder="Your name"
                                            on:input=move |ev| set_name.set(event_target_value(&ev))
                                            prop:value=name
                                        />
                                    </div>

                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">"Email"</label>
                                        <input
                                            type="email"
                                            required
                                            class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                                            placeholder="you@company.com"
                                            on:input=move |ev| set_email.set(event_target_value(&ev))
                                            prop:value=email
                                        />
                                    </div>

                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">"Company"</label>
                                        <input
                                            type="text"
                                            class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                                            placeholder="Your company (optional)"
                                            on:input=move |ev| set_company.set(event_target_value(&ev))
                                            prop:value=company
                                        />
                                    </div>

                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">"I'm interested in..."</label>
                                        <select
                                            class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                                            on:change=move |ev| set_interest.set(event_target_value(&ev))
                                        >
                                            <option value="demo">"Product Demo"</option>
                                            <option value="trial">"Free Trial"</option>
                                            <option value="pricing">"Pricing Information"</option>
                                            <option value="enterprise">"Enterprise Solutions"</option>
                                            <option value="partnership">"Partnership Opportunities"</option>
                                            <option value="other">"Other"</option>
                                        </select>
                                    </div>

                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">"Message"</label>
                                        <textarea
                                            rows="4"
                                            class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                                            placeholder="Tell us about your firmware analysis needs..."
                                            on:input=move |ev| set_message.set(event_target_value(&ev))
                                            prop:value=message
                                        ></textarea>
                                    </div>

                                    <button
                                        type="submit"
                                        class="w-full py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg transition"
                                    >
                                        "Send Message"
                                    </button>
                                </form>
                            </Show>
                        </div>

                        // Contact Info
                        <div class="space-y-8">
                            <div>
                                <h2 class="text-2xl font-bold text-gray-900 mb-4">"Let's Discuss Your Needs"</h2>
                                <p class="text-gray-600">
                                    "Whether you need a quick demo, want to discuss enterprise deployment, "
                                    "or have questions about our analysis capabilities, we're here to help."
                                </p>
                            </div>

                            <div class="space-y-6">
                                <div class="flex items-start">
                                    <div class="flex-shrink-0 w-12 h-12 bg-indigo-100 rounded-lg flex items-center justify-center">
                                        <span class="text-xl">"📧"</span>
                                    </div>
                                    <div class="ml-4">
                                        <h3 class="font-semibold text-gray-900">"Email"</h3>
                                        <p class="text-gray-600">"contact@firmwarescanner.io"</p>
                                    </div>
                                </div>

                                <div class="flex items-start">
                                    <div class="flex-shrink-0 w-12 h-12 bg-indigo-100 rounded-lg flex items-center justify-center">
                                        <span class="text-xl">"🕐"</span>
                                    </div>
                                    <div class="ml-4">
                                        <h3 class="font-semibold text-gray-900">"Response Time"</h3>
                                        <p class="text-gray-600">"We respond within 24 hours"</p>
                                    </div>
                                </div>

                                <div class="flex items-start">
                                    <div class="flex-shrink-0 w-12 h-12 bg-indigo-100 rounded-lg flex items-center justify-center">
                                        <span class="text-xl">"🔒"</span>
                                    </div>
                                    <div class="ml-4">
                                        <h3 class="font-semibold text-gray-900">"Security"</h3>
                                        <p class="text-gray-600">"All communications encrypted"</p>
                                    </div>
                                </div>
                            </div>

                            <div class="bg-gray-100 rounded-lg p-6">
                                <h3 class="font-semibold text-gray-900 mb-2">"Enterprise Customers"</h3>
                                <p class="text-gray-600 mb-4">
                                    "For on-premise deployment, custom integrations, or high-volume licensing, "
                                    "reach out to our enterprise team directly."
                                </p>
                                <a href="mailto:enterprise@firmwarescanner.io" class="text-indigo-600 hover:text-indigo-800 font-medium">
                                    "enterprise@firmwarescanner.io →"
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </section>
        </div>
    }
}
