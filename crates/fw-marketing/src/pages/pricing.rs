//! Pricing page

use leptos::*;

#[component]
pub fn PricingPage() -> impl IntoView {
    view! {
        <div>
            // Hero
            <section class="bg-gradient-to-br from-gray-900 to-gray-800 text-white py-20">
                <div class="container mx-auto px-4">
                    <div class="max-w-3xl mx-auto text-center">
                        <h1 class="text-4xl md:text-5xl font-bold mb-6">"Simple, Transparent Pricing"</h1>
                        <p class="text-xl text-gray-300">
                            "Choose the plan that fits your security analysis needs."
                        </p>
                    </div>
                </div>
            </section>

            // Pricing Cards
            <section class="py-20 bg-gray-50">
                <div class="container mx-auto px-4">
                    <div class="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
                        // Starter
                        <div class="bg-white rounded-xl shadow-lg p-8">
                            <div class="text-center mb-8">
                                <h3 class="text-xl font-semibold text-gray-900 mb-2">"Starter"</h3>
                                <div class="text-4xl font-bold text-gray-900 mb-1">
                                    "$99"
                                    <span class="text-lg font-normal text-gray-500">"/month"</span>
                                </div>
                                <p class="text-gray-600">"For individual researchers"</p>
                            </div>
                            <ul class="space-y-4 mb-8">
                                <PricingFeature text="10 scans per month" included=true/>
                                <PricingFeature text="Up to 500MB per firmware" included=true/>
                                <PricingFeature text="All 6 capability detectors" included=true/>
                                <PricingFeature text="PDF & JSON reports" included=true/>
                                <PricingFeature text="Email support" included=true/>
                                <PricingFeature text="API access" included=false/>
                                <PricingFeature text="Custom claim definitions" included=false/>
                                <PricingFeature text="Priority support" included=false/>
                            </ul>
                            <a href="/contact" class="block w-full py-3 text-center bg-gray-100 hover:bg-gray-200 text-gray-900 font-semibold rounded-lg transition">
                                "Get Started"
                            </a>
                        </div>

                        // Professional
                        <div class="bg-gradient-to-b from-indigo-600 to-purple-700 rounded-xl shadow-xl p-8 text-white transform scale-105">
                            <div class="text-center mb-8">
                                <span class="inline-block px-3 py-1 bg-white/20 rounded-full text-sm font-medium mb-4">"Most Popular"</span>
                                <h3 class="text-xl font-semibold mb-2">"Professional"</h3>
                                <div class="text-4xl font-bold mb-1">
                                    "$499"
                                    <span class="text-lg font-normal text-indigo-200">"/month"</span>
                                </div>
                                <p class="text-indigo-200">"For security teams"</p>
                            </div>
                            <ul class="space-y-4 mb-8">
                                <PricingFeatureWhite text="100 scans per month" included=true/>
                                <PricingFeatureWhite text="Up to 2GB per firmware" included=true/>
                                <PricingFeatureWhite text="All 6 capability detectors" included=true/>
                                <PricingFeatureWhite text="All report formats" included=true/>
                                <PricingFeatureWhite text="Priority email support" included=true/>
                                <PricingFeatureWhite text="Full API access" included=true/>
                                <PricingFeatureWhite text="Custom claim definitions" included=true/>
                                <PricingFeatureWhite text="Dedicated support" included=false/>
                            </ul>
                            <a href="/contact" class="block w-full py-3 text-center bg-white text-indigo-600 font-semibold rounded-lg hover:bg-gray-100 transition">
                                "Get Started"
                            </a>
                        </div>

                        // Enterprise
                        <div class="bg-white rounded-xl shadow-lg p-8">
                            <div class="text-center mb-8">
                                <h3 class="text-xl font-semibold text-gray-900 mb-2">"Enterprise"</h3>
                                <div class="text-4xl font-bold text-gray-900 mb-1">"Custom"</div>
                                <p class="text-gray-600">"For large organizations"</p>
                            </div>
                            <ul class="space-y-4 mb-8">
                                <PricingFeature text="Unlimited scans" included=true/>
                                <PricingFeature text="No size limits" included=true/>
                                <PricingFeature text="All 6 capability detectors" included=true/>
                                <PricingFeature text="All report formats" included=true/>
                                <PricingFeature text="24/7 dedicated support" included=true/>
                                <PricingFeature text="Full API access" included=true/>
                                <PricingFeature text="Custom claim definitions" included=true/>
                                <PricingFeature text="On-premise deployment" included=true/>
                            </ul>
                            <a href="/contact" class="block w-full py-3 text-center bg-gray-900 hover:bg-gray-800 text-white font-semibold rounded-lg transition">
                                "Contact Sales"
                            </a>
                        </div>
                    </div>
                </div>
            </section>

            // FAQ
            <section class="py-20 bg-white">
                <div class="container mx-auto px-4">
                    <div class="max-w-3xl mx-auto">
                        <h2 class="text-3xl font-bold text-gray-900 text-center mb-12">"Frequently Asked Questions"</h2>
                        <div class="space-y-6">
                            <FaqItem
                                question="What counts as a scan?"
                                answer="A scan is a single firmware image analysis. Re-scanning the same image or generating different report formats doesn't count as additional scans."
                            />
                            <FaqItem
                                question="Can I upgrade or downgrade my plan?"
                                answer="Yes, you can change your plan at any time. Upgrades are prorated, and downgrades take effect at the next billing cycle."
                            />
                            <FaqItem
                                question="Do you offer a free trial?"
                                answer="Yes! Contact us for a free analysis of one firmware image so you can evaluate our platform before committing."
                            />
                            <FaqItem
                                question="What file formats do you support?"
                                answer="We support virtually all firmware formats: OTA packages, flash dumps, filesystem images (SquashFS, ext4, JFFS2, etc.), and compressed archives."
                            />
                            <FaqItem
                                question="Is my firmware data secure?"
                                answer="Absolutely. All uploads are encrypted in transit and at rest. Enterprise customers can opt for on-premise deployment for complete data sovereignty."
                            />
                            <FaqItem
                                question="Can I define custom claims to verify?"
                                answer="Professional and Enterprise plans include custom claim definitions. Define your own compliance requirements and verify them automatically."
                            />
                        </div>
                    </div>
                </div>
            </section>
        </div>
    }
}

#[component]
fn PricingFeature(text: &'static str, included: bool) -> impl IntoView {
    let (icon, style) = if included {
        ("✓", "text-green-500")
    } else {
        ("−", "text-gray-300")
    };
    let text_style = if included { "text-gray-700" } else { "text-gray-400" };

    view! {
        <li class="flex items-center">
            <span class=format!("{} mr-3 font-bold", style)>{icon}</span>
            <span class=text_style>{text}</span>
        </li>
    }
}

#[component]
fn PricingFeatureWhite(text: &'static str, included: bool) -> impl IntoView {
    let (icon, style) = if included {
        ("✓", "text-green-300")
    } else {
        ("−", "text-indigo-300")
    };
    let text_style = if included { "text-white" } else { "text-indigo-200" };

    view! {
        <li class="flex items-center">
            <span class=format!("{} mr-3 font-bold", style)>{icon}</span>
            <span class=text_style>{text}</span>
        </li>
    }
}

#[component]
fn FaqItem(question: &'static str, answer: &'static str) -> impl IntoView {
    view! {
        <div class="border-b border-gray-200 pb-6">
            <h3 class="text-lg font-semibold text-gray-900 mb-2">{question}</h3>
            <p class="text-gray-600">{answer}</p>
        </div>
    }
}
