//! Features page

use leptos::*;

#[component]
pub fn FeaturesPage() -> impl IntoView {
    view! {
        <div>
            // Hero
            <section class="bg-gradient-to-br from-gray-900 to-gray-800 text-white py-20">
                <div class="container mx-auto px-4">
                    <div class="max-w-3xl mx-auto text-center">
                        <h1 class="text-4xl md:text-5xl font-bold mb-6">"Platform Features"</h1>
                        <p class="text-xl text-gray-300">
                            "Everything you need for comprehensive firmware security analysis."
                        </p>
                    </div>
                </div>
            </section>

            // Feature Sections
            <section class="py-20 bg-white">
                <div class="container mx-auto px-4">
                    // Format Support
                    <div class="max-w-5xl mx-auto mb-20">
                        <div class="grid md:grid-cols-2 gap-12 items-center">
                            <div>
                                <h2 class="text-3xl font-bold text-gray-900 mb-4">"Universal Format Support"</h2>
                                <p class="text-lg text-gray-600 mb-6">
                                    "Analyze firmware in any format. Our intelligent container detection "
                                    "automatically identifies and extracts nested filesystems."
                                </p>
                                <ul class="space-y-3">
                                    <FeatureItem text="OTA packages (Android, iOS, vendor-specific)"/>
                                    <FeatureItem text="Flash dumps and raw images"/>
                                    <FeatureItem text="SquashFS, CramFS, ext4, JFFS2, YAFFS, UBI"/>
                                    <FeatureItem text="ELF, PE/COFF, Mach-O binaries"/>
                                    <FeatureItem text="Compressed archives (ZIP, TAR, CPIO)"/>
                                </ul>
                            </div>
                            <div class="bg-gray-100 rounded-lg p-8">
                                <div class="font-mono text-sm space-y-2">
                                    <div class="text-green-600">"✓ Detected: Android OTA Package"</div>
                                    <div class="text-gray-600 pl-4">"└── payload.bin (Sparse Image)"</div>
                                    <div class="text-gray-600 pl-8">"└── system.img (ext4)"</div>
                                    <div class="text-gray-600 pl-12">"├── /lib/libtelemetry.so"</div>
                                    <div class="text-gray-600 pl-12">"├── /bin/analytics_daemon"</div>
                                    <div class="text-gray-600 pl-12">"└── /etc/endpoints.conf"</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    // Deep Analysis
                    <div class="max-w-5xl mx-auto mb-20">
                        <div class="grid md:grid-cols-2 gap-12 items-center">
                            <div class="order-2 md:order-1 bg-gray-900 rounded-lg p-8 text-white">
                                <div class="font-mono text-sm space-y-1">
                                    <div class="text-cyan-400">"[NETWORKING] High severity"</div>
                                    <div class="text-gray-400">"├── TCP/IP: lwIP stack detected"</div>
                                    <div class="text-gray-400">"├── HTTP: libcurl 7.84.0"</div>
                                    <div class="text-yellow-400">"├── URL: https://telemetry.vendor.com"</div>
                                    <div class="text-yellow-400">"└── URL: https://updates.vendor.com/v2"</div>
                                    <div class="mt-4 text-cyan-400">"[TELEMETRY] Critical severity"</div>
                                    <div class="text-gray-400">"├── Analytics: Firebase SDK"</div>
                                    <div class="text-gray-400">"├── Crash: Crashlytics"</div>
                                    <div class="text-yellow-400">"└── Metrics: Custom protobuf schema"</div>
                                </div>
                            </div>
                            <div class="order-1 md:order-2">
                                <h2 class="text-3xl font-bold text-gray-900 mb-4">"Deep Binary Analysis"</h2>
                                <p class="text-lg text-gray-600 mb-6">
                                    "Our analysis engine goes beyond surface-level scanning. We examine "
                                    "symbols, strings, imports, and binary patterns to detect capabilities."
                                </p>
                                <ul class="space-y-3">
                                    <FeatureItem text="Symbol table extraction and analysis"/>
                                    <FeatureItem text="Import/export dependency mapping"/>
                                    <FeatureItem text="String pattern matching (URLs, IPs, endpoints)"/>
                                    <FeatureItem text="Library fingerprinting and version detection"/>
                                    <FeatureItem text="Entropy analysis for encrypted sections"/>
                                </ul>
                            </div>
                        </div>
                    </div>

                    // Dormant Detection
                    <div class="max-w-5xl mx-auto mb-20">
                        <div class="grid md:grid-cols-2 gap-12 items-center">
                            <div>
                                <h2 class="text-3xl font-bold text-gray-900 mb-4">"Dormant Capability Detection"</h2>
                                <p class="text-lg text-gray-600 mb-6">
                                    "Find disabled-but-present code that could be activated remotely. "
                                    "Identify feature flags, debug code, and environment-gated functionality."
                                </p>
                                <ul class="space-y-3">
                                    <FeatureItem text="Feature flag analysis (compile-time and runtime)"/>
                                    <FeatureItem text="Debug and development code detection"/>
                                    <FeatureItem text="Environment variable gating"/>
                                    <FeatureItem text="Conditional compilation artifacts"/>
                                    <FeatureItem text="Unreferenced but present code paths"/>
                                </ul>
                            </div>
                            <div class="bg-orange-50 border border-orange-200 rounded-lg p-8">
                                <div class="text-orange-800 font-semibold mb-4">"⚠️ Dormant Capabilities Found"</div>
                                <div class="space-y-4 text-sm">
                                    <div class="bg-white rounded p-3 border border-orange-200">
                                        <div class="font-medium text-gray-900">"Remote Debug Interface"</div>
                                        <div class="text-gray-600">"Gated by: DEBUG_ENABLED env var"</div>
                                        <div class="text-gray-500">"Location: /usr/bin/debug_server"</div>
                                    </div>
                                    <div class="bg-white rounded p-3 border border-orange-200">
                                        <div class="font-medium text-gray-900">"Telemetry Upload"</div>
                                        <div class="text-gray-600">"Gated by: feature_telemetry flag"</div>
                                        <div class="text-gray-500">"Location: /lib/libmetrics.so"</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    // Evidence Preservation
                    <div class="max-w-5xl mx-auto">
                        <div class="grid md:grid-cols-2 gap-12 items-center">
                            <div class="order-2 md:order-1 bg-blue-50 border border-blue-200 rounded-lg p-8">
                                <div class="text-blue-800 font-semibold mb-4">"📋 Evidence Package"</div>
                                <div class="space-y-2 text-sm font-mono">
                                    <div class="text-gray-700">"evidence_id: ev-2024-0892-001"</div>
                                    <div class="text-gray-700">"sha256: 7f83b162..."</div>
                                    <div class="text-gray-700">"file: /lib/libanalytics.so"</div>
                                    <div class="text-gray-700">"offset: 0x4A2F0 (304,880 bytes)"</div>
                                    <div class="text-gray-700">"context: 256 bytes before/after"</div>
                                    <div class="text-gray-700">"chain: OTA → sparse → ext4 → file"</div>
                                    <div class="mt-3 text-gray-500">"Reproduction script included..."</div>
                                </div>
                            </div>
                            <div class="order-1 md:order-2">
                                <h2 class="text-3xl font-bold text-gray-900 mb-4">"Court-Safe Evidence"</h2>
                                <p class="text-lg text-gray-600 mb-6">
                                    "Every finding includes complete evidence preservation for legal "
                                    "proceedings, compliance audits, and third-party verification."
                                </p>
                                <ul class="space-y-3">
                                    <FeatureItem text="SHA-256 content hashing"/>
                                    <FeatureItem text="Byte-exact offset and length"/>
                                    <FeatureItem text="Context preservation (surrounding bytes)"/>
                                    <FeatureItem text="Complete extraction chain documentation"/>
                                    <FeatureItem text="Automated reproduction scripts"/>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            // Integration Section
            <section class="py-20 bg-gray-50">
                <div class="container mx-auto px-4">
                    <div class="max-w-3xl mx-auto text-center mb-12">
                        <h2 class="text-3xl font-bold text-gray-900 mb-4">"Flexible Integration"</h2>
                        <p class="text-lg text-gray-600">
                            "Use our platform through the web dashboard, REST API, or command-line tool."
                        </p>
                    </div>
                    <div class="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
                        <div class="bg-white rounded-lg shadow p-6 text-center">
                            <div class="text-4xl mb-4">"🖥️"</div>
                            <h3 class="text-xl font-semibold text-gray-900 mb-2">"Web Dashboard"</h3>
                            <p class="text-gray-600">"Full-featured admin interface for scan management and reporting."</p>
                        </div>
                        <div class="bg-white rounded-lg shadow p-6 text-center">
                            <div class="text-4xl mb-4">"🔌"</div>
                            <h3 class="text-xl font-semibold text-gray-900 mb-2">"REST API"</h3>
                            <p class="text-gray-600">"Programmatic access for CI/CD integration and automation."</p>
                        </div>
                        <div class="bg-white rounded-lg shadow p-6 text-center">
                            <div class="text-4xl mb-4">"⌨️"</div>
                            <h3 class="text-xl font-semibold text-gray-900 mb-2">"CLI Tool"</h3>
                            <p class="text-gray-600">"Command-line scanner for local analysis and scripting."</p>
                        </div>
                    </div>
                </div>
            </section>
        </div>
    }
}

#[component]
fn FeatureItem(text: &'static str) -> impl IntoView {
    view! {
        <li class="flex items-start">
            <span class="text-green-500 mr-2">"✓"</span>
            <span class="text-gray-700">{text}</span>
        </li>
    }
}
