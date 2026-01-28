//! Home page

use leptos::*;
use crate::components::*;

#[component]
pub fn HomePage() -> impl IntoView {
    view! {
        <div>
            // Hero Section
            <section class="bg-gradient-to-br from-indigo-900 via-purple-900 to-indigo-800 text-white">
                <div class="container mx-auto px-4 py-24">
                    <div class="max-w-4xl mx-auto text-center">
                        <h1 class="text-5xl md:text-6xl font-bold mb-6">
                            "Know What Your Firmware "
                            <span class="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400">
                                "Really Does"
                            </span>
                        </h1>
                        <p class="text-xl md:text-2xl text-gray-300 mb-8">
                            "Static analysis platform that detects hidden capabilities, verifies vendor claims, "
                            "and preserves court-safe evidence from IoT and embedded firmware."
                        </p>
                        <div class="flex flex-col sm:flex-row gap-4 justify-center">
                            <a href="/contact" class="px-8 py-4 bg-cyan-500 hover:bg-cyan-400 text-white font-semibold rounded-lg transition">
                                "Request Demo"
                            </a>
                            <a href="/features" class="px-8 py-4 bg-white/10 hover:bg-white/20 text-white font-semibold rounded-lg border border-white/30 transition">
                                "Learn More"
                            </a>
                        </div>
                    </div>
                </div>
            </section>

            // Problem Statement
            <section class="py-20 bg-gray-50">
                <div class="container mx-auto px-4">
                    <div class="max-w-3xl mx-auto text-center mb-16">
                        <h2 class="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
                            "The Hidden Firmware Problem"
                        </h2>
                        <p class="text-lg text-gray-600">
                            "IoT devices often contain capabilities their vendors never disclosed. "
                            "Telemetry endpoints, remote update mechanisms, and tracking identifiers "
                            "lurk in firmware binaries, invisible to traditional security tools."
                        </p>
                    </div>
                    <div class="grid md:grid-cols-3 gap-8">
                        <ProblemCard
                            icon="📡"
                            title="Hidden Telemetry"
                            description="Devices phone home to analytics services, uploading usage data without user consent or knowledge."
                        />
                        <ProblemCard
                            icon="🔄"
                            title="Undisclosed Updates"
                            description="Remote code execution capabilities enable silent firmware changes, bypassing your change management."
                        />
                        <ProblemCard
                            icon="🔍"
                            title="Dormant Features"
                            description="Disabled-but-present code can be activated remotely, turning compliant devices into data collectors."
                        />
                    </div>
                </div>
            </section>

            // How It Works
            <section class="py-20 bg-white">
                <div class="container mx-auto px-4">
                    <div class="max-w-3xl mx-auto text-center mb-16">
                        <h2 class="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
                            "How It Works"
                        </h2>
                        <p class="text-lg text-gray-600">
                            "Upload firmware, get comprehensive capability analysis with court-admissible evidence."
                        </p>
                    </div>
                    <div class="grid md:grid-cols-4 gap-8">
                        <StepCard
                            number="1"
                            title="Upload"
                            description="Upload firmware images in any format: OTA packages, flash dumps, or filesystem images."
                        />
                        <StepCard
                            number="2"
                            title="Extract"
                            description="Automatic container detection and recursive extraction of nested filesystems."
                        />
                        <StepCard
                            number="3"
                            title="Analyze"
                            description="Six specialized detectors scan for networking, telemetry, storage, update, identity, and crypto capabilities."
                        />
                        <StepCard
                            number="4"
                            title="Report"
                            description="Receive detailed findings with evidence preservation for compliance and legal proceedings."
                        />
                    </div>
                </div>
            </section>

            // Capabilities Grid
            <section class="py-20 bg-gray-900 text-white">
                <div class="container mx-auto px-4">
                    <div class="max-w-3xl mx-auto text-center mb-16">
                        <h2 class="text-3xl md:text-4xl font-bold mb-4">
                            "Six Capability Detectors"
                        </h2>
                        <p class="text-lg text-gray-400">
                            "Comprehensive analysis across all firmware communication and data handling vectors."
                        </p>
                    </div>
                    <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                        <CapabilityCard
                            icon="🌐"
                            title="Networking"
                            items=vec!["TCP/IP stacks", "Socket APIs", "Protocol handlers", "URL patterns"]
                        />
                        <CapabilityCard
                            icon="📊"
                            title="Telemetry"
                            items=vec!["Analytics endpoints", "Crash reporters", "Usage metrics", "Data serialization"]
                        />
                        <CapabilityCard
                            icon="💾"
                            title="Storage"
                            items=vec!["Persistent data", "Configuration files", "Log mechanisms", "Cache structures"]
                        />
                        <CapabilityCard
                            icon="🔄"
                            title="Update"
                            items=vec!["OTA mechanisms", "Remote control", "Command channels", "Update protocols"]
                        />
                        <CapabilityCard
                            icon="🆔"
                            title="Identity"
                            items=vec!["Device fingerprints", "Hardware IDs", "Tracking tokens", "Correlation data"]
                        />
                        <CapabilityCard
                            icon="🔐"
                            title="Crypto"
                            items=vec!["Encryption libs", "Key storage", "Certificate handling", "Hash functions"]
                        />
                    </div>
                </div>
            </section>

            // Claim Verification
            <section class="py-20 bg-white">
                <div class="container mx-auto px-4">
                    <div class="max-w-3xl mx-auto text-center mb-16">
                        <h2 class="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
                            "Verify Vendor Claims"
                        </h2>
                        <p class="text-lg text-gray-600">
                            "Automatically validate marketing claims against actual firmware capabilities."
                        </p>
                    </div>
                    <div class="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
                        <ClaimCard claim="Offline Mode" description="No network stack or external endpoints"/>
                        <ClaimCard claim="No Telemetry" description="No analytics, metrics, or phone-home code"/>
                        <ClaimCard claim="No Tracking" description="No device fingerprinting or correlation"/>
                        <ClaimCard claim="Air-Gapped" description="No communication capabilities whatsoever"/>
                    </div>
                </div>
            </section>

            // CTA Section
            <section class="py-20 bg-gradient-to-r from-cyan-600 to-blue-600 text-white">
                <div class="container mx-auto px-4 text-center">
                    <h2 class="text-3xl md:text-4xl font-bold mb-4">
                        "Ready to See What's Really in Your Firmware?"
                    </h2>
                    <p class="text-xl text-cyan-100 mb-8 max-w-2xl mx-auto">
                        "Get a free analysis of your firmware image and discover hidden capabilities."
                    </p>
                    <a href="/contact" class="inline-block px-8 py-4 bg-white text-blue-600 font-semibold rounded-lg hover:bg-gray-100 transition">
                        "Get Started Free"
                    </a>
                </div>
            </section>
        </div>
    }
}
