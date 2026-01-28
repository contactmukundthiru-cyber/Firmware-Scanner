//! Documentation page

use leptos::*;

#[component]
pub fn DocsPage() -> impl IntoView {
    view! {
        <div>
            // Hero
            <section class="bg-gradient-to-br from-gray-900 to-gray-800 text-white py-20">
                <div class="container mx-auto px-4">
                    <div class="max-w-3xl mx-auto text-center">
                        <h1 class="text-4xl md:text-5xl font-bold mb-6">"Documentation"</h1>
                        <p class="text-xl text-gray-300">
                            "Learn how to use Firmware Scanner effectively."
                        </p>
                    </div>
                </div>
            </section>

            // Docs Content
            <section class="py-20 bg-white">
                <div class="container mx-auto px-4">
                    <div class="grid md:grid-cols-4 gap-8 max-w-6xl mx-auto">
                        // Sidebar
                        <nav class="md:col-span-1">
                            <div class="sticky top-8 space-y-6">
                                <div>
                                    <h3 class="font-semibold text-gray-900 mb-3">"Getting Started"</h3>
                                    <ul class="space-y-2 text-sm">
                                        <li><a href="#quickstart" class="text-indigo-600 hover:text-indigo-800">"Quick Start"</a></li>
                                        <li><a href="#upload" class="text-gray-600 hover:text-gray-900">"Uploading Firmware"</a></li>
                                        <li><a href="#results" class="text-gray-600 hover:text-gray-900">"Understanding Results"</a></li>
                                    </ul>
                                </div>
                                <div>
                                    <h3 class="font-semibold text-gray-900 mb-3">"Capabilities"</h3>
                                    <ul class="space-y-2 text-sm">
                                        <li><a href="#networking" class="text-gray-600 hover:text-gray-900">"Networking Detection"</a></li>
                                        <li><a href="#telemetry" class="text-gray-600 hover:text-gray-900">"Telemetry Detection"</a></li>
                                        <li><a href="#claims" class="text-gray-600 hover:text-gray-900">"Claim Verification"</a></li>
                                    </ul>
                                </div>
                                <div>
                                    <h3 class="font-semibold text-gray-900 mb-3">"API Reference"</h3>
                                    <ul class="space-y-2 text-sm">
                                        <li><a href="#auth" class="text-gray-600 hover:text-gray-900">"Authentication"</a></li>
                                        <li><a href="#endpoints" class="text-gray-600 hover:text-gray-900">"Endpoints"</a></li>
                                        <li><a href="#webhooks" class="text-gray-600 hover:text-gray-900">"Webhooks"</a></li>
                                    </ul>
                                </div>
                            </div>
                        </nav>

                        // Main Content
                        <div class="md:col-span-3 prose prose-lg max-w-none">
                            <section id="quickstart" class="mb-12">
                                <h2 class="text-2xl font-bold text-gray-900 mb-4">"Quick Start"</h2>
                                <p class="text-gray-600 mb-4">
                                    "Get started with Firmware Scanner in under 5 minutes. This guide covers "
                                    "the basics of uploading firmware and interpreting results."
                                </p>

                                <h3 class="text-xl font-semibold text-gray-900 mt-8 mb-3">"Step 1: Upload Your Firmware"</h3>
                                <p class="text-gray-600 mb-4">
                                    "Navigate to the dashboard and click \"New Scan\". Upload your firmware "
                                    "image in any supported format (OTA, flash dump, filesystem image, or archive)."
                                </p>
                                <div class="bg-gray-100 rounded-lg p-4 font-mono text-sm mb-4">
                                    "# Using the CLI\n"
                                    "fw-scanner scan ./firmware.bin --output report.json"
                                </div>

                                <h3 class="text-xl font-semibold text-gray-900 mt-8 mb-3">"Step 2: Wait for Analysis"</h3>
                                <p class="text-gray-600 mb-4">
                                    "The scanner will automatically detect the container type, extract nested "
                                    "filesystems, and run all six capability detectors. This typically takes "
                                    "1-5 minutes depending on firmware size."
                                </p>

                                <h3 class="text-xl font-semibold text-gray-900 mt-8 mb-3">"Step 3: Review Results"</h3>
                                <p class="text-gray-600 mb-4">
                                    "Once complete, you'll see a comprehensive report showing detected "
                                    "capabilities, claim verification status, and any dormant features found."
                                </p>
                            </section>

                            <section id="upload" class="mb-12">
                                <h2 class="text-2xl font-bold text-gray-900 mb-4">"Supported Formats"</h2>
                                <p class="text-gray-600 mb-4">
                                    "Firmware Scanner supports a wide range of firmware formats and automatically "
                                    "detects container types using magic byte signatures."
                                </p>

                                <div class="grid md:grid-cols-2 gap-4 mt-6">
                                    <div class="bg-gray-50 rounded-lg p-4">
                                        <h4 class="font-semibold text-gray-900 mb-2">"Container Formats"</h4>
                                        <ul class="text-sm text-gray-600 space-y-1">
                                            <li>"• Android OTA packages"</li>
                                            <li>"• Android sparse images"</li>
                                            <li>"• ZIP, TAR, CPIO archives"</li>
                                            <li>"• GZIP, BZIP2, XZ, LZ4, ZSTD"</li>
                                        </ul>
                                    </div>
                                    <div class="bg-gray-50 rounded-lg p-4">
                                        <h4 class="font-semibold text-gray-900 mb-2">"Filesystem Images"</h4>
                                        <ul class="text-sm text-gray-600 space-y-1">
                                            <li>"• SquashFS"</li>
                                            <li>"• CramFS"</li>
                                            <li>"• ext4"</li>
                                            <li>"• JFFS2, YAFFS, UBI/UBIFS"</li>
                                        </ul>
                                    </div>
                                </div>
                            </section>

                            <section id="networking" class="mb-12">
                                <h2 class="text-2xl font-bold text-gray-900 mb-4">"Networking Detection"</h2>
                                <p class="text-gray-600 mb-4">
                                    "The networking detector identifies network communication capabilities "
                                    "in firmware binaries. It looks for:"
                                </p>
                                <ul class="list-disc pl-6 text-gray-600 space-y-2 mb-4">
                                    <li>"TCP/IP stack implementations (lwIP, uIP, FreeRTOS+TCP)"</li>
                                    <li>"Socket API symbols (socket, connect, send, recv)"</li>
                                    <li>"HTTP client libraries (libcurl, OpenSSL)"</li>
                                    <li>"Hardcoded URLs and IP addresses"</li>
                                    <li>"IoT protocols (MQTT, CoAP, AMQP)"</li>
                                </ul>

                                <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mt-6">
                                    <h4 class="font-semibold text-yellow-800 mb-2">"Severity Levels"</h4>
                                    <ul class="text-sm text-yellow-700 space-y-1">
                                        <li>"<strong>Critical:</strong> External endpoints to known telemetry services"</li>
                                        <li>"<strong>High:</strong> General HTTP/HTTPS client capabilities"</li>
                                        <li>"<strong>Medium:</strong> Local network communication only"</li>
                                        <li>"<strong>Low:</strong> Protocol handlers without active usage"</li>
                                    </ul>
                                </div>
                            </section>

                            <section id="claims" class="mb-12">
                                <h2 class="text-2xl font-bold text-gray-900 mb-4">"Claim Verification"</h2>
                                <p class="text-gray-600 mb-4">
                                    "Verify vendor marketing claims against actual firmware capabilities. "
                                    "The claim engine checks for conditions that would violate each claim."
                                </p>

                                <div class="space-y-4 mt-6">
                                    <div class="border border-gray-200 rounded-lg p-4">
                                        <h4 class="font-semibold text-gray-900">"\"Offline Mode\" Claim"</h4>
                                        <p class="text-sm text-gray-600 mt-1">
                                            "Requires: No networking capability, no external endpoints, no TCP/IP stack"
                                        </p>
                                    </div>
                                    <div class="border border-gray-200 rounded-lg p-4">
                                        <h4 class="font-semibold text-gray-900">"\"No Telemetry\" Claim"</h4>
                                        <p class="text-sm text-gray-600 mt-1">
                                            "Requires: No telemetry capability, no analytics endpoints, no crash reporting"
                                        </p>
                                    </div>
                                    <div class="border border-gray-200 rounded-lg p-4">
                                        <h4 class="font-semibold text-gray-900">"\"No Tracking\" Claim"</h4>
                                        <p class="text-sm text-gray-600 mt-1">
                                            "Requires: No identity capability, no device fingerprinting, no hardware ID access"
                                        </p>
                                    </div>
                                </div>
                            </section>

                            <section id="auth" class="mb-12">
                                <h2 class="text-2xl font-bold text-gray-900 mb-4">"API Authentication"</h2>
                                <p class="text-gray-600 mb-4">
                                    "The Firmware Scanner API uses JWT tokens for authentication. "
                                    "Include the token in the Authorization header."
                                </p>

                                <div class="bg-gray-900 rounded-lg p-4 text-white font-mono text-sm">
                                    <div class="text-gray-400">"# Authenticate"</div>
                                    <div>"curl -X POST https://api.firmwarescanner.io/auth/login \\"</div>
                                    <div class="pl-4">"-H \"Content-Type: application/json\" \\"</div>
                                    <div class="pl-4">"-d '{\"email\": \"user@example.com\", \"password\": \"...\"}'"</div>
                                    <div class="mt-4 text-gray-400">"# Use token in requests"</div>
                                    <div>"curl https://api.firmwarescanner.io/scans \\"</div>
                                    <div class="pl-4">"-H \"Authorization: Bearer YOUR_TOKEN\""</div>
                                </div>
                            </section>

                            <section id="endpoints" class="mb-12">
                                <h2 class="text-2xl font-bold text-gray-900 mb-4">"API Endpoints"</h2>

                                <div class="space-y-4">
                                    <div class="border border-gray-200 rounded-lg overflow-hidden">
                                        <div class="bg-gray-50 px-4 py-2 border-b border-gray-200">
                                            <code class="text-sm">
                                                <span class="text-green-600 font-semibold">"POST"</span>
                                                " /api/scans"
                                            </code>
                                        </div>
                                        <div class="px-4 py-3">
                                            <p class="text-sm text-gray-600">"Create a new scan. Upload firmware as multipart form data."</p>
                                        </div>
                                    </div>

                                    <div class="border border-gray-200 rounded-lg overflow-hidden">
                                        <div class="bg-gray-50 px-4 py-2 border-b border-gray-200">
                                            <code class="text-sm">
                                                <span class="text-blue-600 font-semibold">"GET"</span>
                                                " /api/scans/:id"
                                            </code>
                                        </div>
                                        <div class="px-4 py-3">
                                            <p class="text-sm text-gray-600">"Get scan details including status and results."</p>
                                        </div>
                                    </div>

                                    <div class="border border-gray-200 rounded-lg overflow-hidden">
                                        <div class="bg-gray-50 px-4 py-2 border-b border-gray-200">
                                            <code class="text-sm">
                                                <span class="text-blue-600 font-semibold">"GET"</span>
                                                " /api/scans/:id/findings"
                                            </code>
                                        </div>
                                        <div class="px-4 py-3">
                                            <p class="text-sm text-gray-600">"Get all findings from a completed scan."</p>
                                        </div>
                                    </div>

                                    <div class="border border-gray-200 rounded-lg overflow-hidden">
                                        <div class="bg-gray-50 px-4 py-2 border-b border-gray-200">
                                            <code class="text-sm">
                                                <span class="text-blue-600 font-semibold">"GET"</span>
                                                " /api/scans/:id/report"
                                            </code>
                                        </div>
                                        <div class="px-4 py-3">
                                            <p class="text-sm text-gray-600">"Download the generated report in JSON, PDF, or Markdown format."</p>
                                        </div>
                                    </div>
                                </div>
                            </section>
                        </div>
                    </div>
                </div>
            </section>
        </div>
    }
}
