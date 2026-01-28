//! Scans management pages

use leptos::*;
use leptos_router::*;

#[component]
pub fn ScansPage() -> impl IntoView {
    view! {
        <div class="space-y-6">
            <div class="flex justify-between items-center">
                <h1 class="text-3xl font-bold text-gray-900">"Scans"</h1>
                <button class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700">
                    "New Scan"
                </button>
            </div>

            <div class="bg-white rounded-lg shadow">
                <div class="p-4 border-b">
                    <input
                        type="text"
                        placeholder="Search scans..."
                        class="w-full px-4 py-2 border rounded-lg"
                    />
                </div>
                <div class="p-6">
                    <p class="text-gray-500">"Scan list will be loaded here"</p>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn ScanDetail() -> impl IntoView {
    let params = use_params_map();
    let scan_id = move || params.with(|p| p.get("id").cloned().unwrap_or_default());

    view! {
        <div class="space-y-6">
            <div class="flex items-center space-x-4">
                <a href="/scans" class="text-blue-600 hover:underline">"← Back"</a>
                <h1 class="text-3xl font-bold text-gray-900">
                    "Scan Details: " {scan_id}
                </h1>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="lg:col-span-2 space-y-6">
                    <div class="bg-white rounded-lg shadow p-6">
                        <h2 class="text-xl font-semibold mb-4">"Capability Findings"</h2>
                        <CapabilityMatrix/>
                    </div>

                    <div class="bg-white rounded-lg shadow p-6">
                        <h2 class="text-xl font-semibold mb-4">"Claim Verification"</h2>
                        <ClaimResults/>
                    </div>
                </div>

                <div class="space-y-6">
                    <div class="bg-white rounded-lg shadow p-6">
                        <h2 class="text-xl font-semibold mb-4">"Summary"</h2>
                        <ScanSummary/>
                    </div>

                    <div class="bg-white rounded-lg shadow p-6">
                        <h2 class="text-xl font-semibold mb-4">"Actions"</h2>
                        <div class="space-y-2">
                            <button class="w-full bg-blue-600 text-white px-4 py-2 rounded-lg">
                                "Download Report"
                            </button>
                            <button class="w-full bg-gray-200 text-gray-800 px-4 py-2 rounded-lg">
                                "Export Evidence"
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}

#[component]
fn CapabilityMatrix() -> impl IntoView {
    let capabilities = vec![
        ("Networking", "Present", "HIGH", 5),
        ("Telemetry", "Present", "CRITICAL", 3),
        ("Storage", "Present", "MEDIUM", 2),
        ("Update", "Present", "HIGH", 4),
        ("Identity", "Absent", "N/A", 0),
        ("Crypto", "Present", "LOW", 1),
    ];

    view! {
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead>
                    <tr>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">"Capability"</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">"Status"</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">"Severity"</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">"Findings"</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-200">
                    {capabilities.into_iter().map(|(cap, status, severity, count)| {
                        view! {
                            <tr>
                                <td class="px-4 py-3 font-medium">{cap}</td>
                                <td class="px-4 py-3">
                                    <span class=if status == "Present" { "text-red-600" } else { "text-green-600" }>
                                        {status}
                                    </span>
                                </td>
                                <td class="px-4 py-3">{severity}</td>
                                <td class="px-4 py-3">{count}</td>
                            </tr>
                        }
                    }).collect_view()}
                </tbody>
            </table>
        </div>
    }
}

#[component]
fn ClaimResults() -> impl IntoView {
    let claims = vec![
        ("Offline", false, "Network stack detected"),
        ("No Telemetry", false, "Analytics endpoints found"),
        ("No Tracking", true, "No tracking found"),
        ("No Remote Access", false, "OTA update capability"),
    ];

    view! {
        <div class="space-y-3">
            {claims.into_iter().map(|(claim, passed, reason)| {
                view! {
                    <div class=format!("p-4 rounded-lg {}", if passed { "bg-green-50 border border-green-200" } else { "bg-red-50 border border-red-200" })>
                        <div class="flex items-center justify-between">
                            <span class="font-medium">{claim}</span>
                            <span class=if passed { "text-green-600" } else { "text-red-600" }>
                                {if passed { "PASS" } else { "FAIL" }}
                            </span>
                        </div>
                        <p class="text-sm text-gray-600 mt-1">{reason}</p>
                    </div>
                }
            }).collect_view()}
        </div>
    }
}

#[component]
fn ScanSummary() -> impl IntoView {
    view! {
        <dl class="space-y-3">
            <div class="flex justify-between">
                <dt class="text-gray-500">"Status"</dt>
                <dd class="font-medium text-green-600">"Completed"</dd>
            </div>
            <div class="flex justify-between">
                <dt class="text-gray-500">"File Size"</dt>
                <dd class="font-medium">"24.5 MB"</dd>
            </div>
            <div class="flex justify-between">
                <dt class="text-gray-500">"Duration"</dt>
                <dd class="font-medium">"2m 34s"</dd>
            </div>
            <div class="flex justify-between">
                <dt class="text-gray-500">"Total Findings"</dt>
                <dd class="font-medium">"15"</dd>
            </div>
            <div class="flex justify-between">
                <dt class="text-gray-500">"Evidence Items"</dt>
                <dd class="font-medium">"42"</dd>
            </div>
        </dl>
    }
}
