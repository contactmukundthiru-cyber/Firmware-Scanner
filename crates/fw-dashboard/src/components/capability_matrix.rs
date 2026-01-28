//! Capability matrix visualization

use leptos::*;

#[component]
pub fn CapabilityMatrixView() -> impl IntoView {
    view! {
        <div class="grid grid-cols-2 md:grid-cols-3 gap-4">
            <CapabilityCell name="Networking" status="present" severity="high"/>
            <CapabilityCell name="Telemetry" status="present" severity="critical"/>
            <CapabilityCell name="Storage" status="present" severity="medium"/>
            <CapabilityCell name="Update" status="present" severity="high"/>
            <CapabilityCell name="Identity" status="absent" severity="none"/>
            <CapabilityCell name="Crypto" status="present" severity="low"/>
        </div>
    }
}

#[component]
fn CapabilityCell(
    name: &'static str,
    status: &'static str,
    severity: &'static str,
) -> impl IntoView {
    let (bg, border) = match severity {
        "critical" => ("bg-red-100", "border-red-500"),
        "high" => ("bg-orange-100", "border-orange-500"),
        "medium" => ("bg-yellow-100", "border-yellow-500"),
        "low" => ("bg-blue-100", "border-blue-500"),
        _ => ("bg-green-100", "border-green-500"),
    };

    view! {
        <div class=format!("p-4 rounded-lg border-l-4 {} {}", bg, border)>
            <h4 class="font-medium text-gray-900">{name}</h4>
            <p class="text-sm text-gray-600">{status}</p>
        </div>
    }
}
