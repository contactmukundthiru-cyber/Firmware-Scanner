//! Dashboard overview page

use leptos::*;

#[component]
pub fn Dashboard() -> impl IntoView {
    let (stats, set_stats) = create_signal(DashboardStats::default());

    // Fetch stats on mount
    create_effect(move |_| {
        spawn_local(async move {
            if let Ok(data) = fetch_stats().await {
                set_stats.set(data);
            }
        });
    });

    view! {
        <div class="space-y-6">
            <h1 class="text-3xl font-bold text-gray-900">"Dashboard"</h1>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard
                    title="Total Scans"
                    value=move || stats.get().total_scans.to_string()
                    icon="scan"
                />
                <StatCard
                    title="Completed"
                    value=move || stats.get().completed_scans.to_string()
                    icon="check"
                />
                <StatCard
                    title="Pending"
                    value=move || stats.get().pending_scans.to_string()
                    icon="clock"
                />
                <StatCard
                    title="Total Findings"
                    value=move || stats.get().total_findings.to_string()
                    icon="alert"
                />
            </div>

            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-xl font-semibold mb-4">"Recent Scans"</h2>
                <RecentScansTable/>
            </div>
        </div>
    }
}

#[component]
fn StatCard(
    title: &'static str,
    value: impl Fn() -> String + 'static,
    icon: &'static str,
) -> impl IntoView {
    view! {
        <div class="bg-white rounded-lg shadow p-6">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-sm text-gray-500">{title}</p>
                    <p class="text-2xl font-bold text-gray-900">{value}</p>
                </div>
                <div class="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
                    <span class="text-blue-600">{icon}</span>
                </div>
            </div>
        </div>
    }
}

#[component]
fn RecentScansTable() -> impl IntoView {
    let (scans, set_scans) = create_signal(Vec::<Scan>::new());

    create_effect(move |_| {
        spawn_local(async move {
            if let Ok(data) = fetch_recent_scans().await {
                set_scans.set(data);
            }
        });
    });

    view! {
        <table class="min-w-full divide-y divide-gray-200">
            <thead>
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">"Name"</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">"Status"</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">"Findings"</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">"Created"</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                <For
                    each=move || scans.get()
                    key=|scan| scan.id.clone()
                    children=move |scan| {
                        view! {
                            <tr>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <a href=format!("/scans/{}", scan.id) class="text-blue-600 hover:underline">
                                        {scan.name.clone()}
                                    </a>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <StatusBadge status=scan.status.clone()/>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">{scan.findings_count}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{scan.created_at.clone()}</td>
                            </tr>
                        }
                    }
                />
            </tbody>
        </table>
    }
}

#[component]
fn StatusBadge(status: String) -> impl IntoView {
    let (bg, text) = match status.as_str() {
        "completed" => ("bg-green-100", "text-green-800"),
        "running" => ("bg-blue-100", "text-blue-800"),
        "failed" => ("bg-red-100", "text-red-800"),
        _ => ("bg-gray-100", "text-gray-800"),
    };

    view! {
        <span class=format!("px-2 py-1 text-xs font-medium rounded-full {} {}", bg, text)>
            {status}
        </span>
    }
}

#[derive(Clone, Default)]
struct DashboardStats {
    total_scans: i64,
    completed_scans: i64,
    pending_scans: i64,
    total_findings: i64,
}

#[derive(Clone)]
struct Scan {
    id: String,
    name: String,
    status: String,
    findings_count: i64,
    created_at: String,
}

async fn fetch_stats() -> Result<DashboardStats, ()> {
    // In production, fetch from API
    Ok(DashboardStats {
        total_scans: 42,
        completed_scans: 38,
        pending_scans: 4,
        total_findings: 156,
    })
}

async fn fetch_recent_scans() -> Result<Vec<Scan>, ()> {
    // In production, fetch from API
    Ok(vec![
        Scan {
            id: "1".to_string(),
            name: "router-firmware-v2.1.bin".to_string(),
            status: "completed".to_string(),
            findings_count: 12,
            created_at: "2024-01-15 10:30".to_string(),
        },
        Scan {
            id: "2".to_string(),
            name: "camera-firmware.img".to_string(),
            status: "running".to_string(),
            findings_count: 0,
            created_at: "2024-01-15 11:45".to_string(),
        },
    ])
}
