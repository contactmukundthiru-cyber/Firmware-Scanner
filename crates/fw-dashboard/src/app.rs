//! Main application component

use leptos::*;
use leptos_router::*;
use crate::pages::*;
use crate::components::*;

#[component]
pub fn App() -> impl IntoView {
    view! {
        <Router>
            <div class="min-h-screen bg-gray-100">
                <Nav/>
                <main class="container mx-auto px-4 py-8">
                    <Routes>
                        <Route path="/" view=Dashboard/>
                        <Route path="/scans" view=ScansPage/>
                        <Route path="/scans/:id" view=ScanDetail/>
                        <Route path="/reports" view=ReportsPage/>
                        <Route path="/settings" view=SettingsPage/>
                    </Routes>
                </main>
            </div>
        </Router>
    }
}
