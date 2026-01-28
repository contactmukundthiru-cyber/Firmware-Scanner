//! Main application component

use leptos::*;
use leptos_router::*;
use crate::pages::*;
use crate::components::*;

#[component]
pub fn App() -> impl IntoView {
    view! {
        <Router>
            <div class="min-h-screen bg-white">
                <MarketingNav/>
                <main>
                    <Routes>
                        <Route path="/" view=HomePage/>
                        <Route path="/features" view=FeaturesPage/>
                        <Route path="/pricing" view=PricingPage/>
                        <Route path="/contact" view=ContactPage/>
                        <Route path="/docs" view=DocsPage/>
                    </Routes>
                </main>
                <Footer/>
            </div>
        </Router>
    }
}
