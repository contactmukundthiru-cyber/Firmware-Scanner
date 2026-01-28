//! Card components for marketing pages

use leptos::*;

#[component]
pub fn ProblemCard(
    icon: &'static str,
    title: &'static str,
    description: &'static str,
) -> impl IntoView {
    view! {
        <div class="bg-white rounded-xl shadow-lg p-6 text-center">
            <div class="text-4xl mb-4">{icon}</div>
            <h3 class="text-xl font-semibold text-gray-900 mb-2">{title}</h3>
            <p class="text-gray-600">{description}</p>
        </div>
    }
}

#[component]
pub fn StepCard(
    number: &'static str,
    title: &'static str,
    description: &'static str,
) -> impl IntoView {
    view! {
        <div class="text-center">
            <div class="w-12 h-12 bg-indigo-600 text-white rounded-full flex items-center justify-center text-xl font-bold mx-auto mb-4">
                {number}
            </div>
            <h3 class="text-xl font-semibold text-gray-900 mb-2">{title}</h3>
            <p class="text-gray-600">{description}</p>
        </div>
    }
}

#[component]
pub fn CapabilityCard(
    icon: &'static str,
    title: &'static str,
    items: Vec<&'static str>,
) -> impl IntoView {
    view! {
        <div class="bg-gray-800 rounded-lg p-6">
            <div class="text-3xl mb-3">{icon}</div>
            <h3 class="text-xl font-semibold mb-3">{title}</h3>
            <ul class="space-y-2 text-gray-400 text-sm">
                {items.into_iter().map(|item| view! {
                    <li class="flex items-center">
                        <span class="text-cyan-400 mr-2">"•"</span>
                        {item}
                    </li>
                }).collect::<Vec<_>>()}
            </ul>
        </div>
    }
}

#[component]
pub fn ClaimCard(
    claim: &'static str,
    description: &'static str,
) -> impl IntoView {
    view! {
        <div class="bg-white rounded-lg shadow p-6 border-l-4 border-green-500">
            <h3 class="font-semibold text-gray-900 mb-2">{claim}</h3>
            <p class="text-sm text-gray-600">{description}</p>
        </div>
    }
}

#[component]
pub fn TestimonialCard(
    quote: &'static str,
    author: &'static str,
    role: &'static str,
) -> impl IntoView {
    view! {
        <div class="bg-white rounded-xl shadow-lg p-8">
            <p class="text-gray-700 italic mb-6">"\""{ quote }"\""</p>
            <div>
                <p class="font-semibold text-gray-900">{author}</p>
                <p class="text-sm text-gray-600">{role}</p>
            </div>
        </div>
    }
}

#[component]
pub fn FeatureHighlight(
    icon: &'static str,
    title: &'static str,
    description: &'static str,
) -> impl IntoView {
    view! {
        <div class="flex items-start">
            <div class="flex-shrink-0 w-12 h-12 bg-indigo-100 rounded-lg flex items-center justify-center">
                <span class="text-xl">{icon}</span>
            </div>
            <div class="ml-4">
                <h3 class="font-semibold text-gray-900">{title}</h3>
                <p class="text-gray-600 text-sm mt-1">{description}</p>
            </div>
        </div>
    }
}

#[component]
pub fn StatCard(
    value: &'static str,
    label: &'static str,
) -> impl IntoView {
    view! {
        <div class="text-center">
            <div class="text-4xl font-bold text-indigo-600">{value}</div>
            <div class="text-gray-600 mt-1">{label}</div>
        </div>
    }
}
