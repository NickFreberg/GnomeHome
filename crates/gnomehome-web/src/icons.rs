//! Line icons from the design system: 2 px strokes on a 24 px grid, round caps,
//! one color (`currentColor`). Every icon is decorative (`aria-hidden`); the word
//! next to it carries the meaning.

use leptos::prelude::*;

use crate::model::Level;

#[component]
pub fn Sprout() -> impl IntoView {
    view! {
        <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d="M12 21v-9M12 12c0-4 3-6 7-6 0 4-3 6-7 6zM12 14c0-3-2-5-6-5 0 3 2 5 6 5z"/>
        </svg>
    }
}

#[component]
pub fn Lantern() -> impl IntoView {
    view! {
        <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d="M9 4h6M12 2v2M8 7h8l-1 11H9zM7 21h10M10 11l2 3 2-3"/>
        </svg>
    }
}

#[component]
pub fn Hat() -> impl IntoView {
    view! {
        <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d="M12 2L5 18h14zM3 18h18v3H3z"/>
        </svg>
    }
}

#[component]
pub fn Fence() -> impl IntoView {
    view! {
        <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d="M5 21V7l2-3 2 3v14M15 21V7l2-3 2 3v14M3 11h18M3 16h18"/>
        </svg>
    }
}

/// The gnome logomark: red pointed hat over a white beard, two dot eyes.
#[component]
pub fn GnomeFace() -> impl IntoView {
    view! {
        <svg class="logo" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
            <path class="logo-hat" d="M32 4L14 34h36z"/>
            <path class="logo-beard" d="M16 34h32c0 14-8 24-16 26-8-2-16-12-16-26z"/>
            <circle class="logo-eye" cx="26" cy="38" r="2.5"/>
            <circle class="logo-eye" cx="38" cy="38" r="2.5"/>
        </svg>
    }
}

/// A risk or severity level: icon plus word, never color alone.
#[component]
pub fn LevelBadge(level: Level) -> impl IntoView {
    let icon = match level {
        Level::Low => view! { <Sprout/> }.into_any(),
        Level::Medium => view! { <Lantern/> }.into_any(),
        Level::High | Level::Critical => view! { <Hat/> }.into_any(),
    };
    let strong = matches!(level, Level::High | Level::Critical);
    view! {
        <span class=format!("badge {}", level.css())>
            {icon}
            {if strong {
                view! { <strong>{level.word()}</strong> }.into_any()
            } else {
                view! { <span>{level.word()}</span> }.into_any()
            }}
        </span>
    }
}
