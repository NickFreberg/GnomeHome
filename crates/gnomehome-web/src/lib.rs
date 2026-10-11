//! The GnomeHome dashboard (FR-19): Leptos compiled to WebAssembly.
//!
//! The Pi serves only JSON and these static files. Sorting, counting, filtering,
//! and chart preparation run here in the browser, to keep load off the Pi (NFR-08).
//!
//! Accessibility (WCAG 2.2 AA, from the design system): a skip link, a logical tab
//! order, a visible focus ring, risk and severity always as a word plus an icon,
//! charts with a table and a sentence, new alerts announced politely through a live
//! region, and a warning before the session times out with a way to extend it.

pub mod api;
pub mod icons;
pub mod model;

use std::time::Duration;

use leptos::prelude::*;
use leptos::task::spawn_local;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::icons::{Fence, GnomeFace, LevelBadge};
use crate::model::{Approval, Asset, Incident, Level, Me};

/// Warn this many seconds before the session ends.
const WARN_BEFORE: i64 = 120;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}

fn now_ts() -> String {
    js_sys::Date::new_0().to_iso_string().into()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Devices,
    Incidents,
    Approvals,
}

impl Tab {
    fn label(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Devices => "Devices",
            Tab::Incidents => "Incidents",
            Tab::Approvals => "Approvals",
        }
    }
}

#[component]
pub fn App() -> impl IntoView {
    let me = RwSignal::new(None::<Me>);
    let checking = RwSignal::new(true);
    spawn_local(async move {
        me.set(api::me().await.ok());
        checking.set(false);
    });
    view! {
        {move || {
            if checking.get() {
                view! { <p class="loading" role="status">"Checking your session…"</p> }.into_any()
            } else if let Some(user) = me.get() {
                view! { <Dashboard me=me user=user/> }.into_any()
            } else {
                view! { <Login me=me/> }.into_any()
            }
        }}
    }
}

#[component]
fn Login(me: RwSignal<Option<Me>>) -> impl IntoView {
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match api::login(
                &username.get_untracked(),
                &password.get_untracked(),
                &code.get_untracked(),
            )
            .await
            {
                Ok(user) => me.set(Some(user)),
                Err(e) => {
                    error.set(Some(e));
                    password.set(String::new());
                    code.set(String::new());
                }
            }
            busy.set(false);
        });
    };
    view! {
        <main id="content" class="login">
            <GnomeFace/>
            <h1>"GnomeHome"</h1>
            <p class="muted">"Sign in to see your home network."</p>
            <form on:submit=submit>
                <label for="username">"Username"</label>
                <input id="username" name="username" autocomplete="username" required
                    prop:value=move || username.get()
                    on:input=move |ev| username.set(event_target_value(&ev))/>
                <label for="password">"Password"</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required
                    prop:value=move || password.get()
                    on:input=move |ev| password.set(event_target_value(&ev))/>
                <label for="code">"Code from your authenticator app"</label>
                <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
                    pattern="[0-9]{6}" maxlength="6" required
                    prop:value=move || code.get()
                    on:input=move |ev| code.set(event_target_value(&ev))/>
                <button type="submit" class="primary" prop:disabled=move || busy.get()>"Sign in"</button>
                <p class="error" role="alert">{move || error.get()}</p>
            </form>
        </main>
    }
}

#[component]
fn Dashboard(me: RwSignal<Option<Me>>, user: Me) -> impl IntoView {
    let tab = RwSignal::new(Tab::Overview);
    let assets = RwSignal::new(Vec::<Asset>::new());
    let incidents = RwSignal::new(Vec::<Incident>::new());
    let approvals = RwSignal::new(Vec::<Approval>::new());
    let error = RwSignal::new(None::<String>);
    let announce = RwSignal::new(String::new());
    let warn = RwSignal::new(false);
    let can_approve = user.can_approve();
    let can_resolve = user.can_resolve();
    let sees_approvals = can_resolve;

    let load = move || {
        spawn_local(async move {
            match api::assets().await {
                Ok(list) => assets.set(list),
                Err(e) => error.set(Some(e)),
            }
            match api::incidents().await {
                Ok(list) => {
                    let before = incidents.get_untracked().len();
                    let after = list.len();
                    if before > 0 && after > before {
                        announce.set(format!("{} new incident(s).", after - before));
                    }
                    incidents.set(list);
                }
                Err(e) => error.set(Some(e)),
            }
            if sees_approvals && let Ok(list) = api::approvals().await {
                approvals.set(list);
            }
        });
    };
    load();
    let _ = set_interval_with_handle(load, Duration::from_secs(60));

    // Session timeout: warn first, and allow extending (WCAG 2.2.1).
    let _ = set_interval_with_handle(
        move || {
            let Some(current) = me.get_untracked() else {
                return;
            };
            match model::seconds_between(&now_ts(), &current.expires_at) {
                Some(left) if left <= 0 => me.set(None),
                Some(left) if left <= WARN_BEFORE => warn.set(true),
                _ => {}
            }
        },
        Duration::from_secs(10),
    );
    let stay = move |_| {
        spawn_local(async move {
            let Some(current) = me.get_untracked() else {
                return;
            };
            match api::extend(&current.csrf).await {
                Ok(fresh) => {
                    me.set(Some(fresh));
                    warn.set(false);
                }
                Err(_) => me.set(None),
            }
        });
    };
    let sign_out = move |_| {
        spawn_local(async move {
            if let Some(current) = me.get_untracked() {
                let _ = api::logout(&current.csrf).await;
            }
            me.set(None);
        });
    };
    let csrf = user.csrf.clone();
    let tabs: Vec<Tab> = if sees_approvals {
        vec![Tab::Overview, Tab::Devices, Tab::Incidents, Tab::Approvals]
    } else {
        vec![Tab::Overview, Tab::Devices, Tab::Incidents]
    };

    view! {
        <a class="skip" href="#content">"Skip to content"</a>
        <header class="top">
            <GnomeFace/>
            <div>
                <p class="brand">"GnomeHome"</p>
                <p class="muted">{move || model::status_line(assets.get().len(), incidents.get().len())}</p>
            </div>
            <p class="who">{format!("{} ({})", user.username, user.role)}</p>
            <button class="quiet" on:click=sign_out>"Sign out"</button>
        </header>
        <nav aria-label="Sections">
            {tabs.into_iter().map(|t| view! {
                <button
                    class="tab"
                    aria-current=move || (tab.get() == t).then_some("page")
                    on:click=move |_| tab.set(t)
                >
                    {t.label()}
                </button>
            }).collect_view()}
        </nav>
        <div class="sr-only" aria-live="polite">{move || announce.get()}</div>
        <Show when=move || warn.get()>
            <div class="dialog" role="alertdialog" aria-labelledby="timeout-title">
                <p id="timeout-title"><strong>"Your session is about to end."</strong></p>
                <p>"You'll be signed out in under two minutes."</p>
                <button class="primary" on:click=stay>"Stay signed in"</button>
            </div>
        </Show>
        <p class="error" role="alert">{move || error.get()}</p>
        <main id="content" tabindex="-1">
            {move || match tab.get() {
                Tab::Overview => view! { <Overview assets=assets incidents=incidents approvals=approvals/> }.into_any(),
                Tab::Devices => view! { <Devices assets=assets/> }.into_any(),
                Tab::Incidents => view! {
                    <Incidents incidents=incidents can_resolve=can_resolve csrf=csrf.clone() reload=Callback::new(move |()| load())/>
                }.into_any(),
                Tab::Approvals => view! {
                    <Approvals approvals=approvals can_approve=can_approve csrf=csrf.clone() reload=Callback::new(move |()| load())/>
                }.into_any(),
            }}
        </main>
    }
}

#[component]
fn Overview(
    assets: RwSignal<Vec<Asset>>,
    incidents: RwSignal<Vec<Incident>>,
    approvals: RwSignal<Vec<Approval>>,
) -> impl IntoView {
    let counts = move || model::risk_counts(&assets.get());
    let summary = move || {
        let (counts, unscored) = counts();
        let parts: Vec<String> = counts
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(l, n)| format!("{n} {}", l.word().to_lowercase()))
            .collect();
        let scored = if parts.is_empty() {
            "No risk scores yet".to_owned()
        } else {
            format!("Risk: {}", parts.join(", "))
        };
        if unscored > 0 {
            format!("{scored}; {unscored} not scored yet.")
        } else {
            format!("{scored}.")
        }
    };
    view! {
        <h1>"Overview"</h1>
        <section aria-labelledby="risk-title">
            <h2 id="risk-title">"Devices by risk"</h2>
            <p>{summary}</p>
            <table class="bars">
                <caption class="sr-only">"Number of devices at each risk level"</caption>
                <thead><tr><th scope="col">"Risk"</th><th scope="col">"Devices"</th><th scope="col"><span class="sr-only">"Share"</span></th></tr></thead>
                <tbody>
                    {move || {
                        let (counts, _) = counts();
                        let total = counts.iter().map(|(_, n)| *n).sum::<usize>().max(1);
                        counts.into_iter().map(|(level, n)| view! {
                            <tr>
                                <th scope="row"><LevelBadge level=level/></th>
                                <td>{n}</td>
                                <td>
                                    // SVG, not an inline style: the CSP allows no style attributes.
                                    <svg class=format!("bar {}", level.css()) viewBox="0 0 100 12"
                                        preserveAspectRatio="none" aria-hidden="true" focusable="false">
                                        <rect width=(n * 100 / total).to_string() height="12" rx="6"/>
                                    </svg>
                                </td>
                            </tr>
                        }).collect_view()
                    }}
                </tbody>
            </table>
        </section>
        <section aria-labelledby="open-title">
            <h2 id="open-title">"Open incidents"</h2>
            {move || {
                let list = incidents.get();
                if list.is_empty() {
                    view! { <p class="empty"><Fence/>" All quiet in the garden: no open incidents."</p> }.into_any()
                } else {
                    view! {
                        <ul class="counts">
                            {model::severity_counts(&list).into_iter().map(|(level, n)| view! {
                                <li><LevelBadge level=level/>" "{n}</li>
                            }).collect_view()}
                        </ul>
                    }.into_any()
                }
            }}
            <p>{move || match approvals.get().len() {
                0 => "Nothing is waiting for your approval.".to_owned(),
                1 => "1 response is waiting for approval.".to_owned(),
                n => format!("{n} responses are waiting for approval."),
            }}</p>
        </section>
    }
}

#[component]
fn Devices(assets: RwSignal<Vec<Asset>>) -> impl IntoView {
    let query = RwSignal::new(String::new());
    let shown = move || {
        let mut list: Vec<Asset> = assets
            .get()
            .into_iter()
            .filter(|a| model::matches(a, &query.get()))
            .collect();
        model::sort_by_risk(&mut list);
        list
    };
    view! {
        <h1>"Devices"</h1>
        <label for="search">"Filter by address, maker, name, or type"</label>
        <input id="search" type="search" prop:value=move || query.get()
            on:input=move |ev| query.set(event_target_value(&ev))/>
        <table>
            <caption>{move || format!("{} of {} devices, riskiest first", shown().len(), assets.get().len())}</caption>
            <thead><tr>
                <th scope="col">"Device"</th><th scope="col">"Address"</th><th scope="col">"Type"</th>
                <th scope="col">"Risk"</th><th scope="col">"Last seen"</th>
            </tr></thead>
            <tbody>
                {move || shown().into_iter().map(|a| {
                    let risk = match a.level() {
                        Some(level) => view! {
                            <LevelBadge level=level/>" "
                            <span class="muted">{a.risk_score.map(|s| format!("{s:.0}/100")).unwrap_or_default()}</span>
                            <p class="small">{a.risk_summary.clone().unwrap_or_default()}</p>
                        }.into_any(),
                        None => view! { <span class="muted">"Not scored"</span> }.into_any(),
                    };
                    view! {
                        <tr>
                            <th scope="row">{a.display_name()}</th>
                            <td class="mono">{a.ip.clone().unwrap_or_default()}<br/>{a.mac.clone()}</td>
                            <td>{a.device_type.clone().unwrap_or_else(|| "unknown".into())}</td>
                            <td>{risk}</td>
                            <td class="mono">{a.last_seen.clone()}</td>
                        </tr>
                    }
                }).collect_view()}
            </tbody>
        </table>
    }
}

#[component]
fn Incidents(
    incidents: RwSignal<Vec<Incident>>,
    can_resolve: bool,
    csrf: String,
    reload: Callback<()>,
) -> impl IntoView {
    let csrf = StoredValue::new(csrf);
    view! {
        <h1>"Incidents"</h1>
        {move || {
            let list = incidents.get();
            if list.is_empty() {
                return view! { <p class="empty"><Fence/>" All quiet in the garden: no open incidents."</p> }.into_any();
            }
            list.into_iter().map(|i| {
                let id = i.id;
                let resolve = move |_| {
                    let token = csrf.get_value();
                    spawn_local(async move {
                        if api::resolve(&token, id).await.is_ok() {
                            reload.run(());
                        }
                    });
                };
                let mitre = i.mitre_url().map(|url| view! {
                    <dt>"MITRE ATT&CK"</dt>
                    <dd><a href=url rel="noopener noreferrer" target="_blank">{i.mitre_technique.clone()}</a></dd>
                });
                view! {
                    <article class="incident" aria-labelledby=format!("inc-{id}")>
                        <header>
                            <LevelBadge level=i.level()/>
                            <h2 id=format!("inc-{id}")>{format!("#{id} {}", i.title)}</h2>
                            <p class="muted mono">{i.occurred_at.clone()}</p>
                        </header>
                        <dl>
                            <dt>"Device"</dt><dd>{i.device.clone().unwrap_or_else(|| "Not tied to one device".into())}</dd>
                            <dt>"What happened"</dt><dd>{i.what_happened.clone()}</dd>
                            <dt>"Why it matters"</dt><dd>{i.why_it_matters.clone()}</dd>
                            <dt>"What to do"</dt><dd>{i.next_steps.clone()}</dd>
                            {mitre}
                            <dt>"Status"</dt><dd>{i.status.replace('_', " ")}{i.outcome.clone().map(|o| format!(". {o}"))}</dd>
                        </dl>
                        <Show when=move || can_resolve>
                            <button class="quiet" on:click=resolve>"Mark resolved"</button>
                        </Show>
                    </article>
                }
            }).collect_view().into_any()
        }}
    }
}

#[component]
fn Approvals(
    approvals: RwSignal<Vec<Approval>>,
    can_approve: bool,
    csrf: String,
    reload: Callback<()>,
) -> impl IntoView {
    let csrf = StoredValue::new(csrf);
    view! {
        <h1>"Approvals"</h1>
        <p class="muted">"Disruptive responses wait here. Approving needs a fresh code from your authenticator app."</p>
        {move || {
            let list = approvals.get();
            if list.is_empty() {
                return view! { <p class="empty">"Nothing is waiting for your approval."</p> }.into_any();
            }
            list.into_iter().map(|a| {
                let code = RwSignal::new(String::new());
                let message = RwSignal::new(None::<String>);
                let run = StoredValue::new(a.run_id.clone());
                let decide = move |approve: bool| {
                    let token = csrf.get_value();
                    let run_id = run.get_value();
                    let entered = code.get_untracked();
                    spawn_local(async move {
                        match api::decide(&token, &run_id, approve, &entered).await {
                            Ok(()) => {
                                message.set(Some(if approve {
                                    "Approved. GnomeHome will act within a minute.".into()
                                } else {
                                    "Denied. Nothing will be done.".into()
                                }));
                                reload.run(());
                            }
                            Err(e) => message.set(Some(e)),
                        }
                        code.set(String::new());
                    });
                };
                let level = a.severity.as_deref().and_then(Level::parse).unwrap_or(Level::Medium);
                let field = format!("code-{}", a.run_id);
                view! {
                    <article class="incident">
                        <header>
                            <LevelBadge level=level/>
                            <h2>{a.title.clone().unwrap_or_else(|| a.playbook.clone())}</h2>
                        </header>
                        <p>{a.outcome.clone()}</p>
                        <p class="muted">{format!("{} · expires {}", a.device.clone().unwrap_or_default(), a.expires_at)}</p>
                        {if can_approve {
                            view! {
                                <form class="inline" on:submit=move |ev: leptos::ev::SubmitEvent| { ev.prevent_default(); decide(true) }>
                                    <label for=field.clone()>"Code"</label>
                                    <input id=field inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required
                                        prop:value=move || code.get() on:input=move |ev| code.set(event_target_value(&ev))/>
                                    <button type="submit" class="primary">"Approve"</button>
                                    <button type="button" class="quiet" on:click=move |_| decide(false)>"Deny"</button>
                                </form>
                            }.into_any()
                        } else {
                            view! { <p class="muted">"Only an admin can approve or deny."</p> }.into_any()
                        }}
                        <p role="status">{move || message.get()}</p>
                    </article>
                }
            }).collect_view().into_any()
        }}
    }
}
