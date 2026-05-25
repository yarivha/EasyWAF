// =========================================================
// routes/dashboard.rs — EasyWAF
// Dashboard: summary counts + recent traffic stats.
// =========================================================

use crate::{auth::get_session, error::Result, AppState};
use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::Serialize;
use tera::Context;

// ─── TrafficSummary ──────────────────────────────────────

#[derive(Debug, Serialize)]
struct TrafficSummary {
    total:   i64,
    blocked: i64,
    allowed: i64,
}

// ─── get_dashboard ───────────────────────────────────────

pub async fn get_dashboard(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    // Summary counts.
    let sites_count: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM sites")
            .fetch_one(&state.db).await?;

    let certs_count: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM certs")
            .fetch_one(&state.db).await?;

    let policies_count: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM policies")
            .fetch_one(&state.db).await?;

    // Traffic stats — last 24 hours.
    let total_requests: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM traffic_events
         WHERE timestamp >= datetime('now', '-1 day')"
    )
    .fetch_one(&state.db).await?;

    let blocked_requests: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM traffic_events
         WHERE blocked = 1 AND timestamp >= datetime('now', '-1 day')"
    )
    .fetch_one(&state.db).await?;

    let traffic = TrafficSummary {
        total:   total_requests,
        blocked: blocked_requests,
        allowed: total_requests - blocked_requests,
    };

    let mut ctx = Context::new();
    ctx.insert("username",       &session.username);
    ctx.insert("title",          "Dashboard");
    ctx.insert("url",            "/");
    ctx.insert("sites_number",   &sites_count);
    ctx.insert("certs_number",   &certs_count);
    ctx.insert("policy_number",  &policies_count);
    ctx.insert("traffic",        &traffic);

    Ok((jar, Html(state.tera.render("dashboard.html", &ctx)?)).into_response())
}
