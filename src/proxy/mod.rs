// =========================================================
// proxy/mod.rs — EasyWAF
// HTTP reverse proxy engine.
//
// Starts a single TCP listener on the configured http_port.
// Incoming requests are routed to a backend site by matching
// the Host: header against sites.server_name in the database.
// Every request is passed through the module pipeline before
// being forwarded to the upstream.
// =========================================================

use crate::modules::{
    traffic::{log_event, TrafficRecord},
    Pipeline, PipelineVerdict, RequestContext,
};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::Response,
    Router,
};

use reqwest::Client;
use sqlx::SqlitePool;
use std::{net::SocketAddr, sync::Arc, time::Instant};
use tokio::net::TcpListener;

// ─── Hop-by-hop headers ──────────────────────────────────

/// Headers that must not be forwarded between proxy and upstream.
const HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

// ─── ProxyState ──────────────────────────────────────────

/// State shared across all proxy request handlers.
#[derive(Clone)]
pub struct ProxyState {
    pub db:       SqlitePool,
    pub pipeline: Arc<Pipeline>,
    pub client:   Client,
}

// ─── SiteRow ─────────────────────────────────────────────

/// Minimal site data fetched per request.
struct SiteRow {
    id:             i64,
    name:           String,
    target:         String,
    hsts:           bool,
    x_frame:        bool,
    x_content_type: bool,
    xss_protection: bool,
}

// ─── start ───────────────────────────────────────────────

/// Bind the proxy listener and start serving. Runs forever.
pub async fn start(state: ProxyState, http_port: u16) {
    let addr = format!("0.0.0.0:{}", http_port);
    let listener = TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("Cannot bind proxy to {}: {}", addr, e));

    tracing::info!("Proxy listening on http://{}", addr);

    let app = Router::new()
        .fallback(handle_request)
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    axum::serve(listener, app)
        .await
        .expect("proxy server error");
}

// ─── handle_request ──────────────────────────────────────

/// Main proxy handler — called for every incoming request.
async fn handle_request(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<ProxyState>,
    req: axum::extract::Request,
) -> Response<Body> {
    let started_at = Instant::now();

    // ── Extract Host header ───────────────────────────────
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(':')        // strip port if present
        .next()
        .unwrap_or("")
        .to_lowercase();

    if host.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Missing Host header");
    }

    // ── Look up site ──────────────────────────────────────
    let site = match lookup_site(&state.db, &host).await {
        Some(s) => s,
        None => {
            tracing::debug!(host = %host, "no site matched");
            return error_response(StatusCode::NOT_FOUND, "No site configured for this host");
        }
    };

    // ── Decompose request ─────────────────────────────────
    let (parts, body) = req.into_parts();
    let method  = parts.method.clone();
    let path    = parts.uri.path().to_string();
    let query   = parts.uri.query().map(str::to_string);
    let headers = parts.headers.clone();
    let client_ip = peer.ip();

    // Buffer the body (needed by WAF modules later).
    let body_bytes = match axum::body::to_bytes(body, 32 * 1024 * 1024).await {
        Ok(b)  => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "Failed to read request body"),
    };

    // ── Build RequestContext ──────────────────────────────
    let ctx = RequestContext {
        site_id:    site.id,
        site_name:  site.name.clone(),
        client_ip,
        method:     method.clone(),
        host:       host.clone(),
        path:       path.clone(),
        query:      query.clone(),
        headers:    headers.clone(),
        body:       body_bytes.clone(),
        started_at,
    };

    // ── Run module pipeline ───────────────────────────────
    let verdict = state.pipeline.run(&ctx).await;

    if let PipelineVerdict::Block { reason, status, .. } = verdict {
        let elapsed = started_at.elapsed().as_millis() as i64;
        let db = state.db.clone();
        let method_str = method.to_string();
        let reason_log = reason.clone();
        tokio::spawn(async move {
            log_event(db, TrafficRecord {
                site_id:      site.id,
                client_ip:    client_ip.to_string(),
                method:       method_str,
                host:         host.clone(),
                path:         path.clone(),
                status_code:  status.as_u16() as i64,
                response_ms:  elapsed,
                blocked:      true,
                block_reason: Some(reason_log),
                waf_score:    None,
                country:      None,
            }).await;
        });
        return error_response(status, &reason);
    }

    // ── Forward to upstream ───────────────────────────────
    let path_and_query = match &query {
        Some(q) => format!("{}?{}", path, q),
        None    => path.clone(),
    };
    let upstream_url = format!(
        "{}{}",
        site.target.trim_end_matches('/'),
        path_and_query
    );

    // Filter hop-by-hop headers before forwarding.
    let mut fwd_headers = headers.clone();
    for h in HOP_HEADERS {
        fwd_headers.remove(*h);
    }

    let upstream_result = state
        .client
        .request(to_reqwest_method(&method), &upstream_url)
        .headers(to_reqwest_headers(&fwd_headers))
        .body(body_bytes)
        .send()
        .await;

    match upstream_result {
        Err(e) => {
            tracing::warn!(upstream = %upstream_url, error = %e, "upstream unreachable");
            let elapsed = started_at.elapsed().as_millis() as i64;
            let db = state.db.clone();
            let method_str = method.to_string();
            tokio::spawn(async move {
                log_event(db, TrafficRecord {
                    site_id:      site.id,
                    client_ip:    client_ip.to_string(),
                    method:       method_str,
                    host,
                    path,
                    status_code:  502,
                    response_ms:  elapsed,
                    blocked:      false,
                    block_reason: None,
                    waf_score:    None,
                    country:      None,
                }).await;
            });
            error_response(StatusCode::BAD_GATEWAY, "Upstream unreachable")
        }

        Ok(upstream_resp) => {
            let status  = upstream_resp.status();
            let resp_headers = upstream_resp.headers().clone();
            let elapsed = started_at.elapsed().as_millis() as i64;

            // Stream the response body back to the client.
            let body_stream = upstream_resp.bytes_stream();
            let body = Body::from_stream(body_stream);

            // Build response, copy upstream headers (minus hop-by-hop).
            let mut resp = Response::builder().status(status);
            if let Some(headers_mut) = resp.headers_mut() {
                for (k, v) in &resp_headers {
                    if !HOP_HEADERS.contains(&k.as_str()) {
                        headers_mut.insert(k, v.clone());
                    }
                }
                // Inject configured security headers.
                inject_security_headers(headers_mut, &site);
            }

            // Log asynchronously.
            let db = state.db.clone();
            let method_str = method.to_string();
            tokio::spawn(async move {
                log_event(db, TrafficRecord {
                    site_id:      site.id,
                    client_ip:    client_ip.to_string(),
                    method:       method_str,
                    host,
                    path,
                    status_code:  status.as_u16() as i64,
                    response_ms:  elapsed,
                    blocked:      false,
                    block_reason: None,
                    waf_score:    None,
                    country:      None,
                }).await;
            });

            resp.body(body).unwrap_or_else(|_| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "Response build error")
            })
        }
    }
}

// ─── lookup_site ─────────────────────────────────────────

/// Find an enabled site matching the given hostname.
async fn lookup_site(db: &SqlitePool, host: &str) -> Option<SiteRow> {
    sqlx::query!(
        "SELECT id as \"id!\", name, target,
                hsts           as \"hsts!: bool\",
                x_frame        as \"x_frame!: bool\",
                x_content_type as \"x_content_type!: bool\",
                xss_protection as \"xss_protection!: bool\"
         FROM sites
         WHERE server_name = ? AND enabled = 1",
        host
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .map(|r| SiteRow {
        id:             r.id,
        name:           r.name,
        target:         r.target,
        hsts:           r.hsts,
        x_frame:        r.x_frame,
        x_content_type: r.x_content_type,
        xss_protection: r.xss_protection,
    })
}

// ─── inject_security_headers ─────────────────────────────

/// Add configured security response headers.
fn inject_security_headers(headers: &mut HeaderMap, site: &SiteRow) {
    if site.hsts {
        headers.insert(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    if site.x_frame {
        headers.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
    }
    if site.x_content_type {
        headers.insert(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        );
    }
    if site.xss_protection {
        headers.insert(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        );
    }
}

// ─── error_response ──────────────────────────────────────

fn error_response(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(msg.to_string()))
        .unwrap()
}

// ─── Header conversion helpers ───────────────────────────

fn to_reqwest_method(m: &Method) -> reqwest::Method {
    reqwest::Method::from_bytes(m.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET)
}

fn to_reqwest_headers(headers: &HeaderMap) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::new();
    for (k, v) in headers {
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_ref()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            out.insert(name, val);
        }
    }
    out
}
