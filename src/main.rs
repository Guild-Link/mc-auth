use std::{collections::HashMap, env, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use azalea_auth::{AccessTokenResponse, cache::ExpiringValue};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use tokio::sync::Mutex;
use uuid::Uuid;

const RESULT_TTL: Duration = Duration::from_secs(90);

#[derive(Clone)]
struct AppState {
    client: reqwest::Client,
    sessions: Arc<Mutex<HashMap<Uuid, AuthStatus>>>,
}

#[derive(Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum AuthStatus {
    Pending,
    Complete { credential: String },
    Failed { error: String },
}

#[derive(Serialize)]
struct StartResponse {
    session: Uuid,
    verification_uri: String,
    user_code: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState {
        client: reqwest::Client::new(),
        sessions: Default::default(),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/auth", post(start_auth))
        .route("/auth/{session}", get(auth_status))
        .with_state(state);

    let port = env::var("PORT").unwrap_or_else(|_| "3000".into());
    let address = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&address).await?;

    println!("listening on http://{address}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn start_auth(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let code = azalea_auth::get_ms_link_code(&state.client, None, None)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let session = Uuid::new_v4();
    let response = StartResponse {
        session,
        verification_uri: code.verification_uri.clone(),
        user_code: code.user_code.clone(),
    };

    state
        .sessions
        .lock()
        .await
        .insert(session, AuthStatus::Pending);
    tokio::spawn(async move {
        let status = match azalea_auth::get_ms_auth_token(&state.client, code, None).await {
            Ok(msa) => encode_credential(msa)
                .map(|credential| AuthStatus::Complete { credential })
                .unwrap_or_else(|error| AuthStatus::Failed { error }),
            Err(error) => AuthStatus::Failed {
                error: error.to_string(),
            },
        };
        state.sessions.lock().await.insert(session, status);
        tokio::time::sleep(RESULT_TTL).await;
        state.sessions.lock().await.remove(&session);
    });

    Ok(([(header::CACHE_CONTROL, "no-store")], Json(response)))
}

async fn auth_status(
    State(state): State<AppState>,
    Path(session): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut sessions = state.sessions.lock().await;
    let status = sessions
        .get(&session)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    if !matches!(&status, AuthStatus::Pending) {
        sessions.remove(&session);
    }

    Ok(([(header::CACHE_CONTROL, "no-store")], Json(status)))
}

fn encode_credential(msa: ExpiringValue<AccessTokenResponse>) -> Result<String, String> {
    let json = serde_json::to_vec(&msa).map_err(|error| error.to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}
