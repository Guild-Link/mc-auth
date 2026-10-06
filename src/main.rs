use std::{collections::HashMap, env, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use azalea_auth::DeviceCodeResponse;
use crypto_box::PublicKey;
use ed25519_dalek::SigningKey;
use serde::Serialize;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::crypto::{Error, encrypt_token, parse_public_key, parse_signing_key, sign, timestamp};

mod crypto;

const RESULT_TTL: Duration = Duration::from_secs(90);

#[derive(Clone)]
struct AppState {
    sessions: Arc<Mutex<HashMap<Uuid, Status>>>,
    client: reqwest::Client,
    signing_key: SigningKey,
}

type Status = Option<Result<String, String>>;

#[derive(Serialize)]
struct StartResponse {
    verification_uri: String,
    user_code: String,
    session: Uuid,
}

#[derive(Serialize)]
struct AccountToken {
    created_at: u64,
    username: String,
    token: String,
    uuid: Uuid,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let state = AppState {
        signing_key: parse_signing_key(&env::var("SIGNING_KEY")?)?,
        sessions: Arc::default(),
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?,
    };

    let app = Router::new()
        .route("/", get(|| async { Html(include_str!("index.html")) }))
        .route("/status", post(auth_status))
        .route("/start", post(start_auth))
        .with_state(state);

    let port = env::var("PORT").unwrap_or_else(|_| "3000".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;

    println!("listening on http://0.0.0.0:{port}");
    Ok(axum::serve(listener, app).await?)
}

async fn start_auth(
    State(state): State<AppState>,
    key: String,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let public_key =
        parse_public_key(&key).map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;

    let code = azalea_auth::get_ms_link_code(&state.client, None, None)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let session = Uuid::new_v4();
    let response = StartResponse {
        verification_uri: code.verification_uri.clone(),
        user_code: code.user_code.clone(),
        session,
    };

    state.sessions.lock().await.insert(session, None);

    tokio::spawn(async move {
        let status = fetch_account(&state, code, public_key)
            .await
            .map_err(|error| error.to_string());

        state.sessions.lock().await.insert(session, Some(status));
        tokio::time::sleep(RESULT_TTL).await;
        state.sessions.lock().await.remove(&session);
    });

    Ok(Json(response))
}

async fn auth_status(State(state): State<AppState>, session: String) -> Response {
    let Ok(session) = Uuid::parse_str(&session) else {
        return (StatusCode::BAD_REQUEST, "invalid session").into_response();
    };

    match state.sessions.lock().await.get(&session).cloned() {
        None => (StatusCode::NOT_FOUND, "Session not found or expired").into_response(),
        Some(None) => StatusCode::ACCEPTED.into_response(),
        Some(Some(Ok(token))) => token.into_response(),
        Some(Some(Err(error))) => (StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    }
}

async fn fetch_account(
    state: &AppState,
    code: DeviceCodeResponse,
    public_key: PublicKey,
) -> Result<String, Error> {
    let client = &state.client;
    let msa = azalea_auth::get_ms_auth_token(client, code, None).await?;
    let mc = azalea_auth::get_minecraft_token(client, &msa.data.access_token).await?;
    let profile = azalea_auth::get_profile(client, &mc.minecraft_access_token).await?;

    let auth = (msa.data.refresh_token, mc.minecraft_access_token);
    let account = AccountToken {
        token: encrypt_token(&auth, &public_key)?,
        created_at: timestamp(),
        username: profile.name,
        uuid: profile.id,
    };

    sign(&account, &state.signing_key)
}
