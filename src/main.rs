use std::{collections::HashMap, env, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use azalea_auth::{AccessTokenResponse, cache::ExpiringValue};
use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::{Compression, write::GzEncoder};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::crypto::{PublicKey, encrypt_token, parse_public_key};

mod crypto;

const RESULT_TTL: Duration = Duration::from_secs(90);

#[derive(Clone)]
struct AppState {
    sessions: Arc<Mutex<HashMap<Uuid, AuthStatus>>>,
    client: reqwest::Client,
}

#[derive(Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum AuthStatus {
    Complete { token: String },
    Failed { error: String },
    Pending,
}

#[derive(Serialize)]
struct StartResponse {
    verification_uri: String,
    user_code: String,
    session: Uuid,
}

#[derive(Deserialize)]
struct StartQuery {
    #[serde(rename = "pubKey")]
    pub_key: Option<String>,
}

#[derive(Serialize)]
struct AccountToken {
    token: String,
    uuid: Uuid,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState {
        sessions: Default::default(),
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?,
    };

    let app = Router::new()
        .route("/", get(|| async { Html(include_str!("index.html")) }))
        .route("/auth/{session}", get(auth_status))
        .route("/auth", post(start_auth))
        .with_state(state);

    let port = env::var("PORT")
        .unwrap_or_else(|_| "3000".into())
        .parse::<u16>()?;
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;

    println!("listening on http://0.0.0.0:{port}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn start_auth(
    State(state): State<AppState>,
    Query(query): Query<StartQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let public_key = query
        .pub_key
        .as_deref()
        .map(parse_public_key)
        .transpose()
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;

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
            Ok(msa) => encode_token(&state.client, msa, public_key.as_ref())
                .await
                .map(|token| AuthStatus::Complete { token })
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
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let status = state
        .sessions
        .lock()
        .await
        .get(&session)
        .cloned()
        .ok_or((StatusCode::NOT_FOUND, "Session not found or expired"))?;

    Ok(([(header::CACHE_CONTROL, "no-store")], Json(status)))
}

async fn encode_token(
    client: &reqwest::Client,
    msa: ExpiringValue<AccessTokenResponse>,
    public_key: Option<&PublicKey>,
) -> Result<String, String> {
    let minecraft = azalea_auth::get_minecraft_token(client, &msa.data.access_token)
        .await
        .map_err(|error| error.to_string())?;

    let profile = azalea_auth::get_profile(client, &minecraft.minecraft_access_token)
        .await
        .map_err(|error| error.to_string())?;

    let token = match public_key {
        Some(public_key) => encrypt_token(&msa, profile.id.as_bytes(), public_key)?,
        None => STANDARD.encode(serde_json::to_vec(&msa).map_err(|error| error.to_string())?),
    };

    encode_compressed(&AccountToken {
        uuid: profile.id,
        token,
    })
}

fn encode_compressed(value: &impl Serialize) -> Result<String, String> {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::best());
    serde_json::to_writer(&mut gzip, value).map_err(|error| error.to_string())?;

    let compressed = gzip.finish().map_err(|error| error.to_string())?;
    Ok(STANDARD.encode(compressed))
}
