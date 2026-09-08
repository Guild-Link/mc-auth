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
use hpke::{
    Deserializable, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, setup_sender,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

type RecipientKey = <X25519HkdfSha256 as hpke::Kem>::PublicKey;
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
    Failed { error: String },
    Complete { token: String },
}

#[derive(Serialize)]
struct StartResponse {
    session: Uuid,
    user_code: String,
    verification_uri: String,
}

#[derive(Deserialize)]
struct StartQuery {
    #[serde(rename = "pubKey")]
    pub_key: Option<String>,
}

#[derive(Serialize)]
struct AccountToken {
    uuid: Uuid,
    token: String,
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

async fn encode_token(
    client: &reqwest::Client,
    msa: ExpiringValue<AccessTokenResponse>,
    public_key: Option<&RecipientKey>,
) -> Result<String, String> {
    let minecraft = azalea_auth::get_minecraft_token(client, &msa.data.access_token)
        .await
        .map_err(|error| error.to_string())?;

    let profile = azalea_auth::get_profile(client, &minecraft.minecraft_access_token)
        .await
        .map_err(|error| error.to_string())?;

    let token = serde_json::to_vec(&msa).map_err(|error| error.to_string())?;
    let token = match public_key {
        Some(public_key) => encrypt(&token, &profile.id, public_key)?,
        None => STANDARD.encode(token),
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

fn parse_public_key(encoded: &str) -> Result<RecipientKey, String> {
    if encoded.len() != 64 || !encoded.is_ascii() {
        return Err("pubKey must be a 64-character hexadecimal X25519 public key".into());
    }

    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .map_err(|_| "pubKey must be a 64-character hexadecimal X25519 public key")?;
    }

    RecipientKey::from_bytes(&bytes).map_err(|error| error.to_string())
}

fn encrypt(token: &[u8], uuid: &Uuid, public_key: &RecipientKey) -> Result<String, String> {
    let (encapped_key, mut sender) =
        setup_sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            public_key,
            b"",
        )
        .map_err(|error| error.to_string())?;

    let ciphertext = sender
        .seal(token, uuid.as_bytes())
        .map_err(|error| error.to_string())?;

    let mut encrypted = encapped_key.to_bytes().to_vec();
    encrypted.extend(ciphertext);

    Ok(format!("hpke:{}", STANDARD.encode(encrypted)))
}
