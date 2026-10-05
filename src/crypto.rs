use azalea_auth::{AccessTokenResponse, cache::ExpiringValue};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use flate2::{Compression, write::GzEncoder};
use hpke::{
    Deserializable, Kem, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, single_shot_seal,
};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;
type KeyExchange = X25519HkdfSha256;
type Token = (ExpiringValue<AccessTokenResponse>, String);

pub(crate) type PublicKey = <KeyExchange as Kem>::PublicKey;

pub(crate) fn encrypt_token(
    token: &Token,
    uuid: &[u8; 16],
    public_key: &PublicKey,
) -> Result<String, String> {
    let data = compress_json(token)?;

    let (encapped_key, ciphertext) =
        single_shot_seal::<Aead, Kdf, KeyExchange>(&OpModeS::Base, public_key, b"", &data, uuid)
            .map_err(|error| error.to_string())?;

    let encoded = [encapped_key.to_bytes().as_ref(), ciphertext.as_slice()].concat();
    Ok(format!("hpke:{}", STANDARD.encode(encoded)))
}

pub(crate) fn compress_json(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::best());
    serde_json::to_writer(&mut gzip, value).map_err(|error| error.to_string())?;
    gzip.finish().map_err(|error| error.to_string())
}

pub(crate) fn parse_public_key(encoded: &str) -> Result<PublicKey, String> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(encoded, &mut bytes).map_err(|_| "invalid public key".to_owned())?;
    PublicKey::from_bytes(&bytes).map_err(|error| error.to_string())
}

pub(crate) fn parse_signing_key(encoded: &str) -> Result<SigningKey, String> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(encoded, &mut bytes).map_err(|_| "invalid signing key".to_owned())?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub(crate) fn sign(data: &[u8], private_key: &SigningKey) -> String {
    STANDARD.encode(private_key.sign(data).to_bytes())
}

pub(crate) fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time is after Unix epoch")
        .as_millis() as u64
}
