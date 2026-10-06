use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use crypto_box::{PublicKey, aead::OsRng};
use ed25519_dalek::{Signer, SigningKey};
use flate2::{Compression, write::GzEncoder};
use serde::Serialize;
use std::{
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) type Error = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type Token = (String, String);

pub(crate) fn encrypt_token(token: &Token, public_key: &PublicKey) -> Result<String, Error> {
    let sealed = public_key
        .seal(&mut OsRng, &compress(&serde_json::to_vec(token)?)?)
        .map_err(|_| "could not encrypt token")?;

    Ok(STANDARD.encode(sealed))
}

pub(crate) fn sign(value: &impl Serialize, signing_key: &SigningKey) -> Result<String, Error> {
    let json = serde_json::to_vec(value)?;
    let signed = [signing_key.sign(&json).to_bytes().as_slice(), &json].concat();
    Ok(STANDARD.encode(compress(&signed)?))
}

pub(crate) fn parse_public_key(encoded: &str) -> Result<PublicKey, Error> {
    let bytes = decode_key(encoded).ok_or("invalid public key")?;
    Ok(PublicKey::from_bytes(bytes))
}

pub(crate) fn parse_signing_key(encoded: &str) -> Result<SigningKey, Error> {
    let bytes = decode_key(encoded).ok_or("invalid signing key")?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub(crate) fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time is after Unix epoch")
        .as_millis() as u64
}

fn decode_key(encoded: &str) -> Option<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded.trim_end_matches('=')).ok()?;
    bytes.try_into().ok()
}

fn compress(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::best());
    gzip.write_all(data)?;
    Ok(gzip.finish()?)
}
