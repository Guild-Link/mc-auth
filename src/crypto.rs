use azalea_auth::{AccessTokenResponse, cache::ExpiringValue};
use base64::{Engine, engine::general_purpose::STANDARD};
use hpke::{
    Deserializable, Kem, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, setup_sender,
};

type Token = ExpiringValue<AccessTokenResponse>;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type KeyExchange = X25519HkdfSha256;
pub(crate) type PublicKey = <KeyExchange as Kem>::PublicKey;

pub(crate) fn encrypt_token(
    token: &Token,
    uuid: &[u8; 16],
    public_key: &PublicKey,
) -> Result<String, String> {
    let (encapped_key, mut sender) =
        setup_sender::<Aead, Kdf, KeyExchange>(&OpModeS::Base, public_key, b"")
            .map_err(|error| error.to_string())?;

    let json = serde_json::to_vec(token).map_err(|error| error.to_string())?;
    let ciphertext = sender
        .seal(&json, uuid)
        .map_err(|error| error.to_string())?;

    let encapped_key = encapped_key.to_bytes();
    let mut result = Vec::with_capacity(encapped_key.len() + ciphertext.len());
    result.extend_from_slice(&encapped_key);
    result.extend(ciphertext);

    Ok(format!("hpke:{}", STANDARD.encode(result)))
}

pub(crate) fn parse_public_key(encoded: &str) -> Result<PublicKey, String> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(encoded, &mut bytes)
        .map_err(|_| "pubKey must be 64 hexadecimal characters".to_owned())?;
    PublicKey::from_bytes(&bytes).map_err(|error| error.to_string())
}
