use azalea_auth::{AccessTokenResponse, cache::ExpiringValue};
use base64::{Engine, engine::general_purpose::STANDARD};
use hpke::{
    Deserializable, Kem, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, single_shot_seal,
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
    let json = serde_json::to_vec(token).map_err(|error| error.to_string())?;

    let (encapped_key, ciphertext) =
        single_shot_seal::<Aead, Kdf, KeyExchange>(&OpModeS::Base, public_key, b"", &json, uuid)
            .map_err(|error| error.to_string())?;

    let encoded = [encapped_key.to_bytes().as_ref(), ciphertext.as_slice()].concat();
    Ok(format!("hpke:{}", STANDARD.encode(encoded)))
}

pub(crate) fn parse_public_key(encoded: &str) -> Result<PublicKey, String> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(encoded, &mut bytes).map_err(|_| "invalid public key".to_owned())?;
    PublicKey::from_bytes(&bytes).map_err(|error| error.to_string())
}
