use azalea_auth::{AccessTokenResponse, cache::ExpiringValue};
use base64::{Engine, engine::general_purpose::STANDARD};
use hpke::{
    Deserializable, Kem, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, setup_sender,
};
use uuid::Uuid;

type Token = ExpiringValue<AccessTokenResponse>;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type KeyExchange = X25519HkdfSha256;
pub(crate) type PublicKey = <KeyExchange as Kem>::PublicKey;

pub(crate) fn encrypt_token(
    token: &Token,
    uuid: &Uuid,
    public_key: &PublicKey,
) -> Result<String, String> {
    let (encapped_key, mut sender) =
        setup_sender::<Aead, Kdf, KeyExchange>(&OpModeS::Base, public_key, b"")
            .map_err(|error| error.to_string())?;

    let json = serde_json::to_vec(token).map_err(|error| error.to_string())?;
    let ciphertext = sender
        .seal(&json, uuid.as_bytes())
        .map_err(|error| error.to_string())?;

    let mut result = encapped_key.to_bytes().to_vec();
    result.extend(ciphertext);

    Ok(format!("hpke:{}", STANDARD.encode(result)))
}

pub(crate) fn parse_public_key(encoded: &str) -> Result<PublicKey, String> {
    PublicKey::from_bytes(&decode_hex::<32>(encoded, "pubKey")?).map_err(|error| error.to_string())
}

fn decode_hex<const N: usize>(encoded: &str, name: &str) -> Result<[u8; N], String> {
    if encoded.len() != N * 2 || !encoded.is_ascii() {
        return Err(format!("{name} must be {} hexadecimal characters", N * 2));
    }

    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{name} must be {} hexadecimal characters", N * 2))?;
    }

    Ok(bytes)
}
