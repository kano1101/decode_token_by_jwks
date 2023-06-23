use jsonwebkey_convert::{Base64BigUint, JsonWebKey, JsonWebKeySet};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

#[derive(Debug, serde::Deserialize)]
struct TokenClaims {
    #[allow(dead_code)]
    sub: String,
}

#[allow(dead_code)]
fn to_base64url<F>(rsa_key: &JsonWebKey, f: F) -> anyhow::Result<String>
where
    F: FnOnce(&jsonwebkey_convert::RSAPublicKey) -> &Base64BigUint,
{
    let rsa_public_key = rsa_key
        .rsa_public_key()
        .ok_or(anyhow::anyhow!("failed to get rsa public key"))?;

    let public_key_string = f(rsa_public_key).to_base64url();

    Ok(public_key_string)
}

#[allow(dead_code)]
pub async fn decode_user_sub_from_token(token: &str, jwks_url: &str) -> anyhow::Result<String> {
    let kid = jsonwebtoken::decode_header(token)?
        .kid
        .ok_or(anyhow::anyhow!("failed to decoding header."))?;

    let response = reqwest::get(jwks_url).await?;

    let jwks: JsonWebKeySet = response.json().await?;
    tracing::info!("jwks: {:?}", jwks);

    let rsa_key: JsonWebKey = jwks
        .keys
        .into_iter()
        .find(|key| match &key {
            JsonWebKey::RSAPublicKey { value, .. } => {
                tracing::warn!("kid1, {:?}", value.generic.kid.as_ref());
                tracing::warn!("kid2, {:?}", Some(&kid));
                value.generic.kid.as_ref() == Some(&kid)
            }
            _ => false,
        })
        .ok_or(anyhow::anyhow!("failed to matching generic kid."))?;

    // 適切な方法で適切なキーを選択する
    let modulus = &to_base64url(&rsa_key, |key| &key.n)?;
    let exponent = &to_base64url(&rsa_key, |key| &key.e)?;

    // RSA公開鍵を作成し、デコーディングキーを生成
    let decoding_key = DecodingKey::from_rsa_components(modulus, exponent)?;

    // デコード
    let validation = Validation::new(Algorithm::RS256);
    let validated_token = decode::<TokenClaims>(token, &decoding_key, &validation)?;

    let claims = validated_token.claims;
    let sub = claims.sub;

    Ok(sub)
}
