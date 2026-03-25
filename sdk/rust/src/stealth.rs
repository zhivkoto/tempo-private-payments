use k256::{
    elliptic_curve::{
        ops::Reduce,
        sec1::ToEncodedPoint,
    },
    ProjectivePoint, PublicKey, Scalar, SecretKey, U256,
};
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

use crate::types::*;

/// Generate a new stealth key pair (spending + viewing) and the 66-byte meta-address.
pub fn generate_stealth_keys() -> (StealthKeys, Vec<u8>) {
    let mut rng = rand::rngs::OsRng;

    let spending_priv = SecretKey::random(&mut rng);
    let viewing_priv = SecretKey::random(&mut rng);

    let keys = StealthKeys {
        spending: StealthKeyPair::new(spending_priv),
        viewing: StealthKeyPair::new(viewing_priv),
    };

    // Meta-address = spending_pub (33 bytes) + viewing_pub (33 bytes) = 66 bytes
    let mut meta_address = Vec::with_capacity(66);
    meta_address.extend_from_slice(&keys.spending.compressed_pub());
    meta_address.extend_from_slice(&keys.viewing.compressed_pub());

    (keys, meta_address)
}

/// Parse a 66-byte stealth meta-address (hex-encoded) into spending and viewing public keys.
pub fn parse_stealth_meta_address(
    meta_hex: &str,
) -> Result<(PublicKey, PublicKey), StealthError> {
    let clean = meta_hex.strip_prefix("0x").unwrap_or(meta_hex);
    let bytes = hex::decode(clean).map_err(|_| StealthError::InvalidHex)?;
    if bytes.len() != 66 {
        return Err(StealthError::InvalidMetaAddressLength(bytes.len()));
    }

    let spending_pub = PublicKey::from_sec1_bytes(&bytes[0..33])
        .map_err(|_| StealthError::InvalidPublicKey)?;
    let viewing_pub = PublicKey::from_sec1_bytes(&bytes[33..66])
        .map_err(|_| StealthError::InvalidPublicKey)?;

    Ok((spending_pub, viewing_pub))
}

/// Derive a one-time stealth address from the recipient's public keys.
///
/// Algorithm (matches TS SDK exactly):
/// 1. Generate ephemeral key pair (r, R) where R = r * G
/// 2. Compute shared secret S = r * K_view (ECDH)
/// 3. view_tag = first byte of keccak256(compress(S))
/// 4. s = keccak256(compress(S)) mod n
/// 5. K_stealth = K_spend + s * G
/// 6. stealth_address = last 20 bytes of keccak256(uncompressed K_stealth without prefix)
pub fn generate_stealth_address(
    spending_pub: &PublicKey,
    viewing_pub: &PublicKey,
) -> Result<GenerateStealthAddressResult, StealthError> {
    let mut rng = rand::rngs::OsRng;

    // 1. Generate ephemeral key pair
    let ephemeral_priv = SecretKey::random(&mut rng);
    let ephemeral_pub = ephemeral_priv.public_key();
    let ephemeral_pub_compressed = {
        let point = ephemeral_pub.to_encoded_point(true);
        let mut buf = [0u8; 33];
        buf.copy_from_slice(point.as_bytes());
        buf
    };

    // 2. Compute shared secret: S = r * K_view
    let viewing_point = ProjectivePoint::from(*viewing_pub.as_affine());
    let ephemeral_scalar = *ephemeral_priv.to_nonzero_scalar();
    let shared_point = viewing_point * ephemeral_scalar.as_ref();

    // Get compressed encoding of shared point
    let shared_compressed = shared_point.to_affine().to_encoded_point(true);
    let shared_compressed_bytes = shared_compressed.as_bytes();

    // 3. Hash the shared secret
    let shared_hash = Keccak256::digest(shared_compressed_bytes);

    // 4. view_tag = first byte
    let view_tag = shared_hash[0];

    // 5. s = hash mod n
    let s = <Scalar as Reduce<U256>>::reduce_bytes((&shared_hash).into());

    // Reject degenerate zero scalar
    if s.is_zero().into() {
        return Err(StealthError::DegenerateScalar);
    }

    // 6. K_stealth = K_spend + s * G
    let spending_point = ProjectivePoint::from(*spending_pub.as_affine());
    let s_times_g = ProjectivePoint::GENERATOR * s;
    let stealth_point = spending_point + s_times_g;

    // 7. Compute address from uncompressed stealth public key
    let stealth_address = pub_point_to_address(&stealth_point);

    Ok(GenerateStealthAddressResult {
        stealth_address,
        ephemeral_pub_key: ephemeral_pub_compressed,
        view_tag,
    })
}

/// Check if a stealth announcement is addressed to us.
///
/// Returns StealthPaymentInfo if the announcement matches, None otherwise.
/// Uses view_tag for fast filtering before doing the full computation.
pub fn check_stealth_announcement(
    announcement: &StealthAnnouncement,
    viewing_priv: &SecretKey,
    spending_pub: &PublicKey,
) -> Option<StealthPaymentInfo> {
    // Only support scheme ID 1
    if announcement.scheme_id != 1 {
        return None;
    }

    // Parse ephemeral public key
    let ephemeral_pub = PublicKey::from_sec1_bytes(&announcement.ephemeral_pub_key).ok()?;
    let ephemeral_point = ProjectivePoint::from(*ephemeral_pub.as_affine());

    // Compute shared secret: S' = k_view * R
    let viewing_scalar = *viewing_priv.to_nonzero_scalar();
    let shared_point = ephemeral_point * viewing_scalar.as_ref();

    // Get compressed encoding
    let shared_compressed = shared_point.to_affine().to_encoded_point(true);
    let shared_compressed_bytes = shared_compressed.as_bytes();

    // Hash the shared secret
    let shared_hash = Keccak256::digest(shared_compressed_bytes);

    // Fast filter: check view tag
    if shared_hash[0] != announcement.view_tag {
        return None;
    }

    // s = hash mod n
    let s = <Scalar as Reduce<U256>>::reduce_bytes((&shared_hash).into());

    // Reject degenerate zero scalar
    if s.is_zero().into() {
        return None;
    }

    // K_stealth' = K_spend + s * G
    let spending_point = ProjectivePoint::from(*spending_pub.as_affine());
    let s_times_g = ProjectivePoint::GENERATOR * s;
    let stealth_point = spending_point + s_times_g;

    // Compute address (uses constant-time Address comparison)
    let computed_address = pub_point_to_address(&stealth_point);

    // Check if it matches (constant-time via subtle::ConstantTimeEq)
    if computed_address != announcement.stealth_address {
        return None;
    }

    // Return the shared secret scalar for later private key computation
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&s.to_bytes());

    let result = StealthPaymentInfo::new(
        computed_address,
        scalar_bytes,
        announcement.ephemeral_pub_key,
    );

    // Zeroize local copy
    scalar_bytes.zeroize();

    Some(result)
}

/// Compute the full stealth private key.
///
/// k_stealth = k_spend + keccak256(k_view * R) mod n
pub fn compute_stealth_private_key(
    spending_priv: &SecretKey,
    ephemeral_pub_key: &[u8; 33],
    viewing_priv: &SecretKey,
) -> Result<SecretKey, StealthError> {
    // Parse ephemeral public key
    let ephemeral_pub = PublicKey::from_sec1_bytes(ephemeral_pub_key)
        .map_err(|_| StealthError::InvalidPublicKey)?;
    let ephemeral_point = ProjectivePoint::from(*ephemeral_pub.as_affine());

    // Compute shared secret: S = k_view * R
    let viewing_scalar = *viewing_priv.to_nonzero_scalar();
    let shared_point = ephemeral_point * viewing_scalar.as_ref();

    // Get compressed encoding and hash
    let shared_compressed = shared_point.to_affine().to_encoded_point(true);
    let shared_hash = Keccak256::digest(shared_compressed.as_bytes());

    // s = hash mod n
    let s = <Scalar as Reduce<U256>>::reduce_bytes((&shared_hash).into());

    // Reject degenerate zero scalar
    if s.is_zero().into() {
        return Err(StealthError::DegenerateScalar);
    }

    // k_stealth = k_spend + s mod n
    let k_spend = *spending_priv.to_nonzero_scalar();
    let k_stealth = *k_spend.as_ref() + s;

    // Convert back to SecretKey
    let mut k_stealth_bytes = k_stealth.to_bytes();
    let result = SecretKey::from_bytes((&k_stealth_bytes).into())
        .map_err(|_| StealthError::InvalidPrivateKey);

    // Zeroize the intermediate bytes
    k_stealth_bytes.as_mut_slice().zeroize();

    result
}

/// Convert a projective point to an Ethereum address.
/// address = last 20 bytes of keccak256(uncompressed_pubkey_no_prefix)
fn pub_point_to_address(point: &ProjectivePoint) -> Address {
    let uncompressed = point.to_affine().to_encoded_point(false);
    let uncompressed_bytes = uncompressed.as_bytes();
    // Remove the 0x04 prefix byte
    let pub_no_prefix = &uncompressed_bytes[1..];
    let hash = Keccak256::digest(pub_no_prefix);
    // Last 20 bytes
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Address(addr)
}

/// Format meta-address bytes as hex string with 0x prefix.
pub fn format_meta_address(meta_bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(meta_bytes))
}

/// Format meta-address as stealth URI: "st:eth:0x..."
pub fn format_stealth_meta_uri(meta_bytes: &[u8]) -> String {
    format!("st:eth:0x{}", hex::encode(meta_bytes))
}

/// Parse a stealth meta URI ("st:eth:0x...") into (spending_pub, viewing_pub).
pub fn parse_stealth_meta_uri(uri: &str) -> Result<(PublicKey, PublicKey), StealthError> {
    let hex_part = uri
        .strip_prefix("st:eth:")
        .ok_or_else(|| StealthError::Parse("Invalid stealth meta URI prefix".into()))?;
    parse_stealth_meta_address(hex_part)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_parse_meta_address() {
        let (keys, meta_bytes) = generate_stealth_keys();
        assert_eq!(meta_bytes.len(), 66);

        let hex = format_meta_address(&meta_bytes);
        let (spending_pub, viewing_pub) = parse_stealth_meta_address(&hex).unwrap();

        assert_eq!(
            spending_pub.to_encoded_point(true).as_bytes(),
            keys.spending.public_key.to_encoded_point(true).as_bytes()
        );
        assert_eq!(
            viewing_pub.to_encoded_point(true).as_bytes(),
            keys.viewing.public_key.to_encoded_point(true).as_bytes()
        );
    }

    #[test]
    fn test_stealth_address_roundtrip() {
        let (keys, _meta_bytes) = generate_stealth_keys();

        let spending_priv = keys.spending.secret_key().unwrap();
        let viewing_priv = keys.viewing.secret_key().unwrap();

        // Generate stealth address (as payer)
        let result = generate_stealth_address(
            &keys.spending.public_key,
            &keys.viewing.public_key,
        ).unwrap();

        // Check announcement (as recipient scanner)
        let announcement = StealthAnnouncement {
            scheme_id: 1,
            stealth_address: result.stealth_address.clone(),
            ephemeral_pub_key: result.ephemeral_pub_key,
            view_tag: result.view_tag,
            metadata: vec![],
        };

        let payment_info = check_stealth_announcement(
            &announcement,
            &viewing_priv,
            &keys.spending.public_key,
        );

        assert!(payment_info.is_some(), "Should detect our stealth payment");
        let info = payment_info.unwrap();
        assert_eq!(info.stealth_address, result.stealth_address);

        // Compute full private key
        let stealth_priv = compute_stealth_private_key(
            &spending_priv,
            &result.ephemeral_pub_key,
            &viewing_priv,
        )
        .unwrap();

        // Verify: the stealth private key's public key should match the stealth address
        let stealth_pub = stealth_priv.public_key();
        let stealth_point = ProjectivePoint::from(*stealth_pub.as_affine());
        let derived_address = pub_point_to_address(&stealth_point);
        assert_eq!(derived_address, result.stealth_address);
    }

    #[test]
    fn test_wrong_recipient_does_not_match() {
        let (keys, _) = generate_stealth_keys();
        let (other_keys, _) = generate_stealth_keys();

        let other_viewing_priv = other_keys.viewing.secret_key().unwrap();

        let result = generate_stealth_address(
            &keys.spending.public_key,
            &keys.viewing.public_key,
        ).unwrap();

        let announcement = StealthAnnouncement {
            scheme_id: 1,
            stealth_address: result.stealth_address.clone(),
            ephemeral_pub_key: result.ephemeral_pub_key,
            view_tag: result.view_tag,
            metadata: vec![],
        };

        let payment_info = check_stealth_announcement(
            &announcement,
            &other_viewing_priv,
            &other_keys.spending.public_key,
        );

        if let Some(info) = payment_info {
            assert_ne!(info.stealth_address, result.stealth_address);
        }
    }

    #[test]
    fn test_unsupported_scheme_returns_none() {
        let (keys, _) = generate_stealth_keys();
        let viewing_priv = keys.viewing.secret_key().unwrap();

        let result = generate_stealth_address(
            &keys.spending.public_key,
            &keys.viewing.public_key,
        ).unwrap();

        let announcement = StealthAnnouncement {
            scheme_id: 2,
            stealth_address: result.stealth_address,
            ephemeral_pub_key: result.ephemeral_pub_key,
            view_tag: result.view_tag,
            metadata: vec![],
        };

        let info = check_stealth_announcement(
            &announcement,
            &viewing_priv,
            &keys.spending.public_key,
        );
        assert!(info.is_none());
    }

    #[test]
    fn test_parse_stealth_meta_uri() {
        let (keys, meta_bytes) = generate_stealth_keys();
        let uri = format_stealth_meta_uri(&meta_bytes);
        assert!(uri.starts_with("st:eth:0x"));

        let (spending_pub, viewing_pub) = parse_stealth_meta_uri(&uri).unwrap();
        assert_eq!(
            spending_pub.to_encoded_point(true).as_bytes(),
            keys.spending.public_key.to_encoded_point(true).as_bytes()
        );
        assert_eq!(
            viewing_pub.to_encoded_point(true).as_bytes(),
            keys.viewing.public_key.to_encoded_point(true).as_bytes()
        );
    }

    #[test]
    fn test_address_checksum() {
        let addr = Address::from_hex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap();
        let checksum = addr.to_checksum();
        assert_eq!(checksum, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    }
}
