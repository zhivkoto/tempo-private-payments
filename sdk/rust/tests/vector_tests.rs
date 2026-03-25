//! Cross-SDK deterministic test vectors for the ERC-5564 stealth address scheme.
//!
//! Uses known private keys and computes the ECDH math inline (bypassing
//! generate_stealth_address which randomises the ephemeral key).

use k256::{
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint},
    ProjectivePoint, PublicKey, Scalar, SecretKey, U256,
};
use sha3::{Digest, Keccak256};

use mpp_rs::*;

// ── Vector constants (must match test-vectors/vectors.json) ─────────────────

const SPENDING_PRIV: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";
const SPENDING_PUB: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const VIEWING_PRIV: &str =
    "0000000000000000000000000000000000000000000000000000000000000002";
const VIEWING_PUB: &str =
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const EPHEMERAL_PRIV: &str =
    "0000000000000000000000000000000000000000000000000000000000000003";
const EPHEMERAL_PUB: &str =
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const META_ADDRESS: &str =
    "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

const EXPECTED_SHARED_POINT: &str =
    "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556";
const EXPECTED_SHARED_HASH: &str =
    "cd36b55d26196fc0b96312b01dd978fc5e380c8afeab49aae283f0ca6a814ff4";
const EXPECTED_VIEW_TAG: u8 = 205;
const EXPECTED_SHARED_SCALAR: &str =
    "cd36b55d26196fc0b96312b01dd978fc5e380c8afeab49aae283f0ca6a814ff4";
const EXPECTED_STEALTH_ADDRESS: &str = "7f7d3bae345ae700dcda65d1b1f98f43835a17c4";
const EXPECTED_STEALTH_PRIV: &str =
    "cd36b55d26196fc0b96312b01dd978fc5e380c8afeab49aae283f0ca6a814ff5";

// ── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn test_vector_parse_meta_address() {
    let (spending_pub, viewing_pub) = parse_stealth_meta_address(META_ADDRESS).unwrap();
    assert_eq!(
        hex::encode(spending_pub.to_encoded_point(true).as_bytes()),
        SPENDING_PUB
    );
    assert_eq!(
        hex::encode(viewing_pub.to_encoded_point(true).as_bytes()),
        VIEWING_PUB
    );
}

#[test]
fn test_vector_derive_stealth_address() {
    let ephemeral_priv_bytes = hex::decode(EPHEMERAL_PRIV).unwrap();
    let ephemeral_priv = SecretKey::from_slice(&ephemeral_priv_bytes).unwrap();

    let viewing_pub_bytes = hex::decode(VIEWING_PUB).unwrap();
    let viewing_pub = PublicKey::from_sec1_bytes(&viewing_pub_bytes).unwrap();

    // S = r * K_view (ECDH)
    let viewing_point = ProjectivePoint::from(*viewing_pub.as_affine());
    let ephemeral_scalar = *ephemeral_priv.to_nonzero_scalar();
    let shared_point = viewing_point * ephemeral_scalar.as_ref();

    let shared_compressed = shared_point.to_affine().to_encoded_point(true);
    let shared_compressed_bytes = shared_compressed.as_bytes();
    assert_eq!(hex::encode(shared_compressed_bytes), EXPECTED_SHARED_POINT);

    // H = keccak256(compress(S))
    let shared_hash = Keccak256::digest(shared_compressed_bytes);
    assert_eq!(hex::encode(&shared_hash), EXPECTED_SHARED_HASH);

    // View tag
    assert_eq!(shared_hash[0], EXPECTED_VIEW_TAG);

    // s = H mod n
    let s = <Scalar as Reduce<U256>>::reduce_bytes((&shared_hash).into());
    assert_eq!(hex::encode(s.to_bytes()), EXPECTED_SHARED_SCALAR);

    // K_stealth = K_spend + s*G
    let spending_pub_bytes = hex::decode(SPENDING_PUB).unwrap();
    let spending_pub = PublicKey::from_sec1_bytes(&spending_pub_bytes).unwrap();
    let spending_point = ProjectivePoint::from(*spending_pub.as_affine());
    let s_times_g = ProjectivePoint::GENERATOR * s;
    let stealth_point = spending_point + s_times_g;

    // Compute address
    let stealth_uncompressed = stealth_point.to_affine().to_encoded_point(false);
    let pub_no_prefix = &stealth_uncompressed.as_bytes()[1..];
    let addr_hash = Keccak256::digest(pub_no_prefix);
    let stealth_address = hex::encode(&addr_hash[12..]);

    assert_eq!(stealth_address, EXPECTED_STEALTH_ADDRESS);
}

#[test]
fn test_vector_check_stealth_announcement() {
    let viewing_priv_bytes = hex::decode(VIEWING_PRIV).unwrap();
    let viewing_priv = SecretKey::from_slice(&viewing_priv_bytes).unwrap();

    let spending_pub_bytes = hex::decode(SPENDING_PUB).unwrap();
    let spending_pub = PublicKey::from_sec1_bytes(&spending_pub_bytes).unwrap();

    let stealth_address = Address::from_hex(&format!("0x{}", EXPECTED_STEALTH_ADDRESS)).unwrap();
    let mut ephemeral_pub_key = [0u8; 33];
    ephemeral_pub_key.copy_from_slice(&hex::decode(EPHEMERAL_PUB).unwrap());

    let announcement = StealthAnnouncement {
        scheme_id: 1,
        stealth_address,
        ephemeral_pub_key,
        view_tag: EXPECTED_VIEW_TAG,
        metadata: vec![],
    };

    let info = check_stealth_announcement(&announcement, &viewing_priv, &spending_pub);
    assert!(info.is_some(), "Should detect the stealth payment");

    let payment_info = info.unwrap();
    assert_eq!(
        hex::encode(&*payment_info.shared_secret_scalar()),
        EXPECTED_SHARED_SCALAR
    );
}

#[test]
fn test_vector_compute_stealth_private_key() {
    let spending_priv_bytes = hex::decode(SPENDING_PRIV).unwrap();
    let spending_priv = SecretKey::from_slice(&spending_priv_bytes).unwrap();

    let viewing_priv_bytes = hex::decode(VIEWING_PRIV).unwrap();
    let viewing_priv = SecretKey::from_slice(&viewing_priv_bytes).unwrap();

    let mut ephemeral_pub_key = [0u8; 33];
    ephemeral_pub_key.copy_from_slice(&hex::decode(EPHEMERAL_PUB).unwrap());

    let stealth_priv =
        compute_stealth_private_key(&spending_priv, &ephemeral_pub_key, &viewing_priv).unwrap();

    assert_eq!(hex::encode(stealth_priv.to_bytes()), EXPECTED_STEALTH_PRIV);

    // Verify: derive public key and check address
    let stealth_pub = stealth_priv.public_key();
    let stealth_uncompressed = stealth_pub.to_encoded_point(false);
    let pub_no_prefix = &stealth_uncompressed.as_bytes()[1..];
    let addr_hash = Keccak256::digest(pub_no_prefix);
    let derived_address = hex::encode(&addr_hash[12..]);

    assert_eq!(derived_address, EXPECTED_STEALTH_ADDRESS);
}
