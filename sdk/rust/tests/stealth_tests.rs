use k256::elliptic_curve::sec1::ToEncodedPoint;
use mpp_rs::*;
use sha3::{Digest, Keccak256};

#[test]
fn test_generate_stealth_keys_produces_valid_meta_address() {
    let (keys, meta_bytes) = generate_stealth_keys();
    assert_eq!(meta_bytes.len(), 66);

    assert_eq!(&meta_bytes[0..33], &keys.spending.compressed_pub());
    assert_eq!(&meta_bytes[33..66], &keys.viewing.compressed_pub());
}

#[test]
fn test_meta_address_hex_roundtrip() {
    let (keys, meta_bytes) = generate_stealth_keys();
    let hex = format_meta_address(&meta_bytes);

    assert!(hex.starts_with("0x"));
    assert_eq!(hex.len(), 2 + 66 * 2);

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
fn test_stealth_meta_uri_roundtrip() {
    let (_keys, meta_bytes) = generate_stealth_keys();
    let uri = format_stealth_meta_uri(&meta_bytes);

    assert!(uri.starts_with("st:eth:0x"));

    let (spending_pub, viewing_pub) = parse_stealth_meta_uri(&uri).unwrap();
    let (spending_pub2, viewing_pub2) =
        parse_stealth_meta_address(&format_meta_address(&meta_bytes)).unwrap();

    assert_eq!(
        spending_pub.to_encoded_point(true).as_bytes(),
        spending_pub2.to_encoded_point(true).as_bytes()
    );
    assert_eq!(
        viewing_pub.to_encoded_point(true).as_bytes(),
        viewing_pub2.to_encoded_point(true).as_bytes()
    );
}

#[test]
fn test_invalid_meta_address_length() {
    let result = parse_stealth_meta_address("0xaabb");
    assert!(result.is_err());
}

#[test]
fn test_full_stealth_payment_flow() {
    let (keys, _meta_bytes) = generate_stealth_keys();
    let spending_priv = keys.spending.secret_key().unwrap();
    let viewing_priv = keys.viewing.secret_key().unwrap();

    let result = generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap();

    println!("Stealth address: {}", result.stealth_address);
    println!("Ephemeral pubkey: 0x{}", hex::encode(result.ephemeral_pub_key));
    println!("View tag: {}", result.view_tag);

    let announcement = StealthAnnouncement {
        scheme_id: 1,
        stealth_address: result.stealth_address.clone(),
        ephemeral_pub_key: result.ephemeral_pub_key,
        view_tag: result.view_tag,
        metadata: b"inv_test123".to_vec(),
    };

    let payment_info = check_stealth_announcement(
        &announcement,
        &viewing_priv,
        &keys.spending.public_key,
    );

    assert!(payment_info.is_some(), "Scanner should detect the stealth payment");
    let info = payment_info.unwrap();
    assert_eq!(info.stealth_address, result.stealth_address);

    let stealth_priv = compute_stealth_private_key(
        &spending_priv,
        &result.ephemeral_pub_key,
        &viewing_priv,
    ).unwrap();

    let stealth_pub = stealth_priv.public_key();
    let stealth_uncompressed = stealth_pub.to_encoded_point(false);
    let hash = Keccak256::digest(&stealth_uncompressed.as_bytes()[1..]);
    let mut derived_addr = [0u8; 20];
    derived_addr.copy_from_slice(&hash[12..]);

    assert_eq!(
        Address(derived_addr),
        result.stealth_address,
        "Stealth private key should derive to the stealth address"
    );
}

#[test]
fn test_multiple_payments_to_same_recipient() {
    let (keys, _) = generate_stealth_keys();
    let viewing_priv = keys.viewing.secret_key().unwrap();

    let results: Vec<_> = (0..10)
        .map(|_| generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap())
        .collect();

    let addresses: Vec<_> = results.iter().map(|r| r.stealth_address.clone()).collect();
    for i in 0..addresses.len() {
        for j in (i + 1)..addresses.len() {
            assert_ne!(addresses[i], addresses[j], "Each payment should have a unique stealth address");
        }
    }

    for result in &results {
        let announcement = StealthAnnouncement {
            scheme_id: 1,
            stealth_address: result.stealth_address.clone(),
            ephemeral_pub_key: result.ephemeral_pub_key,
            view_tag: result.view_tag,
            metadata: vec![],
        };
        let info = check_stealth_announcement(
            &announcement,
            &viewing_priv,
            &keys.spending.public_key,
        );
        assert!(info.is_some());
    }
}

#[test]
fn test_wrong_viewing_key_does_not_detect() {
    let (keys, _) = generate_stealth_keys();
    let (other_keys, _) = generate_stealth_keys();
    let other_viewing_priv = other_keys.viewing.secret_key().unwrap();

    let result = generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap();

    let announcement = StealthAnnouncement {
        scheme_id: 1,
        stealth_address: result.stealth_address.clone(),
        ephemeral_pub_key: result.ephemeral_pub_key,
        view_tag: result.view_tag,
        metadata: vec![],
    };

    let info = check_stealth_announcement(
        &announcement,
        &other_viewing_priv,
        &keys.spending.public_key,
    );

    match info {
        None => {}
        Some(i) => {
            assert_ne!(i.stealth_address, result.stealth_address);
        }
    }
}

#[test]
fn test_wrong_spending_key_does_not_detect() {
    let (keys, _) = generate_stealth_keys();
    let (other_keys, _) = generate_stealth_keys();
    let viewing_priv = keys.viewing.secret_key().unwrap();

    let result = generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap();

    let announcement = StealthAnnouncement {
        scheme_id: 1,
        stealth_address: result.stealth_address.clone(),
        ephemeral_pub_key: result.ephemeral_pub_key,
        view_tag: result.view_tag,
        metadata: vec![],
    };

    let info = check_stealth_announcement(
        &announcement,
        &viewing_priv,
        &other_keys.spending.public_key,
    );

    assert!(info.is_none(), "Wrong spending pub should not produce matching address");
}

#[test]
fn test_scheme_id_filtering() {
    let (keys, _) = generate_stealth_keys();
    let viewing_priv = keys.viewing.secret_key().unwrap();
    let result = generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap();

    let announcement_0 = StealthAnnouncement {
        scheme_id: 0,
        stealth_address: result.stealth_address.clone(),
        ephemeral_pub_key: result.ephemeral_pub_key,
        view_tag: result.view_tag,
        metadata: vec![],
    };
    assert!(check_stealth_announcement(&announcement_0, &viewing_priv, &keys.spending.public_key).is_none());

    let announcement_1 = StealthAnnouncement {
        scheme_id: 1,
        stealth_address: result.stealth_address.clone(),
        ephemeral_pub_key: result.ephemeral_pub_key,
        view_tag: result.view_tag,
        metadata: vec![],
    };
    assert!(check_stealth_announcement(&announcement_1, &viewing_priv, &keys.spending.public_key).is_some());
}

#[test]
fn test_view_tag_determinism() {
    let (keys, _) = generate_stealth_keys();
    let viewing_priv = keys.viewing.secret_key().unwrap();

    let result1 = generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap();
    let result2 = generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap();

    for result in [&result1, &result2] {
        let announcement = StealthAnnouncement {
            scheme_id: 1,
            stealth_address: result.stealth_address.clone(),
            ephemeral_pub_key: result.ephemeral_pub_key,
            view_tag: result.view_tag,
            metadata: vec![],
        };
        assert!(check_stealth_announcement(&announcement, &viewing_priv, &keys.spending.public_key).is_some());
    }
}

#[test]
fn test_address_format() {
    let (keys, _) = generate_stealth_keys();
    let result = generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap();

    let addr_hex = result.stealth_address.to_hex();
    assert!(addr_hex.starts_with("0x"));
    assert_eq!(addr_hex.len(), 42);

    let checksum = result.stealth_address.to_checksum();
    assert!(checksum.starts_with("0x"));
    assert_eq!(checksum.len(), 42);
}

#[test]
fn test_compute_stealth_private_key_consistency() {
    let (keys, _) = generate_stealth_keys();
    let spending_priv = keys.spending.secret_key().unwrap();
    let viewing_priv = keys.viewing.secret_key().unwrap();

    for _ in 0..5 {
        let result = generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap();

        let stealth_priv = compute_stealth_private_key(
            &spending_priv,
            &result.ephemeral_pub_key,
            &viewing_priv,
        ).unwrap();

        let stealth_pub = stealth_priv.public_key();
        let stealth_uncompressed = stealth_pub.to_encoded_point(false);
        let hash = Keccak256::digest(&stealth_uncompressed.as_bytes()[1..]);
        let mut derived_addr = [0u8; 20];
        derived_addr.copy_from_slice(&hash[12..]);

        assert_eq!(Address(derived_addr), result.stealth_address);
    }
}
