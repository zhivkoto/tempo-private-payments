use mpp_rs::*;

#[test]
fn test_scanner_scan_range_finds_all_our_payments() {
    let (keys, _) = generate_stealth_keys();
    let viewing_priv = keys.viewing.secret_key().unwrap();

    let results: Vec<_> = (0..10)
        .map(|_| generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap())
        .collect();

    let announcements: Vec<_> = results
        .iter()
        .map(|r| StealthAnnouncement {
            scheme_id: 1,
            stealth_address: r.stealth_address.clone(),
            ephemeral_pub_key: r.ephemeral_pub_key,
            view_tag: r.view_tag,
            metadata: vec![],
        })
        .collect();

    let scanner = AnnouncementScanner::new(viewing_priv, keys.spending.public_key);

    let found = scanner.scan_range(&announcements);
    assert_eq!(found.len(), 10);

    for (i, info) in found.iter().enumerate() {
        assert_eq!(info.stealth_address, results[i].stealth_address);
    }
}

#[test]
fn test_scanner_filters_out_others_payments() {
    let (keys, _) = generate_stealth_keys();
    let (other_keys, _) = generate_stealth_keys();
    let viewing_priv = keys.viewing.secret_key().unwrap();

    let our_results: Vec<_> = (0..3)
        .map(|_| generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap())
        .collect();

    let other_results: Vec<_> = (0..7)
        .map(|_| generate_stealth_address(&other_keys.spending.public_key, &other_keys.viewing.public_key).unwrap())
        .collect();

    let mut announcements = Vec::new();
    for r in &other_results[..3] {
        announcements.push(StealthAnnouncement {
            scheme_id: 1,
            stealth_address: r.stealth_address.clone(),
            ephemeral_pub_key: r.ephemeral_pub_key,
            view_tag: r.view_tag,
            metadata: vec![],
        });
    }
    for r in &our_results {
        announcements.push(StealthAnnouncement {
            scheme_id: 1,
            stealth_address: r.stealth_address.clone(),
            ephemeral_pub_key: r.ephemeral_pub_key,
            view_tag: r.view_tag,
            metadata: vec![],
        });
    }
    for r in &other_results[3..] {
        announcements.push(StealthAnnouncement {
            scheme_id: 1,
            stealth_address: r.stealth_address.clone(),
            ephemeral_pub_key: r.ephemeral_pub_key,
            view_tag: r.view_tag,
            metadata: vec![],
        });
    }

    let scanner = AnnouncementScanner::new(viewing_priv, keys.spending.public_key);

    let found = scanner.scan_range(&announcements);
    assert_eq!(found.len(), 3, "Should find exactly our 3 payments");

    let our_addresses: Vec<_> = our_results.iter().map(|r| r.stealth_address.clone()).collect();
    for info in &found {
        assert!(our_addresses.contains(&info.stealth_address), "Found payment should be one of ours");
    }
}

#[test]
fn test_scanner_verify_payment() {
    let (keys, _) = generate_stealth_keys();
    let viewing_priv = keys.viewing.secret_key().unwrap();

    let result = generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap();

    let announcement = StealthAnnouncement {
        scheme_id: 1,
        stealth_address: result.stealth_address.clone(),
        ephemeral_pub_key: result.ephemeral_pub_key,
        view_tag: result.view_tag,
        metadata: b"payment-123".to_vec(),
    };

    let scanner = AnnouncementScanner::new(viewing_priv, keys.spending.public_key);

    let verified = scanner.verify_payment(&announcement);
    assert!(verified.is_some());
    assert_eq!(verified.unwrap().stealth_address, result.stealth_address);
}

#[test]
fn test_scanner_empty_range() {
    let (keys, _) = generate_stealth_keys();
    let viewing_priv = keys.viewing.secret_key().unwrap();

    let scanner = AnnouncementScanner::new(viewing_priv, keys.spending.public_key);

    let found = scanner.scan_range(&[]);
    assert!(found.is_empty());
}

#[tokio::test]
async fn test_scanner_async_multiple_payments() {
    let (keys, _) = generate_stealth_keys();
    let viewing_priv = keys.viewing.secret_key().unwrap();

    let scanner = AnnouncementScanner::new(viewing_priv, keys.spending.public_key);

    let (tx, mut rx) = scanner.start();

    let mut expected_addresses = Vec::new();
    for _ in 0..3 {
        let result = generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap();
        expected_addresses.push(result.stealth_address.clone());

        tx.send(StealthAnnouncement {
            scheme_id: 1,
            stealth_address: result.stealth_address,
            ephemeral_pub_key: result.ephemeral_pub_key,
            view_tag: result.view_tag,
            metadata: vec![],
        })
        .await
        .unwrap();
    }

    for _ in 0..3 {
        let info = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert!(expected_addresses.contains(&info.stealth_address), "Received payment should be one we sent");
    }

    scanner.stop();
}

#[tokio::test]
async fn test_scanner_start_stop() {
    let (keys, _) = generate_stealth_keys();
    let viewing_priv = keys.viewing.secret_key().unwrap();

    let scanner = AnnouncementScanner::new(viewing_priv, keys.spending.public_key);

    assert!(!scanner.is_running());

    let (_tx, _rx) = scanner.start();
    assert!(scanner.is_running());

    scanner.stop();
    assert!(!scanner.is_running());
}
