use k256::PublicKey;
use k256::SecretKey;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::stealth::check_stealth_announcement;
use crate::types::*;

/// A scanner that checks stealth announcements for payments addressed to us.
pub struct AnnouncementScanner {
    viewing_priv: SecretKey,
    spending_pub: PublicKey,
    running: Arc<AtomicBool>,
}

impl AnnouncementScanner {
    /// Create a new scanner with the recipient's viewing private key and spending public key.
    pub fn new(viewing_priv: SecretKey, spending_pub: PublicKey) -> Self {
        Self {
            viewing_priv,
            spending_pub,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start scanning announcements. Returns a channel receiver for detected payments.
    pub fn start(
        &self,
    ) -> (
        mpsc::Sender<StealthAnnouncement>,
        mpsc::Receiver<StealthPaymentInfo>,
    ) {
        if self.running.load(Ordering::SeqCst) {
            panic!("Scanner already running — stop it first");
        }
        self.running.store(true, Ordering::SeqCst);

        let (announcement_tx, mut announcement_rx) = mpsc::channel::<StealthAnnouncement>(256);
        let (payment_tx, payment_rx) = mpsc::channel::<StealthPaymentInfo>(64);

        let viewing_priv = self.viewing_priv.clone();
        let spending_pub = self.spending_pub;
        let running = self.running.clone();

        tokio::spawn(async move {
            while running.load(Ordering::SeqCst) {
                match announcement_rx.recv().await {
                    Some(announcement) => {
                        if let Some(info) = check_stealth_announcement(
                            &announcement,
                            &viewing_priv,
                            &spending_pub,
                        ) {
                            if payment_tx.send(info).await.is_err() {
                                break;
                            }
                        }
                    }
                    None => break,
                }
            }
        });

        (announcement_tx, payment_rx)
    }

    /// Stop the scanner.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if the scanner is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Scan a batch of announcements synchronously (useful for historical scanning).
    pub fn scan_range(&self, announcements: &[StealthAnnouncement]) -> Vec<StealthPaymentInfo> {
        announcements
            .iter()
            .filter_map(|a| {
                check_stealth_announcement(a, &self.viewing_priv, &self.spending_pub)
            })
            .collect()
    }

    /// Verify that a specific payment was received at the expected stealth address.
    pub fn verify_payment(&self, announcement: &StealthAnnouncement) -> Option<StealthPaymentInfo> {
        check_stealth_announcement(announcement, &self.viewing_priv, &self.spending_pub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stealth::generate_stealth_address;
    use crate::stealth::generate_stealth_keys;

    #[test]
    fn test_scan_range() {
        let (keys, _) = generate_stealth_keys();
        let viewing_priv = keys.viewing.secret_key().unwrap();

        let results: Vec<_> = (0..5)
            .map(|_| {
                generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap()
            })
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
        assert_eq!(found.len(), 5, "Should detect all 5 payments");
    }

    #[test]
    fn test_scan_range_mixed() {
        let (keys, _) = generate_stealth_keys();
        let (other_keys, _) = generate_stealth_keys();
        let viewing_priv = keys.viewing.secret_key().unwrap();

        let our_result =
            generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap();
        let other_result = generate_stealth_address(
            &other_keys.spending.public_key,
            &other_keys.viewing.public_key,
        ).unwrap();

        let announcements = vec![
            StealthAnnouncement {
                scheme_id: 1,
                stealth_address: our_result.stealth_address.clone(),
                ephemeral_pub_key: our_result.ephemeral_pub_key,
                view_tag: our_result.view_tag,
                metadata: vec![],
            },
            StealthAnnouncement {
                scheme_id: 1,
                stealth_address: other_result.stealth_address.clone(),
                ephemeral_pub_key: other_result.ephemeral_pub_key,
                view_tag: other_result.view_tag,
                metadata: vec![],
            },
        ];

        let scanner = AnnouncementScanner::new(viewing_priv, keys.spending.public_key);

        let found = scanner.scan_range(&announcements);
        assert!(found.len() >= 1);
        assert_eq!(found[0].stealth_address, our_result.stealth_address);
    }

    #[tokio::test]
    async fn test_async_scanner() {
        let (keys, _) = generate_stealth_keys();
        let viewing_priv = keys.viewing.secret_key().unwrap();

        let scanner = AnnouncementScanner::new(viewing_priv, keys.spending.public_key);

        let (tx, mut rx) = scanner.start();

        let result =
            generate_stealth_address(&keys.spending.public_key, &keys.viewing.public_key).unwrap();

        tx.send(StealthAnnouncement {
            scheme_id: 1,
            stealth_address: result.stealth_address.clone(),
            ephemeral_pub_key: result.ephemeral_pub_key,
            view_tag: result.view_tag,
            metadata: vec![],
        })
        .await
        .unwrap();

        let info = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for payment")
            .expect("channel closed");

        assert_eq!(info.stealth_address, result.stealth_address);

        scanner.stop();
    }
}
