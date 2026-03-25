use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 20-byte Ethereum address with constant-time comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Returns checksummed EIP-55 address.
    pub fn to_checksum(&self) -> String {
        use sha3::{Digest, Keccak256};
        let hex_addr = hex::encode(self.0);
        let hash = Keccak256::digest(hex_addr.as_bytes());
        let mut result = String::with_capacity(42);
        result.push_str("0x");
        for (i, c) in hex_addr.chars().enumerate() {
            if c.is_ascii_digit() {
                result.push(c);
            } else {
                let hash_nibble = if i % 2 == 0 {
                    hash[i / 2] >> 4
                } else {
                    hash[i / 2] & 0x0f
                };
                if hash_nibble >= 8 {
                    result.push(c.to_ascii_uppercase());
                } else {
                    result.push(c.to_ascii_lowercase());
                }
            }
        }
        result
    }

    pub fn from_hex(s: &str) -> Result<Self, StealthError> {
        let clean = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(clean).map_err(|_| StealthError::InvalidHex)?;
        if bytes.len() != 20 {
            return Err(StealthError::InvalidAddress);
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes);
        Ok(Address(addr))
    }
}

// C-RS-2: Constant-time address comparison for privacy-sensitive stealth address matching
impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Address {}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_checksum())
    }
}

/// Stealth key pair (private + compressed public key).
/// Private key bytes are zeroized on drop (C-RS-1).
#[derive(Clone, ZeroizeOnDrop)]
pub struct StealthKeyPair {
    #[zeroize(skip)]
    pub public_key: PublicKey,
    private_key_bytes: [u8; 32],
}

impl StealthKeyPair {
    pub fn new(secret: SecretKey) -> Self {
        let public_key = secret.public_key();
        let bytes = secret.to_bytes();
        let mut private_key_bytes = [0u8; 32];
        private_key_bytes.copy_from_slice(&bytes);
        Self {
            public_key,
            private_key_bytes,
        }
    }

    /// Returns the 33-byte compressed public key.
    pub fn compressed_pub(&self) -> [u8; 33] {
        let point = self.public_key.to_encoded_point(true);
        let mut buf = [0u8; 33];
        buf.copy_from_slice(point.as_bytes());
        buf
    }

    /// Returns the private key as a Zeroizing wrapper.
    pub fn private_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.private_key_bytes)
    }

    /// Get the SecretKey (reconstructed from bytes).
    pub fn secret_key(&self) -> Result<SecretKey, StealthError> {
        SecretKey::from_slice(&self.private_key_bytes)
            .map_err(|_| StealthError::InvalidPrivateKey)
    }
}

impl std::fmt::Debug for StealthKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StealthKeyPair")
            .field("public_key", &"[redacted]")
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Spending + viewing key pairs.
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct StealthKeys {
    pub spending: StealthKeyPair,
    pub viewing: StealthKeyPair,
}

/// Result of generating a stealth address for a payment.
#[derive(Debug, Clone)]
pub struct GenerateStealthAddressResult {
    /// The one-time stealth address to send funds to.
    pub stealth_address: Address,
    /// Ephemeral public key (33 bytes compressed) for the announcement.
    pub ephemeral_pub_key: [u8; 33],
    /// View tag (first byte of keccak256(shared_secret)) for fast scanning.
    pub view_tag: u8,
}

/// Information about a detected stealth payment.
#[derive(Debug, Clone)]
pub struct StealthPaymentInfo {
    /// The stealth address that matched.
    pub stealth_address: Address,
    /// The shared secret scalar s (needs k_spend added for full private key).
    shared_secret_scalar_inner: [u8; 32],
    /// The ephemeral public key from the announcement.
    pub ephemeral_pub_key: [u8; 33],
}

impl StealthPaymentInfo {
    pub fn new(stealth_address: Address, shared_secret_scalar: [u8; 32], ephemeral_pub_key: [u8; 33]) -> Self {
        Self {
            stealth_address,
            shared_secret_scalar_inner: shared_secret_scalar,
            ephemeral_pub_key,
        }
    }

    /// Access the shared secret scalar (returns a copy that should be zeroized after use).
    pub fn shared_secret_scalar(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.shared_secret_scalar_inner)
    }
}

impl Drop for StealthPaymentInfo {
    fn drop(&mut self) {
        self.shared_secret_scalar_inner.zeroize();
    }
}

/// A stealth announcement from the chain.
#[derive(Debug, Clone)]
pub struct StealthAnnouncement {
    pub scheme_id: u64,
    pub stealth_address: Address,
    pub ephemeral_pub_key: [u8; 33],
    pub view_tag: u8,
    pub metadata: Vec<u8>,
}

/// Parsed confidential payment challenge from WWW-Authenticate header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialChallenge {
    pub id: String,
    pub method: String,
    pub intent: String,
    pub request: String,
    pub stealth_meta: String,
}

/// Result of a confidential payment execution.
#[derive(Debug, Clone)]
pub struct ConfidentialPaymentResult {
    pub tx_hash: [u8; 32],
    pub announcement_tx_hash: [u8; 32],
    pub stealth_address: Address,
    pub credential: String,
}

#[derive(Debug, thiserror::Error)]
pub enum StealthError {
    #[error("Invalid hex string")]
    InvalidHex,
    #[error("Invalid meta-address length: expected 66 bytes, got {0}")]
    InvalidMetaAddressLength(usize),
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Unsupported scheme ID: {0}")]
    UnsupportedScheme(u64),
    #[error("Degenerate scalar (zero after reduction)")]
    DegenerateScalar,
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Parse error: {0}")]
    Parse(String),
}
