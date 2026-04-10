//! H33 Agent Capability Token — shared crate
//!
//! This crate defines the `cka_*` agent capability token format used across
//! the entire H33 stack: scif-backend, auth1-delivery-rs, h33-mcp, h33-cli.
//! It is the single source of truth for the token binary layout, HMAC
//! verification, capability bitmap, and mint/parse API.
//!
//! **The architectural rule this crate enforces:**
//!
//! > Agents hold `cka_*`. Servers hold `ck_live_*`. They are never the same thing.
//!
//! `ck_live_*` and `ck_test_*` keys are server-side credentials managed by the
//! H33 backend. `cka_*` tokens are short-lived, capability-scoped credentials
//! issued to AI agents via `POST /v1/agent_tokens`. The token parser in this
//! crate refuses to parse anything that does not begin with the `cka_` prefix.
//!
//! ## Wire format
//!
//! `cka_<base64url(payload || hmac)>` where `payload` is exactly 64 bytes and
//! the trailing signature is a 32-byte HMAC-SHA3-256 over the payload.
//!
//! ```text
//!   cka_<base64url(payload || hmac)>
//! ```
//!
//! Where `payload` is exactly 64 bytes:
//!
//! | Offset | Width | Field             | Encoding                          |
//! |--------|-------|-------------------|------------------------------------|
//! | 0      | 1     | version           | uint8 (currently 0x01)            |
//! | 1      | 1     | environment       | 0x00=sandbox 0x01=production      |
//! | 2      | 8     | tenant_id         | u64 big-endian                    |
//! | 10     | 16    | session_id        | 16-byte UUID                       |
//! | 26     | 8     | expires_at        | u64 big-endian Unix milliseconds  |
//! | 34     | 8     | issued_at         | u64 big-endian Unix milliseconds  |
//! | 42     | 16    | capability_bitmap | 128 bits, one per capability      |
//! | 58     | 4     | quota_scope       | u32 big-endian                    |
//! | 62     | 2     | agent_flags       | u16 big-endian                    |
//!
//! Followed by a 32-byte HMAC-SHA3-256 signature over bytes 0..63.
//!
//! Patent context: this token format is the practical implementation of
//! the capability-scoped agent access architecture described in the
//! cumulative substrate patent's claims around tenant isolation, audit
//! attribution, and the FraudGuard chain.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha3::Sha3_256;
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const PAYLOAD_LEN: usize = 64;
pub const HMAC_LEN: usize = 32;
pub const TOKEN_LEN: usize = PAYLOAD_LEN + HMAC_LEN;
pub const VERSION: u8 = 0x01;

type HmacSha3 = Hmac<Sha3_256>;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("missing cka_ prefix")]
    MissingPrefix,
    #[error("base64 decode failed")]
    Base64Decode,
    #[error("payload length invalid: expected {0} bytes, got {1}")]
    PayloadLength(usize, usize),
    #[error("unsupported version: {0:#x}")]
    UnsupportedVersion(u8),
    #[error("invalid environment byte: {0:#x}")]
    InvalidEnvironment(u8),
    #[error("HMAC verification failed (token tampered or wrong secret)")]
    HmacFailed,
    #[error("token expired at {0} (now {1})")]
    Expired(u64, u64),
    #[error("issued_at after expires_at — token format invalid")]
    InvalidTimestamps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Sandbox,
    Production,
}

impl Environment {
    fn from_byte(b: u8) -> Result<Self, TokenError> {
        match b {
            0x00 => Ok(Environment::Sandbox),
            0x01 => Ok(Environment::Production),
            other => Err(TokenError::InvalidEnvironment(other)),
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            Environment::Sandbox => 0x00,
            Environment::Production => 0x01,
        }
    }
}

/// Capability bits — must match the documented enum in
/// docs/agent-token-architecture.md §4.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Capability {
    SubstrateEnroll = 0,
    SubstrateVerify = 1,
    SubstrateAttest = 2,
    SubstrateListDomains = 3,
    SubstrateAnchorAiInference = 4,
    TenantRead = 5,
    TenantReadUsage = 6,
    TenantRotateKeys = 7,
    TenantUpdateQuota = 8,
    TenantDelete = 9,
    AuditRead = 10,
    HatsRegister = 11,
    HatsRead = 12,
    McpConnect = 13,
    SubstrateRevoke = 14,
    // 15..=127 reserved for future capabilities
    BiometricEnroll = 16,
    BiometricVerify = 17,
    ZkProve = 18,
    ZkVerify = 19,
    TripleKeySign = 20,
    TripleKeyVerify = 21,
    BotshieldChallenge = 22,
    BotshieldVerify = 23,
    HicsScan = 24,
    HicsBadge = 25,
}

impl Capability {
    pub const fn bit(self) -> u8 {
        self as u8
    }

    pub fn name(self) -> &'static str {
        match self {
            Capability::SubstrateEnroll => "substrate:enroll",
            Capability::SubstrateVerify => "substrate:verify",
            Capability::SubstrateAttest => "substrate:attest",
            Capability::SubstrateListDomains => "substrate:list_domains",
            Capability::SubstrateAnchorAiInference => "substrate:anchor_ai_inference",
            Capability::TenantRead => "tenant:read",
            Capability::TenantReadUsage => "tenant:read_usage",
            Capability::TenantRotateKeys => "tenant:rotate_keys",
            Capability::TenantUpdateQuota => "tenant:update_quota",
            Capability::TenantDelete => "tenant:delete",
            Capability::AuditRead => "audit:read",
            Capability::HatsRegister => "hats:register",
            Capability::HatsRead => "hats:read",
            Capability::McpConnect => "mcp:connect",
            Capability::SubstrateRevoke => "substrate:revoke",
            Capability::BiometricEnroll => "biometric:enroll",
            Capability::BiometricVerify => "biometric:verify",
            Capability::ZkProve => "zk:prove",
            Capability::ZkVerify => "zk:verify",
            Capability::TripleKeySign => "triple_key:sign",
            Capability::TripleKeyVerify => "triple_key:verify",
            Capability::BotshieldChallenge => "botshield:challenge",
            Capability::BotshieldVerify => "botshield:verify",
            Capability::HicsScan => "hics:scan",
            Capability::HicsBadge => "hics:badge",
        }
    }

    pub fn is_destructive(self) -> bool {
        matches!(
            self,
            Capability::TenantRotateKeys
                | Capability::TenantUpdateQuota
                | Capability::TenantDelete
                | Capability::SubstrateRevoke
        )
    }
}

/// Parsed agent token. Constructed by `AgentToken::parse`. The HMAC has
/// already been verified at construction time, so all field accesses are
/// guaranteed authentic.
#[derive(Debug, Clone)]
pub struct AgentToken {
    pub version: u8,
    pub environment: Environment,
    pub tenant_id: u64,
    pub session_id: [u8; 16],
    pub expires_at: u64,
    pub issued_at: u64,
    pub capability_bitmap: [u8; 16],
    pub quota_scope: u32,
    pub agent_flags: u16,
    /// The raw token string (without the cka_ prefix and HMAC, base64-decoded).
    /// Used as the session_secret seed for nullifier derivation.
    pub raw: Vec<u8>,
}

impl AgentToken {
    /// Parse and verify a `cka_*` token. Returns Err on:
    ///   - missing prefix
    ///   - base64 decode failure
    ///   - wrong length
    ///   - unsupported version
    ///   - HMAC mismatch
    ///   - expired token (relative to `now_ms`)
    pub fn parse(token: &str, secret: &[u8], now_ms: u64) -> Result<Self, TokenError> {
        let stripped = token.strip_prefix("cka_").ok_or(TokenError::MissingPrefix)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(stripped)
            .map_err(|_| TokenError::Base64Decode)?;
        if bytes.len() != TOKEN_LEN {
            return Err(TokenError::PayloadLength(TOKEN_LEN, bytes.len()));
        }

        let payload = &bytes[..PAYLOAD_LEN];
        let signature = &bytes[PAYLOAD_LEN..];

        // Verify HMAC in constant time
        let mut mac = HmacSha3::new_from_slice(secret).map_err(|_| TokenError::HmacFailed)?;
        mac.update(payload);
        let expected = mac.finalize().into_bytes();
        if expected.as_slice().ct_eq(signature).unwrap_u8() != 1 {
            return Err(TokenError::HmacFailed);
        }

        // Parse fields
        let version = payload[0];
        if version != VERSION {
            return Err(TokenError::UnsupportedVersion(version));
        }
        let environment = Environment::from_byte(payload[1])?;
        let tenant_id = u64::from_be_bytes(
            payload[2..10].try_into().map_err(|_| TokenError::HmacFailed)?,
        );
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&payload[10..26]);
        let expires_at = u64::from_be_bytes(
            payload[26..34].try_into().map_err(|_| TokenError::HmacFailed)?,
        );
        let issued_at = u64::from_be_bytes(
            payload[34..42].try_into().map_err(|_| TokenError::HmacFailed)?,
        );
        let mut capability_bitmap = [0u8; 16];
        capability_bitmap.copy_from_slice(&payload[42..58]);
        let quota_scope = u32::from_be_bytes(
            payload[58..62].try_into().map_err(|_| TokenError::HmacFailed)?,
        );
        let agent_flags = u16::from_be_bytes(
            payload[62..64].try_into().map_err(|_| TokenError::HmacFailed)?,
        );

        if issued_at > expires_at {
            return Err(TokenError::InvalidTimestamps);
        }
        if now_ms > expires_at {
            return Err(TokenError::Expired(expires_at, now_ms));
        }

        Ok(Self {
            version,
            environment,
            tenant_id,
            session_id,
            expires_at,
            issued_at,
            capability_bitmap,
            quota_scope,
            agent_flags,
            raw: bytes,
        })
    }

    /// Test whether the token grants the given capability.
    pub fn has_capability(&self, cap: Capability) -> bool {
        let bit = cap.bit();
        let byte = (bit / 8) as usize;
        let mask = 1u8 << (bit % 8);
        if byte >= 16 {
            return false;
        }
        self.capability_bitmap[byte] & mask != 0
    }

    /// Returns true if the token is in sandbox mode.
    pub fn is_sandbox(&self) -> bool {
        self.environment == Environment::Sandbox
    }

    /// Returns the session ID as a UUID-style hex string for logging.
    pub fn session_id_hex(&self) -> String {
        hex::encode(self.session_id)
    }

    /// Returns true if the token is expired relative to the supplied wall-clock.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.expires_at
    }

    /// Approximate remaining lifetime in milliseconds.
    pub fn ttl_remaining_ms(&self, now_ms: u64) -> u64 {
        self.expires_at.saturating_sub(now_ms)
    }
}

/// Mint a token with the given fields. Used by tests and (in production)
/// by the `auth1-delivery-rs` mint endpoint, which would link this crate
/// or duplicate the format.
#[allow(clippy::too_many_arguments)]
pub fn mint(
    secret: &[u8],
    environment: Environment,
    tenant_id: u64,
    session_id: [u8; 16],
    issued_at: u64,
    ttl_ms: u64,
    capabilities: &[Capability],
    quota_scope: u32,
    agent_flags: u16,
) -> Result<String, TokenError> {
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[0] = VERSION;
    payload[1] = environment.to_byte();
    payload[2..10].copy_from_slice(&tenant_id.to_be_bytes());
    payload[10..26].copy_from_slice(&session_id);
    let expires_at = issued_at + ttl_ms;
    payload[26..34].copy_from_slice(&expires_at.to_be_bytes());
    payload[34..42].copy_from_slice(&issued_at.to_be_bytes());

    // Build capability bitmap
    let mut bitmap = [0u8; 16];
    for cap in capabilities {
        let bit = cap.bit();
        let byte = (bit / 8) as usize;
        let mask = 1u8 << (bit % 8);
        if byte < 16 {
            bitmap[byte] |= mask;
        }
    }
    payload[42..58].copy_from_slice(&bitmap);
    payload[58..62].copy_from_slice(&quota_scope.to_be_bytes());
    payload[62..64].copy_from_slice(&agent_flags.to_be_bytes());

    let mut mac = HmacSha3::new_from_slice(secret).map_err(|_| TokenError::HmacFailed)?;
    mac.update(&payload);
    let signature = mac.finalize().into_bytes();

    let mut full = Vec::with_capacity(TOKEN_LEN);
    full.extend_from_slice(&payload);
    full.extend_from_slice(&signature);
    let encoded = URL_SAFE_NO_PAD.encode(&full);
    Ok(format!("cka_{}", encoded))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test-secret-do-not-use-in-production";

    #[test]
    fn round_trip() {
        let token = mint(
            TEST_SECRET,
            Environment::Sandbox,
            42,
            [0xab; 16],
            1_000_000,
            3_600_000,
            &[
                Capability::SubstrateEnroll,
                Capability::SubstrateVerify,
                Capability::HicsScan,
            ],
            0,
            0,
        )
        .expect("mint should succeed");

        let parsed =
            AgentToken::parse(&token, TEST_SECRET, 1_500_000).expect("parse should succeed");
        assert_eq!(parsed.version, VERSION);
        assert_eq!(parsed.environment, Environment::Sandbox);
        assert_eq!(parsed.tenant_id, 42);
        assert_eq!(parsed.session_id, [0xab; 16]);
        assert_eq!(parsed.issued_at, 1_000_000);
        assert_eq!(parsed.expires_at, 4_600_000);
        assert!(parsed.has_capability(Capability::SubstrateEnroll));
        assert!(parsed.has_capability(Capability::SubstrateVerify));
        assert!(parsed.has_capability(Capability::HicsScan));
        assert!(!parsed.has_capability(Capability::TenantDelete));
    }

    #[test]
    fn rejects_tampered_token() {
        let token = mint(
            TEST_SECRET,
            Environment::Sandbox,
            42,
            [0u8; 16],
            1_000_000,
            3_600_000,
            &[Capability::SubstrateEnroll],
            0,
            0,
        )
        .expect("mint");

        // Flip a character in the middle of the base64 — guarantee it changes
        // by picking a replacement different from the original.
        let mut chars: Vec<char> = token.chars().collect();
        let mid = chars.len() / 2;
        let original = chars[mid];
        chars[mid] = if original == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert_ne!(tampered, token);

        let result = AgentToken::parse(&tampered, TEST_SECRET, 1_500_000);
        assert!(
            matches!(
                result,
                Err(TokenError::HmacFailed)
                    | Err(TokenError::Base64Decode)
                    | Err(TokenError::PayloadLength(_, _))
            ),
            "tampered token should be rejected, got {:?}",
            result
        );
    }

    #[test]
    fn rejects_expired_token() {
        let token = mint(
            TEST_SECRET,
            Environment::Sandbox,
            42,
            [0u8; 16],
            1_000_000,
            3_600_000,
            &[Capability::SubstrateEnroll],
            0,
            0,
        )
        .expect("mint");
        let result = AgentToken::parse(&token, TEST_SECRET, 5_000_000_000);
        assert!(matches!(result, Err(TokenError::Expired(_, _))));
    }

    #[test]
    fn rejects_wrong_secret() {
        let token = mint(
            TEST_SECRET,
            Environment::Sandbox,
            42,
            [0u8; 16],
            1_000_000,
            3_600_000,
            &[Capability::SubstrateEnroll],
            0,
            0,
        )
        .expect("mint");
        let result = AgentToken::parse(&token, b"different-secret", 1_500_000);
        assert!(matches!(result, Err(TokenError::HmacFailed)));
    }

    #[test]
    fn missing_prefix_rejected() {
        let result = AgentToken::parse("not_a_token", TEST_SECRET, 1_500_000);
        assert!(matches!(result, Err(TokenError::MissingPrefix)));
    }
}
