# h33-agent-token

**Shared Rust crate defining the H33 `cka_*` agent capability token format.**

Used across the entire H33 stack: `scif-backend`, `auth1-delivery-rs`, `h33-mcp`, `h33-cli`. This is the single source of truth for the token binary layout, HMAC verification, capability bitmap, and mint/parse API.

---

## The architectural rule

> **Agents hold `cka_*`. Servers hold `ck_live_*`. They are never the same thing.**

- `ck_live_*` — production API keys, server-side only, managed by the H33 backend. Never enters an agent context.
- `ck_test_*` — sandbox API keys, same rules, safer for dev.
- `cka_*` — agent capability tokens, short-lived (1–24 hours), capability-scoped, attributable to a specific human user. This is what AI agents (Claude Code, Cursor, Codex, Aider) hold.

The token parser in this crate refuses anything that does not begin with `cka_`. Every other H33 service depends on this invariant holding at the boundary.

---

## Wire format

```
cka_<base64url(payload || hmac)>
```

Where `payload` is exactly 64 bytes:

| Offset | Width | Field             | Encoding                          |
|-------:|------:|:------------------|:----------------------------------|
|      0 |     1 | version           | uint8 (currently `0x01`)          |
|      1 |     1 | environment       | `0x00`=sandbox `0x01`=production  |
|      2 |     8 | tenant_id         | u64 big-endian                    |
|     10 |    16 | session_id        | 16-byte UUID                      |
|     26 |     8 | expires_at        | u64 big-endian Unix milliseconds  |
|     34 |     8 | issued_at         | u64 big-endian Unix milliseconds  |
|     42 |    16 | capability_bitmap | 128 bits, one per capability     |
|     58 |     4 | quota_scope       | u32 big-endian                    |
|     62 |     2 | agent_flags       | u16 big-endian                    |

Followed by a 32-byte HMAC-SHA3-256 signature over bytes 0..63.

---

## Usage

### Parse and verify a token

```rust
use h33_agent_token::{AgentToken, Capability};

let now_ms = 1_700_000_000_000u64;
let token = AgentToken::parse(token_str, secret, now_ms)?;

// Tenant extracted from the signed boundary — safe to trust after parse
let tenant_id = token.tenant_id;

// Capability bitmap check
if !token.has_capability(Capability::SubstrateEnroll) {
    return Err(MyError::MissingCapability);
}

// Sandbox vs production
if token.is_sandbox() {
    // Route to sandbox.api.h33.ai
}
```

### Mint a new token (H33 backend only)

```rust
use h33_agent_token::{mint, Capability, Environment};

let token_str = mint(
    secret,
    Environment::Sandbox,
    tenant_id,
    session_id,
    issued_at_ms,
    3_600_000,  // 1 hour TTL
    &[
        Capability::SubstrateEnroll,
        Capability::SubstrateVerify,
        Capability::HicsScan,
    ],
    0,  // quota_scope
    0,  // agent_flags
)?;
```

---

## Capability bits

| Bit | Capability                           | Description                                      |
|----:|:-------------------------------------|:-------------------------------------------------|
|   0 | `SubstrateEnroll`                    | Create new substrate anchors                     |
|   1 | `SubstrateVerify`                    | Verify existing anchors                          |
|   2 | `SubstrateAttest`                    | Issue fresh attestations                         |
|   3 | `SubstrateListDomains`               | List registry domain identifiers                 |
|   4 | `SubstrateAnchorAiInference`         | Substrate + HATS Tier 1 in one call              |
|   5 | `TenantRead`                         | Read tenant metadata                             |
|   6 | `TenantReadUsage`                    | Read quota / usage                               |
|   7 | `TenantRotateKeys` **(destructive)** | Rotate API keys                                  |
|   8 | `TenantUpdateQuota` **(destructive)**| Adjust quota                                     |
|   9 | `TenantDelete` **(destructive)**     | Delete tenant                                    |
|  10 | `AuditRead`                          | Read agent session audit log                     |
|  11 | `HatsRegister`                       | Register AI endpoint in HATS governance          |
|  12 | `HatsRead`                           | Read HATS compliance status                      |
|  13 | `McpConnect`                         | Connect to H33 MCP server                        |
|  14 | `SubstrateRevoke` **(destructive)**  | Revoke an existing anchor                        |
|  16 | `BiometricEnroll`                    | Enroll a biometric template under FHE            |
|  17 | `BiometricVerify`                    | Verify a probe template                          |
|  18 | `ZkProve`                            | Generate a STARK lookup proof                    |
|  19 | `ZkVerify`                           | Verify a STARK proof                             |
|  20 | `TripleKeySign`                      | Nested Ed25519 + Dilithium-5 + FALCON-512        |
|  21 | `TripleKeyVerify`                    | Verify a triple-key anchor                       |
|  22 | `BotshieldChallenge`                 | Issue a PoW challenge                            |
|  23 | `BotshieldVerify`                    | Verify a PoW solution                            |
|  24 | `HicsScan`                           | Run a HICS cryptographic scan                    |
|  25 | `HicsBadge`                          | Format a scan result as a Markdown PR badge      |

Bits 15, 26-127 are reserved. Destructive capabilities require two-phase confirmation on the H33 API side.

---

## Integration across the H33 stack

### `scif-backend` (server)

Verifies incoming `cka_*` tokens on every authenticated endpoint. Extracts the `tenant_id` from the HMAC-covered payload and uses it for authorization. Checks the capability bitmap per-route.

### `auth1-delivery-rs` (auth server)

Owns the `POST /v1/agent_tokens` mint endpoint. Calls `mint()` with a per-tenant HMAC secret and the human-approved capability set. Never parses incoming `cka_*` — only issues them.

### `h33-mcp` (MCP server)

Holds a `cka_*` token handed in via env var. Validates the prefix at startup (refuses `ck_live_*`), then passes the token as a bearer on every downstream H33 API call. Uses the token's `session_id` to seed the FraudGuard nullifier cache.

### `h33-cli` (developer CLI)

Mints a `cka_*` token for a terminal AI session, stores it in memory, passes it to the `h33-mcp` subprocess via env var. Never persists.

---

## Testing

```bash
cargo test
```

Current test coverage:
- ✅ Round-trip mint/parse preserves all fields
- ✅ Expired token rejected
- ✅ Wrong secret rejected
- ✅ Tampered token rejected (HMAC check)
- ✅ Missing prefix rejected
- ✅ Capability bitmap precision

---

## Publishing to the private GitLab registry

```bash
cargo publish --registry h33-private
```

Assumes `.cargo/config.toml` has:

```toml
[registries.h33-private]
index = "https://gitlab.com/drata5764111/h33/_cargo-api/packages/cargo"
```

---

## License

Proprietary. Commercial License Required. See `LICENSE`.

This crate is part of the H33 post-quantum security infrastructure. Patent pending.

---

**H33 Products:** [H33-74](https://h33.ai) · [Auth1](https://auth1.ai) · [Chat101](https://chat101.ai) · [Cachee](https://cachee.ai) · [Z101](https://z101.ai) · [RevMine](https://revmine.ai) · [BotShield](https://h33.ai/botshield)

*Introducing H33-74. 74 bytes. Any computation. Post-quantum attested. Forever.*


---

## H33 Product Suite

| Product | Description |
|---------|-------------|
| [H33.ai](https://h33.ai) | Post-quantum security infrastructure |
| [V100.ai](https://v100.ai) | AI Video API — 20 Rust microservices, post-quantum encrypted |
| [Auth1.ai](https://auth1.ai) | Multi-tenant auth without Auth0 |
| [Chat101.ai](https://chat101.ai) | AI chat widget with Rust gateway sidecar |
| [Cachee.ai](https://cachee.ai) | Sub-microsecond PQ-attested cache |
| [Z101.ai](https://z101.ai) | 20+ SaaS products on one backend |
| [RevMine.ai](https://revmine.ai) | Revenue intelligence platform |
| [BotShield](https://h33.ai/botshield) | Free CAPTCHA replacement |

*Introducing H33-74. 74 bytes. Any computation. Post-quantum attested. Forever.*
