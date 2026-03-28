/// Core data types for ZK-Octopus
///
/// POD (Provable Object Data) structures, Octopus transaction records,
/// and claim predicates modelled after the Zupass POD / GPC framework.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

// ─── Octopus Transaction ───────────────────────────────────────────────────

/// Category of an Octopus card transaction, encoding the four touchpoint domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionCategory {
    Transit,
    Retail,
    BuildingAccess,
    GovernmentService,
}

impl std::fmt::Display for TransactionCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transit          => write!(f, "TRANSIT"),
            Self::Retail           => write!(f, "RETAIL"),
            Self::BuildingAccess   => write!(f, "BUILDING_ACCESS"),
            Self::GovernmentService => write!(f, "GOV_SERVICE"),
        }
    }
}

/// Hong Kong geographic zones aligned with MTR district boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Zone {
    Kowloon,
    HongKongIsland,
    NewTerritories,
    Lantau,
}

impl std::fmt::Display for Zone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kowloon        => write!(f, "KOWLOON"),
            Self::HongKongIsland => write!(f, "HONG_KONG_ISLAND"),
            Self::NewTerritories => write!(f, "NEW_TERRITORIES"),
            Self::Lantau         => write!(f, "LANTAU"),
        }
    }
}

/// A single Octopus card transaction record (the private witness).
///
/// In the real system this would be fetched from the Octopus portal API
/// via TLSNotary and never leave the cardholder's device in plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OctopusTransaction {
    /// Unix timestamp of the tap
    pub timestamp:   DateTime<Utc>,
    /// Human-readable terminal name (e.g. "MTR Kowloon Tong")
    pub terminal_id: String,
    /// Amount in HKD cents (negative = debit from card)
    pub amount_cents: i64,
    /// Domain category
    pub category:    TransactionCategory,
    /// Geographic zone of the terminal
    pub zone:        Zone,
}

impl OctopusTransaction {
    pub fn amount_hkd(&self) -> f64 {
        self.amount_cents as f64 / 100.0
    }
}

// ─── POD Credential ───────────────────────────────────────────────────────

/// A POD entry value — mirrors the Zupass POD type system.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum PodValue {
    /// Arbitrary UTF-8 string
    String(String),
    /// Signed 64-bit integer (HKD cents, trip counts, timestamps, …)
    Integer(i64),
    /// Raw bytes encoded as hex (hashes, signatures, …)
    Bytes(String),
}

impl std::fmt::Display for PodValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s)  => write!(f, "{s}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::Bytes(h)   => write!(f, "{}", &h[..std::cmp::min(h.len(), 16)]),
        }
    }
}

/// A single key-value entry in a POD credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodEntry {
    pub key:   String,
    pub value: PodValue,
}

/// The registration status of the cardholder — the two-class distinction
/// that is central to the PDPO analysis in the paper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistrationStatus {
    /// Anonymous stored-value token; no personal data linked
    Pseudonymous,
    /// Card is bound to an HKID number (daily > HKD 3,000 or annual > HKD 25,000)
    IdentityRegistered { hkid_hash: String },
}

/// A ZK-Octopus POD credential.
///
/// The `entries` form a Poseidon Merkle tree (mocked here with SHA-256).
/// The `merkle_root` and `issuer_signature` are produced by the local
/// issuance service on the cardholder's device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodCredential {
    /// All key-value entries hashed into the Merkle tree
    pub entries:          Vec<PodEntry>,
    /// Poseidon Merkle root (mock: SHA-256 of sorted entry hashes)
    pub merkle_root:      String,
    /// EdDSA signature by the local issuer (mock: SHA-256-based)
    pub issuer_signature: String,
    /// Commitment to the TLSNotary attestation for data provenance
    pub provenance_hash:  String,
    /// Which user class generated this credential
    pub registration:     RegistrationStatus,
    /// ISO-8601 issuance time
    pub issued_at:        DateTime<Utc>,
}

// ─── Claim Predicates ─────────────────────────────────────────────────────

/// A ZK-Octopus claim predicate — what the prover wants to prove
/// without revealing the underlying transaction data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClaimPredicate {
    /// Prove that the number of transit taps in a given zone during a
    /// given time window (YYYY-MM) is at least `min_trips`.
    MobilityThreshold {
        zone:       Zone,
        period:     String,
        min_trips:  u32,
    },

    /// Prove that cumulative payments in a given category during a time
    /// window lie within [min_cents, max_cents].
    AggregatePayment {
        category:  TransactionCategory,
        period:    String,
        min_cents: i64,
        max_cents: Option<i64>,
    },

    /// Prove that a usage pattern (e.g. weekday morning commute) occurred
    /// at least `min_occurrences` times in the specified window.
    TemporalRegularity {
        pattern:         String,
        period:          String,
        min_occurrences: u32,
    },

    /// Compound credential: residency in a district, evidenced by both
    /// transit usage and management fee payment thresholds.
    CompositeResidency {
        district:       String,
        min_trips:      u32,
        min_fee_cents:  i64,
        period:         String,
    },
}

impl ClaimPredicate {
    pub fn name(&self) -> &'static str {
        match self {
            Self::MobilityThreshold { .. }  => "MobilityThreshold",
            Self::AggregatePayment { .. }   => "AggregatePayment",
            Self::TemporalRegularity { .. } => "TemporalRegularity",
            Self::CompositeResidency { .. } => "CompositeResidency",
        }
    }

    pub fn eas_schema(&self) -> &'static str {
        match self {
            Self::MobilityThreshold { .. }  => "MobilityCredential",
            Self::AggregatePayment { .. }   => "PaymentComplianceCredential",
            Self::TemporalRegularity { .. } => "MobilityCredential",
            Self::CompositeResidency { .. } => "CompositeResidencyCredential",
        }
    }
}

// ─── Proof & Attestation ─────────────────────────────────────────────────

/// The public output of a satisfied predicate — what the verifier learns.
/// This is the *only* information that leaves the prover's device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PublicOutput {
    /// Boolean: claim is satisfied or not
    Boolean(bool),
    /// Range bucket: value lies in [lo, hi) HKD cents
    RangeBucket { lo: i64, hi: i64 },
    /// Aggregate count (no individual records)
    AggregateCount(u32),
}

impl std::fmt::Display for PublicOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Boolean(b)            => write!(f, "{}", if *b { "TRUE ✓" } else { "FALSE ✗" }),
            Self::RangeBucket { lo, hi } => write!(f, "HKD {:.2}–{:.2}", *lo as f64/100.0, *hi as f64/100.0),
            Self::AggregateCount(n)     => write!(f, "count={n}"),
        }
    }
}

/// A mock Groth16 proof.  In the real system this would be a 256-byte
/// proof over BN254 generated by Mopro/rapidsnark on the cardholder's device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockProof {
    /// Serialised proof bytes (mock: random hex)
    pub proof_bytes:      String,
    /// Public inputs to the circuit (claim parameters)
    pub public_inputs:    Vec<String>,
    /// Semaphore nullifier — deterministic per (identity, scope)
    pub nullifier:        String,
    /// The verified public output of the claim
    pub public_output:    PublicOutput,
    /// Name of the GPC claim predicate
    pub predicate_name:   String,
    /// Approximate proof generation time on mobile (mock)
    pub proving_time_ms:  u64,
}

/// An EAS-style on-chain attestation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EasAttestation {
    /// Attestation UID (mock: random 32-byte hex)
    pub uid:            String,
    /// EAS schema identifier
    pub schema:         String,
    /// The smart contract that issued the attestation
    pub attester:       String,
    /// Recipient — anonymous; only the nullifier is recorded
    pub recipient:      String,
    /// Serialised public claim data (JSON)
    pub data:           String,
    /// Arbitrum One block number (mock)
    pub block_number:   u64,
    /// Gas used by ZKOctopusResolver.attest()
    pub gas_used:       u64,
    /// Attestation timestamp
    pub timestamp:      DateTime<Utc>,
}
