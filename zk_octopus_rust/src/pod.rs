/// POD Credential construction
///
/// Converts raw Octopus transaction data into a Zupass-compatible
/// POD (Provable Object Data) credential, with a mocked Poseidon Merkle
/// tree (SHA-256 stand-in) and EdDSA signature (also mocked).
///
/// In the real system:
///   - The Merkle tree uses the Poseidon hash function (ZK-circuit-friendly)
///   - The issuer signature is EdDSA on the Baby JubJub curve
///   - Data provenance is attested by TLSNotary over the Octopus portal API

use anyhow::Result;
use sha2::{Sha256, Digest};
use hex;
use chrono::Utc;

use crate::types::*;

/// Build a POD credential from a slice of Octopus transactions.
///
/// Aggregates the transactions into summary statistics, encodes them as
/// POD entries, and produces the Merkle root + issuer signature.
pub fn build_pod(
    txns:         &[OctopusTransaction],
    zone:         &Zone,
    period:       &str,
    registration: RegistrationStatus,
    notary_session_id: &str,
) -> Result<PodCredential> {
    // ── 1. Aggregate statistics from transactions ──────────────────────────
    let transit_count = txns.iter()
        .filter(|t| t.category == TransactionCategory::Transit && &t.zone == zone)
        .count() as i64;

    let mgmt_fee_total = txns.iter()
        .filter(|t| t.category == TransactionCategory::BuildingAccess)
        .map(|t| t.amount_cents.abs())
        .sum::<i64>();

    let retail_total = txns.iter()
        .filter(|t| t.category == TransactionCategory::Retail)
        .map(|t| t.amount_cents.abs())
        .sum::<i64>();

    let transit_fare_total = txns.iter()
        .filter(|t| t.category == TransactionCategory::Transit)
        .map(|t| t.amount_cents.abs())
        .sum::<i64>();

    // Temporal regularity: count weekday morning taps (06:00–09:30)
    let morning_commute_count = txns.iter()
        .filter(|t| {
            t.category == TransactionCategory::Transit
                && t.timestamp.format("%H").to_string().parse::<u32>().unwrap_or(99) < 10
        })
        .count() as i64;

    // ── 2. Encode as POD entries ───────────────────────────────────────────
    let entries = vec![
        PodEntry { key: "zone".into(),                value: PodValue::String(zone.to_string()) },
        PodEntry { key: "period".into(),              value: PodValue::String(period.to_string()) },
        PodEntry { key: "transit_count".into(),       value: PodValue::Integer(transit_count) },
        PodEntry { key: "mgmt_fee_total".into(),      value: PodValue::Integer(mgmt_fee_total) },
        PodEntry { key: "retail_total".into(),        value: PodValue::Integer(retail_total) },
        PodEntry { key: "transit_fare_total".into(),  value: PodValue::Integer(transit_fare_total) },
        PodEntry { key: "morning_commute_count".into(), value: PodValue::Integer(morning_commute_count) },
        PodEntry { key: "tx_count".into(),            value: PodValue::Integer(txns.len() as i64) },
        PodEntry { key: "registration_class".into(),  value: PodValue::String(match &registration {
            RegistrationStatus::Pseudonymous               => "PSEUDONYMOUS".into(),
            RegistrationStatus::IdentityRegistered { .. }  => "IDENTITY_REGISTERED".into(),
        })},
    ];

    // ── 3. Build Poseidon Merkle tree (mocked with SHA-256) ───────────────
    //
    // Real implementation: each entry value → Poseidon hash → leaf node
    // → pairwise Poseidon hash up the tree → root.
    // Mock: SHA-256(key || "|" || value) per entry, then SHA-256 of concatenated leaf hashes.
    let leaf_hashes: Vec<[u8; 32]> = entries.iter().map(|e| {
        let mut hasher = Sha256::new();
        hasher.update(e.key.as_bytes());
        hasher.update(b"|");
        hasher.update(e.value.to_string().as_bytes());
        let h = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h);
        arr
    }).collect();

    let merkle_root = {
        let mut hasher = Sha256::new();
        for leaf in &leaf_hashes {
            hasher.update(leaf);
        }
        hex::encode(hasher.finalize())
    };

    // ── 4. Mock issuer signature (EdDSA on BabyJubJub in reality) ─────────
    let issuer_signature = {
        let mut hasher = Sha256::new();
        hasher.update(b"LOCAL_ISSUER_SECRET");
        hasher.update(merkle_root.as_bytes());
        hex::encode(hasher.finalize())
    };

    // ── 5. Provenance hash — commits to TLSNotary session ─────────────────
    let provenance_hash = {
        let mut hasher = Sha256::new();
        hasher.update(b"TLSNOTARY_NOTARY_PUBKEY");
        hasher.update(notary_session_id.as_bytes());
        hasher.update(merkle_root.as_bytes());
        hex::encode(hasher.finalize())
    };

    Ok(PodCredential {
        entries,
        merkle_root,
        issuer_signature,
        provenance_hash,
        registration,
        issued_at: Utc::now(),
    })
}

/// Verify that a POD credential's Merkle root is consistent with its entries.
/// Returns true if the locally-recomputed root matches the stored root.
pub fn verify_pod_integrity(pod: &PodCredential) -> bool {
    let leaf_hashes: Vec<[u8; 32]> = pod.entries.iter().map(|e| {
        let mut hasher = Sha256::new();
        hasher.update(e.key.as_bytes());
        hasher.update(b"|");
        hasher.update(e.value.to_string().as_bytes());
        let h = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h);
        arr
    }).collect();

    let computed_root = {
        let mut hasher = Sha256::new();
        for leaf in &leaf_hashes {
            hasher.update(leaf);
        }
        hex::encode(hasher.finalize())
    };

    computed_root == pod.merkle_root
}

/// Display a POD credential in a human-readable table.
pub fn display_pod(pod: &PodCredential) {
    println!("\n┌─ POD Credential ─────────────────────────────────────────────");
    println!("│ Issued:      {}", pod.issued_at.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("│ Status:      {:?}", pod.registration);
    println!("│ Merkle root: 0x{}…", &pod.merkle_root[..16]);
    println!("│ Provenance:  0x{}…", &pod.provenance_hash[..16]);
    println!("├─ Entries ────────────────────────────────────────────────────");
    for e in &pod.entries {
        println!("│  {:32} = {}", e.key, e.value);
    }
    println!("└──────────────────────────────────────────────────────────────");
}
