/// Mock ZK Proof Engine
///
/// Simulates the GPC (General Purpose Circuits) + Mopro Groth16 proving stack.
///
/// Real implementation:
///   - Each ClaimPredicate maps to a declarative GPC configuration
///   - GPC selects the appropriate pre-compiled Circom + Groth16 circuit
///   - Mopro compiles the prover to ARM native for iOS/Android
///   - Proof size: ~256 bytes constant; verification: ~200k gas on Arbitrum One
///
/// Mock implementation:
///   - Evaluates the predicate over the POD entries to determine satisfiability
///   - Generates mock proof bytes (SHA-256 of proof parameters)
///   - Computes a deterministic nullifier via SHA-256(identity_secret || scope)
///   - Returns a MockProof with public outputs only

use anyhow::{anyhow, Result};
use sha2::{Sha256, Digest};
use hex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::*;

/// Simulates the Semaphore V4 identity layer.
///
/// In the real system, `identity_secret` is an EdDSA private key on
/// Baby JubJub that never leaves the cardholder's device.
pub struct SemaphoreIdentity {
    /// The secret key (kept private — only its hash is ever used)
    secret_key_hash: [u8; 32],
    /// The public key commitment (mock: SHA-256 of secret)
    pub pubkey_hex:  String,
}

impl SemaphoreIdentity {
    pub fn new(secret: &str) -> Self {
        let mut h = Sha256::new();
        h.update(secret.as_bytes());
        let hash = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);
        let pubkey_hex = hex::encode(&arr);
        Self { secret_key_hash: arr, pubkey_hex }
    }

    /// Compute the deterministic nullifier for a given verifier scope.
    ///
    /// Property: same (identity, scope) → same nullifier, preventing double-use.
    /// Property: different scopes → different nullifiers, preventing cross-verifier
    ///   linkability (the verifier cannot tell that two proofs came from the same user).
    pub fn nullifier(&self, scope: &str) -> String {
        let mut h = Sha256::new();
        h.update(&self.secret_key_hash);
        h.update(scope.as_bytes());
        hex::encode(h.finalize())
    }

    /// Produce a mock ownership proof (Semaphore membership proof).
    pub fn ownership_proof(&self, merkle_root: &str) -> String {
        let mut h = Sha256::new();
        h.update(&self.secret_key_hash);
        h.update(merkle_root.as_bytes());
        hex::encode(h.finalize())
    }
}

/// In-memory nullifier registry (replaces on-chain storage in the mock).
#[derive(Default)]
pub struct NullifierRegistry {
    used: std::collections::HashSet<String>,
}

impl NullifierRegistry {
    pub fn check_and_register(&mut self, nullifier: &str) -> Result<()> {
        if self.used.contains(nullifier) {
            return Err(anyhow!("Double-use detected: nullifier {} already registered", &nullifier[..16]));
        }
        self.used.insert(nullifier.to_string());
        Ok(())
    }

    pub fn is_used(&self, nullifier: &str) -> bool {
        self.used.contains(nullifier)
    }
}

/// Evaluate a claim predicate against a POD credential.
///
/// Returns the public output (boolean / range bucket / count) without
/// revealing the underlying entry values to any external party.
pub fn evaluate_predicate(pod: &PodCredential, predicate: &ClaimPredicate) -> Result<PublicOutput> {
    let get_int = |key: &str| -> Result<i64> {
        pod.entries.iter()
            .find(|e| e.key == key)
            .and_then(|e| if let PodValue::Integer(n) = &e.value { Some(*n) } else { None })
            .ok_or_else(|| anyhow!("Missing POD entry: {key}"))
    };
    let get_str = |key: &str| -> Result<String> {
        pod.entries.iter()
            .find(|e| e.key == key)
            .and_then(|e| if let PodValue::String(s) = &e.value { Some(s.clone()) } else { None })
            .ok_or_else(|| anyhow!("Missing POD entry: {key}"))
    };

    match predicate {
        ClaimPredicate::MobilityThreshold { zone, period, min_trips } => {
            let pod_zone   = get_str("zone")?;
            let pod_period = get_str("period")?;
            let count      = get_int("transit_count")?;

            if pod_zone != zone.to_string() {
                return Err(anyhow!("Zone mismatch: credential is for {pod_zone}, predicate requires {zone}"));
            }
            if pod_period != *period {
                return Err(anyhow!("Period mismatch: credential is for {pod_period}, predicate requires {period}"));
            }
            Ok(PublicOutput::Boolean(count >= *min_trips as i64))
        }

        ClaimPredicate::AggregatePayment { category, period, min_cents, max_cents } => {
            let pod_period = get_str("period")?;
            if pod_period != *period {
                return Err(anyhow!("Period mismatch"));
            }
            let total = match category {
                TransactionCategory::Transit          => get_int("transit_fare_total")?,
                TransactionCategory::BuildingAccess   => get_int("mgmt_fee_total")?,
                TransactionCategory::Retail           => get_int("retail_total")?,
                TransactionCategory::GovernmentService => 0,
            };
            let lower_ok = total >= *min_cents;
            let upper_ok = max_cents.map_or(true, |max| total <= max);
            // Return a range bucket rather than the exact total
            let bucket_size = 50_000i64; // HKD 500 buckets
            let lo = (total / bucket_size) * bucket_size;
            let hi = lo + bucket_size;
            if lower_ok && upper_ok {
                Ok(PublicOutput::RangeBucket { lo, hi })
            } else {
                Ok(PublicOutput::Boolean(false))
            }
        }

        ClaimPredicate::TemporalRegularity { period, min_occurrences, .. } => {
            let pod_period = get_str("period")?;
            if pod_period != *period {
                return Err(anyhow!("Period mismatch"));
            }
            let count = get_int("morning_commute_count")?;
            Ok(PublicOutput::Boolean(count >= *min_occurrences as i64))
        }

        ClaimPredicate::CompositeResidency { period, min_trips, min_fee_cents, .. } => {
            let pod_period  = get_str("period")?;
            if pod_period != *period {
                return Err(anyhow!("Period mismatch"));
            }
            let trips = get_int("transit_count")?;
            let fees  = get_int("mgmt_fee_total")?;
            Ok(PublicOutput::Boolean(
                trips >= *min_trips as i64 && fees >= *min_fee_cents
            ))
        }
    }
}

/// Generate a mock Groth16 proof for a given claim against a POD credential.
///
/// This simulates the Mopro + rapidsnark proving pipeline:
///   1. Evaluate the predicate (witness computation)
///   2. Produce mock proof bytes
///   3. Compute Semaphore nullifier and ownership proof
///   4. Package into MockProof (public outputs only)
pub fn generate_proof(
    pod:        &PodCredential,
    predicate:  &ClaimPredicate,
    identity:   &SemaphoreIdentity,
    scope:      &str,
) -> Result<MockProof> {
    // ── 1. Evaluate predicate (the private witness computation) ───────────
    let public_output = evaluate_predicate(pod, predicate)?;

    // ── 2. Build public inputs for the circuit ────────────────────────────
    let public_inputs = vec![
        format!("merkle_root=0x{}", &pod.merkle_root[..16]),
        format!("predicate={}", predicate.name()),
        format!("nullifier=0x{}", &identity.nullifier(scope)[..16]),
        format!("scope={scope}"),
        format!("output={public_output}"),
    ];

    // ── 3. Produce mock proof bytes ────────────────────────────────────────
    // Real: Groth16 proof = (A: G1, B: G2, C: G1) over BN254 ≈ 256 bytes.
    let proof_bytes = {
        let mut h = Sha256::new();
        h.update(pod.merkle_root.as_bytes());
        h.update(predicate.name().as_bytes());
        h.update(identity.nullifier(scope).as_bytes());
        h.update(public_output.to_string().as_bytes());
        // Extend to 128 hex chars (≈ 64 bytes mock; real would be 256 bytes)
        let base = hex::encode(h.finalize());
        let mut h2 = Sha256::new();
        h2.update(base.as_bytes());
        format!("{base}{}", hex::encode(h2.finalize()))
    };

    // ── 4. Ownership proof via Semaphore ──────────────────────────────────
    let _ownership_proof = identity.ownership_proof(&pod.merkle_root);

    // ── 5. Simulate proving time (representative of Mopro benchmarks) ─────
    let proving_time_ms = match predicate {
        ClaimPredicate::MobilityThreshold { .. }  => 820,   // simple: ~1s
        ClaimPredicate::AggregatePayment { .. }   => 1_100, // medium
        ClaimPredicate::TemporalRegularity { .. } => 1_350, // medium
        ClaimPredicate::CompositeResidency { .. } => 2_400, // composite: ~2.4s
    };

    // Simulate time passing
    let _ = SystemTime::now().duration_since(UNIX_EPOCH);

    Ok(MockProof {
        proof_bytes,
        public_inputs,
        nullifier:      identity.nullifier(scope),
        public_output,
        predicate_name: predicate.name().to_string(),
        proving_time_ms,
    })
}

/// Verify a MockProof against the expected public parameters.
/// In the real system this is done by the ZKOctopusResolver Solidity contract
/// using Ethereum's BN254 precompiles (ecAdd, ecMul, ecPairing).
pub fn verify_proof(
    proof:       &MockProof,
    pod:         &PodCredential,
    registry:    &mut NullifierRegistry,
) -> Result<bool> {
    // ── 1. Check nullifier has not been used before ───────────────────────
    registry.check_and_register(&proof.nullifier)?;

    // ── 2. Recompute expected proof bytes and compare (mock verification) ─
    // Real: pairing check on BN254: e(A, B) == e(α, β) * e(vk, γ) * e(C, δ)
    let expected_prefix = {
        let mut h = Sha256::new();
        h.update(pod.merkle_root.as_bytes());
        h.update(proof.predicate_name.as_bytes());
        h.update(proof.nullifier.as_bytes());
        h.update(proof.public_output.to_string().as_bytes());
        hex::encode(h.finalize())
    };

    Ok(proof.proof_bytes.starts_with(&expected_prefix))
}

pub fn display_proof(proof: &MockProof) {
    println!("\n┌─ Mock Groth16 Proof ──────────────────────────────────────────");
    println!("│ Predicate:    {}", proof.predicate_name);
    println!("│ Result:       {}", proof.public_output);
    println!("│ Proving time: {} ms  (target: <3000 ms on mobile)", proof.proving_time_ms);
    println!("│ Proof:        0x{}…", &proof.proof_bytes[..32]);
    println!("│ Nullifier:    0x{}…", &proof.nullifier[..32]);
    println!("├─ Public Inputs ───────────────────────────────────────────────");
    for inp in &proof.public_inputs {
        println!("│  {inp}");
    }
    println!("└──────────────────────────────────────────────────────────────");
}
