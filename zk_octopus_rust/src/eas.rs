/// Ethereum Attestation Service (EAS) mock layer
///
/// Simulates the ZKOctopusResolver contract on Arbitrum One:
///   1. Receives the Groth16 proof and public inputs from the prover
///   2. Verifies the proof via BN254 precompiles (mocked)
///   3. Checks and registers the nullifier
///   4. Issues an EAS attestation with the public claim data
///
/// Real deployment: Arbitrum One, ~200,000 gas per attest() call,
/// ≈ USD 0.02–0.04 at post-EIP-4844 gas prices.

use anyhow::Result;
use sha2::{Sha256, Digest};
use hex;
use chrono::Utc;

use crate::types::*;
use crate::proof::{MockProof, NullifierRegistry, verify_proof};

/// The ZKOctopusResolver contract address (mock, Arbitrum One)
pub const RESOLVER_ADDRESS: &str = "0x4e7d9f3a2c8b1d6e0f5a4b7c9d2e8f1a3b6c9d2e";

/// Issue an EAS attestation after verifying the ZK proof.
///
/// This simulates the full on-chain flow:
///   ZKOctopusResolver.attest() → proof verification → nullifier check → EAS.attest()
pub fn issue_attestation(
    proof:    &MockProof,
    pod:      &PodCredential,
    predicate: &ClaimPredicate,
    registry: &mut NullifierRegistry,
) -> Result<EasAttestation> {
    // ── 1. On-chain proof verification (mock BN254 pairing check) ─────────
    println!("  [Resolver] Verifying Groth16 proof via BN254 precompiles…");
    let valid = verify_proof(proof, pod, registry)?;
    if !valid {
        anyhow::bail!("Proof verification failed");
    }
    println!("  [Resolver] Proof valid. Nullifier registered.");

    // ── 2. Produce attestation UID ─────────────────────────────────────────
    let uid = {
        let mut h = Sha256::new();
        h.update(proof.nullifier.as_bytes());
        h.update(proof.predicate_name.as_bytes());
        h.update(Utc::now().to_rfc3339().as_bytes());
        hex::encode(h.finalize())
    };

    // ── 3. Serialise the public claim data (what verifiers can read) ───────
    let claim_data = serde_json::json!({
        "predicate": proof.predicate_name,
        "public_output": proof.public_output,
        "public_inputs": proof.public_inputs,
        "schema": predicate.eas_schema(),
        "resolver": RESOLVER_ADDRESS,
        "groth16_verified": true,
        "nullifier_registered": true,
    });

    // ── 4. Simulate gas usage (~200k gas for Groth16 verify + EAS write) ──
    let gas_used = 198_412u64 + (proof.proof_bytes.len() as u64 * 16);

    // Simulate a mock Arbitrum block number
    let block_number = 285_400_000u64 + (Utc::now().timestamp() as u64 % 100_000);

    Ok(EasAttestation {
        uid,
        schema:         predicate.eas_schema().to_string(),
        attester:       RESOLVER_ADDRESS.to_string(),
        recipient:      format!("nullifier:0x{}", &proof.nullifier[..16]),
        data:           serde_json::to_string_pretty(&claim_data)?,
        block_number,
        gas_used,
        timestamp:      Utc::now(),
    })
}

/// A verifier checks an EAS attestation (Transport Dept, Housing Authority, etc.)
/// They receive ONLY the public claim data — no raw transaction records.
pub fn verify_attestation(attest: &EasAttestation, predicate: &ClaimPredicate) -> bool {
    // In the real system, the verifier queries the EAS contract on-chain
    // and the ZKOctopusResolver confirms the attestation is valid.
    // Here we check schema consistency as a mock.
    attest.schema == predicate.eas_schema()
}

pub fn display_attestation(attest: &EasAttestation) {
    println!("\n┌─ EAS Attestation (Arbitrum One) ─────────────────────────────");
    println!("│ UID:          0x{}…", &attest.uid[..24]);
    println!("│ Schema:       {}", attest.schema);
    println!("│ Attester:     {}", attest.attester);
    println!("│ Recipient:    {}…", &attest.recipient[..32]);
    println!("│ Block:        {}", attest.block_number);
    println!("│ Gas used:     {} (~${:.4} USD at Arbitrum prices)",
        attest.gas_used,
        attest.gas_used as f64 * 0.1e-9 * 3000.0 // rough estimate
    );
    println!("│ Timestamp:    {}", attest.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("├─ Public Claim Data (all that verifiers receive) ──────────────");
    for line in attest.data.lines() {
        println!("│  {line}");
    }
    println!("└──────────────────────────────────────────────────────────────");
}
