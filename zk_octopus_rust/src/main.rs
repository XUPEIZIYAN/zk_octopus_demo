/// ZK-Octopus CLI — Privacy-Preserving Urban Credential Prototype
///
/// Demonstrates the full pipeline from Octopus card transaction data to
/// EAS-anchored ZK credentials on Ethereum, following the architecture
/// described in the ZK-Octopus Ethereum Foundation fellowship proposal.
///
/// Usage:
///   cargo run -- demo                    # run all four urban coordination scenarios
///   cargo run -- issue                   # issue a POD credential from synthetic data
///   cargo run -- prove --claim mobility  # generate a mobility threshold proof
///   cargo run -- prove --claim payment   # generate a payment compliance proof
///   cargo run -- prove --claim temporal  # generate a temporal regularity proof
///   cargo run -- prove --claim composite # generate a composite residency proof
///   cargo run -- verify --claim mobility # full pipeline: issue → prove → verify → attest

mod types;
mod pod;
mod proof;
mod eas;
mod demo;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use crate::types::*;
use crate::proof::{SemaphoreIdentity, NullifierRegistry};

// ── CLI definition ─────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name        = "zk-octopus",
    version     = "0.1.0",
    about       = "ZK-Octopus: Privacy-Preserving Urban Credential Prototype",
    long_about  = r#"
ZK-Octopus transforms Octopus card transaction data into selective-disclosure,
publicly verifiable ZK credentials on Ethereum — enabling cardholders to prove
urban coordination claims (transit frequency, payment compliance, residency) without
revealing any underlying transactions.

Architecture: TLSNotary → POD Credential → GPC/Groth16 → EAS (Arbitrum One)
Paper: Ethereum Foundation PhD Fellowship 2026 — Coordination Rails for Cities
    "#
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run all four urban coordination demo scenarios end-to-end
    Demo,
    /// Issue a POD credential from synthetic Octopus transaction data
    Issue {
        /// Registration status of the cardholder
        #[arg(long, default_value = "pseudonymous")]
        status: RegistrationArg,
    },
    /// Generate a ZK proof for a specific claim predicate
    Prove {
        /// Type of claim predicate to prove
        #[arg(long, default_value = "mobility")]
        claim: ClaimArg,
    },
    /// Run the full pipeline: issue credential → prove claim → verify → attest
    Verify {
        /// Type of claim predicate to prove and verify
        #[arg(long, default_value = "mobility")]
        claim: ClaimArg,
    },
}

#[derive(Clone, ValueEnum)]
enum RegistrationArg { Pseudonymous, Registered }

#[derive(Clone, ValueEnum)]
enum ClaimArg { Mobility, Payment, Temporal, Composite }

// ── Helpers ────────────────────────────────────────────────────────────────

fn make_predicate(claim: &ClaimArg) -> ClaimPredicate {
    match claim {
        ClaimArg::Mobility => ClaimPredicate::MobilityThreshold {
            zone:       Zone::Kowloon,
            period:     "2026-03".to_string(),
            min_trips:  15,
        },
        ClaimArg::Payment => ClaimPredicate::AggregatePayment {
            category:  TransactionCategory::BuildingAccess,
            period:    "2026-03".to_string(),
            min_cents: 20000, // HKD 200
            max_cents: None,
        },
        ClaimArg::Temporal => ClaimPredicate::TemporalRegularity {
            pattern:         "WEEKDAY_MORNING_COMMUTE".to_string(),
            period:          "2026-03".to_string(),
            min_occurrences: 10,
        },
        ClaimArg::Composite => ClaimPredicate::CompositeResidency {
            district:      "KOWLOON_CITY".to_string(),
            period:        "2026-03".to_string(),
            min_trips:     10,
            min_fee_cents: 20000, // HKD 200
        },
    }
}

fn print_separator(label: &str) {
    let line = "═".repeat(60);
    println!("\n╔{line}╗");
    println!("║  {label:<58}║");
    println!("╚{line}╝");
}

// ── Subcommand handlers ────────────────────────────────────────────────────

fn cmd_issue(status: &RegistrationArg) -> Result<PodCredential> {
    print_separator("STEP 1 — Issuing POD Credential from Octopus Data");

    let txns = demo::synthetic_transactions_march_2026();
    demo::print_transaction_summary(&txns);

    let registration = match status {
        RegistrationArg::Pseudonymous => RegistrationStatus::Pseudonymous,
        RegistrationArg::Registered   => RegistrationStatus::IdentityRegistered {
            hkid_hash: "sha256(A123456(7))".to_string(),
        },
    };

    let notary_session = "sess_20260328_zk_octopus_demo_a1b2c3d4";
    println!("\n  [TLSNotary] Notarizing Octopus portal API session: {notary_session}");
    println!("  [TLSNotary] MPC-TLS handshake complete. Signed fields extracted.");
    println!("  [POD]       Building Poseidon Merkle tree (mock: SHA-256)…");

    let pod = pod::build_pod(&txns, &Zone::Kowloon, "2026-03", registration, notary_session)?;
    pod::display_pod(&pod);

    println!("\n  Integrity check: {}", if pod::verify_pod_integrity(&pod) {
        "PASS — Merkle root consistent with entries"
    } else {
        "FAIL — Merkle root mismatch"
    });
    Ok(pod)
}

fn cmd_prove(claim: &ClaimArg, pod: &PodCredential) -> Result<proof::MockProof> {
    print_separator("STEP 2 — Generating ZK Proof (Groth16 / GPC, on-device)");

    let predicate = make_predicate(claim);
    println!("\n  Predicate type:  {}", predicate.name());
    println!("  EAS schema:      {}", predicate.eas_schema());

    // Semaphore identity (secret key never leaves the device)
    let identity = SemaphoreIdentity::new("CARDHOLDER_SECRET_KEY_NEVER_TRANSMITTED");
    println!("\n  [Semaphore V4]  Identity pubkey: 0x{}…", &identity.pubkey_hex[..20]);

    let scope = "transport_dept_fare_subsidy_2026Q1";
    println!("  [Semaphore V4]  Nullifier scope:  {scope}");

    println!("\n  [Mopro/Groth16] Generating proof… (ARM native, mock timer)");
    let prf = proof::generate_proof(pod, &predicate, &identity, scope)?;
    proof::display_proof(&prf);

    println!(
        "\n  Privacy guarantee: verifier will receive ONLY the public output\n  ({}) and NOTHING from the {} underlying transactions.",
        prf.public_output,
        demo::synthetic_transactions_march_2026().len()
    );
    Ok(prf)
}

fn cmd_verify_and_attest(
    claim:    &ClaimArg,
    pod:      &PodCredential,
    prf:      &proof::MockProof,
    registry: &mut NullifierRegistry,
) -> Result<EasAttestation> {
    print_separator("STEP 3 — On-chain Verification & EAS Attestation (Arbitrum One)");

    let predicate = make_predicate(claim);
    println!("\n  [ZKOctopusResolver] Submitting proof to Arbitrum One…");

    let attest = eas::issue_attestation(prf, pod, &predicate, registry)?;
    eas::display_attestation(&attest);

    let valid = eas::verify_attestation(&attest, &predicate);
    println!("\n  Verifier check: {}", if valid {
        "PASS — attestation schema matches claim predicate"
    } else {
        "FAIL — schema mismatch"
    });
    Ok(attest)
}

fn cmd_demo() -> Result<()> {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║          ZK-Octopus — End-to-End Demo                       ║");
    println!("║  Privacy-Preserving Urban Credentials on Ethereum           ║");
    println!("║  Ethereum Foundation PhD Fellowship 2026                    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    let mut registry = NullifierRegistry::default();
    let txns = demo::synthetic_transactions_march_2026();
    let registration = RegistrationStatus::Pseudonymous;
    let pod = pod::build_pod(
        &txns, &Zone::Kowloon, "2026-03", registration,
        "sess_20260328_demo"
    )?;

    // ── Scenario 1: Transport Subsidy ──────────────────────────────────────
    print_separator("SCENARIO 1 — Public Transport Fare Subsidy (Transport Dept)");
    println!("  Claim: 'I made ≥ 15 transit trips in Kowloon in March 2026'");
    println!("  Purpose: Verify eligibility for PTFSS public transport subsidy");

    let id1 = SemaphoreIdentity::new("CARDHOLDER_SECRET_1");
    let pred1 = ClaimPredicate::MobilityThreshold {
        zone: Zone::Kowloon, period: "2026-03".into(), min_trips: 15
    };
    let prf1 = proof::generate_proof(&pod, &pred1, &id1, "transport_dept_ptfss_2026Q1")?;
    println!("  Result: {} in {}ms", prf1.public_output, prf1.proving_time_ms);
    let att1 = eas::issue_attestation(&prf1, &pod, &pred1, &mut registry)?;
    println!("  EAS UID: 0x{}…\n", &att1.uid[..20]);

    // ── Scenario 2: Housing Eligibility ───────────────────────────────────
    print_separator("SCENARIO 2 — Public Housing Eligibility (Housing Authority)");
    println!("  Claim: 'I am a regular resident of Kowloon (transit + mgmt fees)'");
    println!("  Purpose: Establish residency evidence for PRH application");

    let id2 = SemaphoreIdentity::new("CARDHOLDER_SECRET_2");
    let pred2 = ClaimPredicate::CompositeResidency {
        district: "KOWLOON_CITY".into(), period: "2026-03".into(),
        min_trips: 10, min_fee_cents: 20000,
    };
    let prf2 = proof::generate_proof(&pod, &pred2, &id2, "housing_auth_prh_2026")?;
    println!("  Result: {} in {}ms", prf2.public_output, prf2.proving_time_ms);
    let att2 = eas::issue_attestation(&prf2, &pod, &pred2, &mut registry)?;
    println!("  EAS UID: 0x{}…\n", &att2.uid[..20]);

    // ── Scenario 3: Management Fee Compliance ─────────────────────────────
    print_separator("SCENARIO 3 — Management Fee Compliance (Property Manager)");
    println!("  Claim: 'My Octopus management fee payment this month ≥ HKD 200'");
    println!("  Purpose: Fee payment verification without exposing all transactions");

    let id3 = SemaphoreIdentity::new("CARDHOLDER_SECRET_3");
    let pred3 = ClaimPredicate::AggregatePayment {
        category: TransactionCategory::BuildingAccess,
        period: "2026-03".into(), min_cents: 20000, max_cents: None,
    };
    let prf3 = proof::generate_proof(&pod, &pred3, &id3, "property_mgr_compliance_2026")?;
    println!("  Result: {} in {}ms", prf3.public_output, prf3.proving_time_ms);
    let att3 = eas::issue_attestation(&prf3, &pod, &pred3, &mut registry)?;
    println!("  EAS UID: 0x{}…\n", &att3.uid[..20]);

    // ── Scenario 4: Temporal Regularity (Planning Input) ──────────────────
    print_separator("SCENARIO 4 — Regular Commuter Signal (Planning Dept)");
    println!("  Claim: 'I have ≥ 10 morning commute taps in March 2026'");
    println!("  Purpose: Contribute to station demand estimation anonymously");

    let id4 = SemaphoreIdentity::new("CARDHOLDER_SECRET_4");
    let pred4 = ClaimPredicate::TemporalRegularity {
        pattern: "WEEKDAY_MORNING_COMMUTE".into(),
        period: "2026-03".into(), min_occurrences: 10,
    };
    let prf4 = proof::generate_proof(&pod, &pred4, &id4, "planning_dept_demand_2026")?;
    println!("  Result: {} in {}ms", prf4.public_output, prf4.proving_time_ms);
    let att4 = eas::issue_attestation(&prf4, &pod, &pred4, &mut registry)?;
    println!("  EAS UID: 0x{}…\n", &att4.uid[..20]);

    // ── Summary ───────────────────────────────────────────────────────────
    print_separator("DEMO COMPLETE — Summary");
    println!();
    println!("  Four urban coordination claims proved and attested on Ethereum.");
    println!("  In all cases:");
    println!("    - {} raw transactions stayed on the cardholder's device",
        demo::synthetic_transactions_march_2026().len());
    println!("    - Each verifier received only a boolean or range output");
    println!("    - No cardholder identity was disclosed to any verifier");
    println!("    - Cross-verifier linkability prevented by distinct nullifiers");
    println!();
    println!("  Attestation UIDs (Arbitrum One, queryable by any EAS verifier):");
    println!("    Transport Dept:   0x{}…", &att1.uid[..24]);
    println!("    Housing Auth:     0x{}…", &att2.uid[..24]);
    println!("    Property Mgr:     0x{}…", &att3.uid[..24]);
    println!("    Planning Dept:    0x{}…", &att4.uid[..24]);
    println!();
    println!("  Gas used per attestation: ~200,000 (≈ USD 0.02–0.04 on Arbitrum)");
    println!();
    println!("  This is a mock prototype. Real implementation:");
    println!("    TLSNotary + Zupass POD + Circom/Groth16 (GPC) + Mopro iOS/Android");
    println!("    + Semaphore V4 + ZKOctopusResolver + EAS on Arbitrum One");
    println!();

    Ok(())
}

// ── Main ───────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Demo => {
            cmd_demo()?;
        }
        Command::Issue { status } => {
            cmd_issue(status)?;
        }
        Command::Prove { claim } => {
            let pod = cmd_issue(&RegistrationArg::Pseudonymous)?;
            cmd_prove(claim, &pod)?;
        }
        Command::Verify { claim } => {
            let mut registry = NullifierRegistry::default();
            let pod = cmd_issue(&RegistrationArg::Pseudonymous)?;
            let prf = cmd_prove(claim, &pod)?;
            cmd_verify_and_attest(claim, &pod, &prf, &mut registry)?;
        }
    }

    Ok(())
}
