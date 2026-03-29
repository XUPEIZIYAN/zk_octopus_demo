# ZK-Octopus: Privacy-Preserving Urban Credential Prototype

**ZK-Octopus** is a Rust CLI prototype demonstrating a privacy-preserving urban credential system on Ethereum. It implements the architecture described in the **Ethereum Foundation PhD Fellowship 2026 — Coordination Rails for Cities** proposal.

This library transforms Octopus card (Hong Kong's smart card payment system) transaction data into selective-disclosure, publicly verifiable Zero-Knowledge (ZK) credentials on Ethereum. It enables cardholders to prove urban coordination claims—such as transit frequency, payment compliance, and residency—without revealing any of their underlying plaintext payment transactions.

## Architecture Pipeline

The system simulates the following end-to-end pipeline:

1. **TLSNotary & Data Extraction:** Secures API sessions from the Octopus portal to extract transaction data in a verifiable manner.
2. **POD Credential Issuance:** Constructs a Poseidon Merkle tree over the transactions to issue a Provable Object Data (POD) credential.
3. **ZK Proof Generation (Groth16 / GPC):** Generates an on-device ZK proof evaluating specific claim predicates (e.g., "completed 15 trips in Kowloon") while keeping the raw data completely hidden. Integrates **Semaphore V4** for anonymous nullifier identity management.
4. **EAS Attestation (Arbitrum One):** On-chain verification of the ZK proof on an Ethereum L2 (Arbitrum One), dropping an Ethereum Attestation Service (EAS) attestation for downstream smart contracts to consume.

## Getting Started

### Prerequisites

- Rust (edition 2021) and Cargo installed.

### Build the Project

```bash
cd zk_octopus_rust
cargo build --release
```

### CLI Usage

The CLI provides a set of subcommands to simulate different stages of the credential lifecycle.

**1. Run the Full End-to-End Demo**
Runs all four urban coordination scenarios defined in the paper:
```bash
cargo run -- demo
```

**2. Issue a Credential**
Issues a POD credential from a synthetically generated Octopus transaction dataset (March 2026).
```bash
cargo run -- issue --status pseudonymous  # Or --status registered
```

**3. Generate a ZK Proof**
Proves a specific claim predicate based on the generated credential:
```bash
# Proves the user has taken a minimum number of trips in a specific zone
cargo run -- prove --claim mobility

# Proves the user has spent a minimum amount on a specific category (e.g. Building Access)
cargo run -- prove --claim payment

# Proves a specific temporal pattern (e.g., weekday morning commutes)
cargo run -- prove --claim temporal

# Proves a composite residency claim (both trips and fee thresholds)
cargo run -- prove --claim composite
```

**4. Verify and Attest**
Runs the full pipeline (Issue → Prove → On-chain Verify → EAS Attest) for a given claim:
```bash
cargo run -- verify --claim mobility
cargo run -- verify --claim composite
```

## Urban Coordination Scenarios

The prototype features synthetic Octopus datasets tailored to demonstrate four real-world urban scenarios:
1. **Mobility (Transport Fare Subsidy):** Transport Department verifies transit trips ≥ N in a specific zone.
2. **Payment (Management Fee Compliance):** Property managers privately verify fee payments via aggregate payment range bucket proofs.
3. **Temporal (Regular Commuter Signal):** Planning Department collects anonymous proofs of temporal regularity (e.g., Weekday Morning Commute) for infrastructure planning.
4. **Composite (Public Housing Eligibility):** Housing Authority verifies composite residency credentials without needing access to itemized transit or retail data.

## Project Structure

- `src/main.rs`: The main CLI entry point providing the `clap` subcommands.
- `src/types.rs`: Core domain models (`OctopusTransaction`, `PodCredential`, `ClaimPredicate`, `MockProof`, `EasAttestation`, etc.).
- `src/pod.rs`: Logic for constructing the POD credential and the Merkle tree.
- `src/proof.rs`: Mock Groth16 prover environment simulating GPC predicate evaluation and Semaphore nullifier registries.
- `src/eas.rs`: EAS attestation issuance simulating a ZK resolver smart contract.
- `src/demo.rs`: Synthetic transaction generator simulating an active Kowloon resident's monthly activities for demo orchestration.

## Prototype Disclaimer: Mocked vs. Real Components

This repository is a *prototype*. Certain cryptographic operations are mocked for demonstration and ease of compilation:

| Component | This Prototype | Real Production System |
|---|---|---|
| **Hash function** | SHA-256 | Poseidon (Circuit-friendly) |
| **Merkle tree** | SHA-256 leaf hashes | Poseidon Merkle tree |
| **EdDSA signature** | SHA-256 MAC | Baby JubJub EdDSA |
| **Groth16 proof** | Deterministic SHA-256 byte payload | Circom + rapidsnark via Mopro |
| **TLSNotary** | Mocked session ID | Real MPC-TLS with notary co-signer |
| **EAS attestation** | Native in-memory struct evaluation | On-chain verification (Arbitrum One, ~200k L2 gas) |
| **Nullifier** | SHA-256(secret, scope) | Poseidon(secret, scope) inside ZK circuit |

## License
MIT
