# ZK-Octopus Rust Prototype

Privacy-Preserving Urban Credential System on Ethereum — Rust CLI prototype implementing the architecture from the Ethereum Foundation PhD Fellowship proposal.

## Quick Start

```bash
# Build
cargo build --release

# Run the full end-to-end demo (4 urban coordination scenarios)
cargo run -- demo

# Issue a POD credential from synthetic Octopus data
cargo run -- issue

# Generate a specific ZK proof
cargo run -- prove --claim mobility
cargo run -- prove --claim payment
cargo run -- prove --claim temporal
cargo run -- prove --claim composite

# Full pipeline: issue → prove → on-chain verify → EAS attest
cargo run -- verify --claim mobility
cargo run -- verify --claim composite
```

## Project Structure

```
src/
  main.rs     — CLI entry point (clap subcommands)
  types.rs    — Core data structures (OctopusTransaction, PodCredential,
                ClaimPredicate, MockProof, EasAttestation, …)
  pod.rs      — POD credential construction (Poseidon Merkle tree, mocked with SHA-256)
  proof.rs    — Mock Groth16 prover (GPC predicate evaluation + Semaphore nullifiers)
  eas.rs      — EAS attestation issuance via ZKOctopusResolver mock
  demo.rs     — Synthetic Octopus dataset + scenario orchestration
```

## What is Mocked vs. Real

| Component | This Prototype | Real ZK-Octopus |
|---|---|---|
| Hash function | SHA-256 | Poseidon (ZK-circuit-friendly) |
| Merkle tree | SHA-256 leaf hashes | Poseidon Merkle tree |
| EdDSA signature | SHA-256 MAC | Baby JubJub EdDSA |
| Groth16 proof | Deterministic SHA-256 bytes | Circom + rapidsnark via Mopro |
| TLSNotary | Mock session ID | Real MPC-TLS with notary co-signer |
| EAS attestation | In-memory struct | On-chain (Arbitrum One, ~200k gas) |
| Nullifier | SHA-256(secret, scope) | Poseidon(secret, scope) in-circuit |

## Dependencies

- `clap` — CLI argument parsing
- `serde` / `serde_json` — serialization of credentials and attestations
- `sha2` — SHA-256 (stand-in for Poseidon hash)
- `hex` — hex encoding of proof bytes, hashes
- `chrono` — timestamps for transactions and attestations
- `anyhow` — ergonomic error handling

## Urban Coordination Scenarios

The `demo` subcommand runs four scenarios from the fellowship proposal:

1. **Transport Fare Subsidy** (Transport Department) — proves transit trips ≥ N in zone Z
2. **Public Housing Eligibility** (Housing Authority) — composite residency credential
3. **Management Fee Compliance** (Property Manager) — aggregate payment proof (range bucket)
4. **Regular Commuter Signal** (Planning Department) — temporal regularity proof

In all cases, the underlying transaction records never leave the cardholder's device.
