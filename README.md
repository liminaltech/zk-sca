# ZK-SCA

> WARNING: This software is in early development and not recommended for production use. See “Security” below.

Vulnerable third-party dependencies pose a risk to application security. One mitigation is for a producer to give the consumer a [software bill of materials](https://www.ntia.gov/page/software-bill-materials) (SBOM). As an alternative to SBOMs, this library enables the producer to generate a cryptographic proof that undisclosed source code meets explicit software composition policies.

More precisely, zero-knowledge software composition analysis (ZK-SCA) enables the producer to generate a [zero-knowledge proof](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof) that a source archive with a given Merkle root only depends on external packages in an explicit allowlist, with a version greater than or equal to the minimum version known to the producer to be safe. Optionally, the producer may also specify a list of allowed licenses. A consumer may retrieve this proof and verify it to gain assurance regarding application security.

## Getting Started

To generate a receipt using test inputs, clone the repo and run the following commands. Please note that proof generation will consume a lot of time and compute on most personal computers.

```bash
cd crates/cli
cargo run -- \                                  
  prove \
  -a ../../fixtures/safe.tar.gz \
  -m Cargo \
  -v 1.81.0 \
  -p ../../fixtures/permitted-dependencies.json
```

To verify the resultant proof, run:

```bash
cargo run -- verify -r safe.zk-sca.bin -j
```

## Security

This code is in early development. It might contain bugs that impact the validity of receipts, leak source code, or cause other problems. To report a security issue, please see the instructions in [SECURITY.md](./SECURITY.md). Caveat emptor.

For consumers, a key risk is that bugs could let a malicious producer mint a receipt that indicates policy compliance for non-compliant code, giving consumers repudiable false assurances. Tests for counter-measures to this threat are located in `crates/prover/tests/security.rs`; run them via:

```bash
cargo test -p zk-sca-prover --test security
```

For producers: Each receipt discloses the SHA-256 Merkle root of your source bundle, the package manager that resolved dependencies, an allowlist of permitted dependencies with minimum versions, and—optionally—an allowlist of license requirements. Weaknesses in SHA-256, the zkVM protocol, or their implementations could reveal source code. The more inclusive these allowlists are, the less the receipt indicates about your actual dependencies and licenses.

This library uses the [RISC Zero zkVM](https://github.com/risc0/risc0) to generate receipts. Please see their source code and [security documentation](https://github.com/risc0/risc0?tab=readme-ov-file#security) for more detail.

## Contributing

We are not accepting outside pull requests at this time.

## License

Licensed under Apache-2.0. See [LICENSE](./LICENSE).
