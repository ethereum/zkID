# Revocation

This work explores the design and evaluation of revocation strategies for verifiable credentials, with a focus on analyzing the trade-offs between different cryptographic approaches.

Revocation is critical for maintaining trust, without it, verifiers cannot know whether a credential is still valid, which undermines the entire system. At the same time, existing revocation mechanisms often compromise user privacy.

The goal of this work is to provide a framework that allows verifiers to reliably detect whether a credential has been revoked, while minimizing disclosure of personal data.

## Resources

- Revocation in zkID: Merkle Tree-based Approaches: https://pse.dev/blog/revocation-in-zkid-merkle-tree-based-approaches

- DIF Revocation Report: https://github.com/decentralized-identity/labs-privacy-preserving-revocation-mechanisms/blob/main/docs/report.md

- LeanIMT+: Efficient Merkle Tree for Membership and Non-Membership Proofs: https://pse.dev/blog/lean-imt-plus-efficient-merkle-tree-for-membership-and-non-membership-proofs

- Privacy-Preserving Revocation for Verifiable Credentials Using Zero-Knowledge Non-Membership Proofs: https://pse.dev/blog/privacy-preserving-revocation-for-verifiable-credentials-using-zero-knowledge-non-membership-proofs