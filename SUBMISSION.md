Category: Builder → Intelligent Contracts

Title: LogAccord: Consensus verification of append-only transparency logs

Notes / Description:

LogAccord tracks the append-only history of Google's Argon2026h2 Certificate Transparency log. Leader and validators independently fetch signed tree heads, full leaf inputs and Merkle proofs. The contract verifies P-256 signatures and requires the next tree to preserve the current prefix. Validators can observe different live sizes and must prove consistency with the proposal. The ledger stores authenticated checkpoints, historical prefixes and entry inclusion records. GenVM lint and 15 tests passed. Two StudioNet deployments verified 11 finalized receipts. One advanced from three leaves to a signed 3,501,950,757-leaf checkpoint and recorded a real entry and historical prefix. The other rejected a modified root under the original signature.

Evidence: [Contract source](contracts/log_accord.py) · [StudioNet checkpoint](https://explorer-studio.genlayer.com/address/0x2E2621D15B5399eFe3dCEca4aE3A88Fc69b155f4) · [Onchain proofs](proofs/README.md)
