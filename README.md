# LogAccord

LogAccord audits the append-only history of Google's Argon2026h2 Certificate
Transparency log. It retains authenticated checkpoints, proofs of historical
prefixes and inclusion records for individual CT entries on GenLayer.
Any account can submit the next verification call.

The contract pins the log's P-256 public key. Deployment fixes a public GitHub
commit URL containing an archived Argon signed tree head. On `seed()`, the
leader and validators fetch the archive and verify the signature over the
timestamp, tree size and root. A deployment can use the complete signed tree
or start at a smaller prefix. In the latter case, the contract reconstructs
that prefix's root from a public leaf and path, then verifies a consistency
proof from the prefix to the signed tree. The prefix record preserves the
attesting signature and proof.

`sync(expected_size)` fetches a live signed tree head and proves that the
previous checkpoint is its prefix. Validators verify the proposed signature,
fetch the consistency proof independently and check the link against their
own live signed head. If their head has a different size, they verify the
consistency proof in the appropriate direction. At equal sizes the roots must
match. This handles a moving log without weakening the append-only condition.
The expected size prevents a stale caller from advancing from a different
checkpoint.

`record_leaf(index, size)` fetches the full CT leaf and verifies its inclusion
at the current checkpoint. The stored record contains its hash, timestamp,
entry type and Merkle path. `record_prefix(prefix_size, size)` authenticates a
historical root against that checkpoint. Both methods use exact agreement on
the independently verified result. The public getters expose these records
and each checkpoint's proof.

The contract checks the signed history for one log. Its progress depends on
the log serving the required proofs. An inclusion record establishes that the
log committed to a leaf and makes no statement about certificate validity or
domain control. Cross-log monitoring and public split-view gossip are outside
this contract's scope.

Sources: [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962) ·
[Chromium CT log keys](https://chromium.googlesource.com/chromium/src/+/HEAD/components/certificate_transparency/data/log_list.json) ·
[GenLayer Equivalence Principle](https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle)

```sh
pip install -r requirements-dev.txt
genvm-lint download --version v0.2.16
genvm-lint check contracts/log_accord.py
python -m pytest tests/direct -q
node --test tests/rpc-preflight.test.cjs
```

The StudioNet proof workflow uses a real Argon tree head and a fixture that
changes its root while retaining the original signature. It independently
checks the resulting state, signatures and RFC consistency paths. Generic
CLI transport and test signing helpers are reused under MIT from
[ArchiveLift](https://github.com/gabrieladash123-bit/archive-lift).

The valid run advanced from a three-leaf prefix to a signed checkpoint of
3,501,950,757 leaves. Both runs verified 11 finalized receipts.
[StudioNet receipts and addresses](proofs/README.md) · [Submission text](SUBMISSION.md)
