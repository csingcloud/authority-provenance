# Examples

Every example is **synthetic**, with no real people, systems or data. The
records are built from a fictional organization (the State of Trescott
Department of Transportation); the test vector uses placeholder values and
the published RFC 8032 test key. Both valid records carry `"synthetic": true`
inside their seals.

| File | What it is | CONFORMANCE | INTEGRITY | SIGNATURE | ISSUER TRUST | Failure | Exit |
|---|---|---|---|---|---|---|---|
| `trescott-agents-2026-10-07.bundle.json` | A signed record for one Authorization and one cycle, from a corpus dated 2026-10-07 | PASS | PASS | VALID | NOT_ESTABLISHED | none | 0 |
| same, with `--key` set to the issuer key below | The same record, with the issuer key supplied out of band | PASS | PASS | VALID | TRUSTED | none | 0 |
| same, with `--key` set to any other valid key | The same record, with a key that does not match | PASS | PASS | VALID | MISMATCH | `ISSUER_TRUST_MISMATCH` | 1 |
| `negative/corrupted-tampered-payload.json` | The valid record with `payload.synthetic` changed from `true` to `false`; seal and signature untouched | PASS | FAIL | VALID | NOT_ESTABLISHED | `DIGEST_MISMATCH` | 1 |
| `negative/corrupted-malformed-envelope.json` | The valid record with the top-level `seal` member removed | FAIL | NOT_ESTABLISHED | NOT_ESTABLISHED | NOT_ESTABLISHED | `MALFORMED_ENVELOPE` | 2 |
| `vectors/minimal-signed-envelope.json` | The `FORMAT.md` §2.2 test vector: a minimal record signed with the RFC 8032 TEST 1 key | PASS | PASS | VALID | NOT_ESTABLISHED | none | 0 |

The valid example is a record from a synthetic corpus dated 2026-10-07. For
publication, three strings in its `disclosure` object were reworded and the
record was re-sealed and re-signed under the same synthetic issuer key.

The tampered example validates against `schema/bundle.schema.json`. A schema
cannot detect a relabelled record; the seal does.

**Issuer key of the valid example** (raw Ed25519, hex):

```
8b237d788e8eaaef550c6d125823fa45f1fd5fc29b2c88bdf871119471fc1312
```

**SHA-256 of `trescott-agents-2026-10-07.bundle.json`:**

```
2b8724e3fd355538262deae65ad5bad25cf08d1ca0251e6e4b29ff07965d47a0
```

The valid example carries 4 evaluated, 12 not-evaluated and 3 withheld roster
conditions, and 4 conformant determinations. A verifier reports the
approver's immutable identity key, lifecycle, actor continuity, drift states
and revalidation as not included: this record does not carry them.
