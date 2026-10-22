# Authority Provenance

Authority Provenance is the recorded answer to who granted a non-human actor
its authority, under what declared terms, and whether that authority was
still in force when the actor acted. An Authority Provenance record binds the
grant to the grantor's identity as verified by the organization's identity
provider, states how each declared condition was judged at a sealed cutoff,
and is sealed so that a third party can check, from the record alone, that it
has not changed and which key sealed it.

Enforcement points and identity systems enforce or infer authority. An
Authority Provenance record states who granted it, whether it was still in
force when the actor acted, and how each declared condition was judged.

## Contents

| Path | What it is | License |
|---|---|---|
| [`SPEC.md`](SPEC.md) | The specification, version 0.1: what a record asserts, the record format, and the verification procedure | CC BY 4.0 |
| [`FORMAT.md`](FORMAT.md) | Field tables for every payload member, and test vectors for serialization, seal and signature | CC BY 4.0 |
| [`schema/bundle.schema.json`](schema/bundle.schema.json) | JSON Schema for the record's structure | Apache-2.0 |
| [`verifier/`](verifier/) | Reference verifier, `ap-verify`: one Python file, offline, one dependency | Apache-2.0 |
| [`examples/`](examples/) | One synthetic record, two deliberately broken ones, and the `FORMAT.md` test-vector envelope, with expected results | Apache-2.0 |

## Verify the example

```
cd verifier
pip install cryptography
python ap_verify.py ../examples/trescott-agents-2026-10-07.bundle.json
```

The verifier needs no network, no account and no other software. It reports
four results separately: conformance, integrity, signature and issuer trust.
See [`examples/README.md`](examples/README.md) for what each example must
produce.

## Status

Version 0.1 is a draft. Comments are welcome as issues. The companion control
text for assessors is *Authority Provenance: Standing of Delegated Authority
Behind Non-Person Actor Actions*, v0.3, doi:10.5281/zenodo.23105657.

## License

- Specification text (`SPEC.md`, `FORMAT.md`, this README): Creative Commons Attribution
  4.0 International, in [`LICENSE-SPEC`](LICENSE-SPEC).
- Schema, verifier and examples: Apache License 2.0, in [`LICENSE`](LICENSE).

## Contributing

Contributions are accepted under the Developer Certificate of Origin 1.1
([`DCO`](DCO)). Sign off each commit (`git commit -s`), which adds a line of
the form:

```
Signed-off-by: Your Name <you@example.org>
```

By signing off you certify the statements in `DCO` for that contribution. A
contribution to `SPEC.md` is licensed under CC BY 4.0. A contribution to any
other file is licensed under Apache-2.0.
