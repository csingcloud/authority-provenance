# Reference verifier: ap-verify

`ap_verify.py` implements the verification procedure of `SPEC.md` §7
for record format `cerydora-proof-bundle`, version 1 (a historical
identifier; see `SPEC.md` §2). It is one file. It
uses the Python standard library and one dependency, `cryptography`, for
Ed25519 only. It opens no network connection.

## Run

```
pip install cryptography
python ap_verify.py RECORD.json
python ap_verify.py RECORD.json --key ISSUER_KEY   # key obtained out of band
python ap_verify.py RECORD.json --json             # machine-readable result
```

`--key` takes a 64-hex-character Ed25519 public key, or a path to a file that
contains one. Obtain it through a channel other than the record: a contract,
a record you retained earlier, or a published key record.

Or install it as a command:

```
pip install .
ap-verify RECORD.json
```

## Results

Four results, reported separately, and exit codes as in `SPEC.md` §7.3:

- `0`: CONFORMANCE PASS, INTEGRITY PASS, SIGNATURE VALID, and ISSUER TRUST
  not MISMATCH.
- `1`: any other completed verification.
- `2`: unreadable or structurally nonconforming input.

Text output escapes control, DEL, C1 and bidirectional characters in
record-carried strings, so a record cannot rewrite a terminal or forge a
result line. `--json` output is ASCII-only.

## Other implementations

Any implementation that follows `SPEC.md` §7 and produces the results in
`../examples/README.md` conforms. The reference verifier is not normative
where it and `SPEC.md` differ; report the difference as an issue.

## Name

The command is `ap-verify`. The usage line, `--help` and the text-report
heading print the name the verifier was invoked under: `ap-verify` when
installed, `ap_verify` when run as `python ap_verify.py` or
`python -m ap_verify`.
