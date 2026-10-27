# Authority Provenance bundle v0.1.1

**Version:** 0.1.1 (2026-10-25; changes in §12) · **Editor:** Cliff Singletary
(Cerydora LLC) · **License:** CC BY 4.0 for this text (`LICENSE-SPEC`);
Apache-2.0 for the schema and the reference verifier (`LICENSE`).
**Companion:** *Authority Provenance: Standing of Delegated Authority Behind
Non-Person Actor Actions*, v0.3, doi:10.5281/zenodo.23105657. The companion
states control language for assessors; this document states what a record
contains and how a third party checks it.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as described in
RFC 2119 and RFC 8174 when, and only when, they appear in capitals.

---

## 1. The category

**Authority Provenance** is the recorded answer to who granted a non-human
actor its authority, under what declared terms, and whether that authority
was still in force when the actor acted. An Authority Provenance record binds
the grant to the grantor's identity as verified by the organization's
identity provider, states how each declared condition was judged at a sealed
cutoff, and is sealed so that a third party can check, from the record alone,
that it has not changed and which key sealed it.

It is provenance of the **grant**, not of the artifact. Supply-chain and model
provenance say what produced an output. Authority Provenance says who
authorized the actor that produced it. Either can be complete while the other
is absent.

Enforcement points, gateways and identity systems enforce or infer authority.
An Authority Provenance record does neither. It records a declared grant and
reports what the organization's own systems showed about it.

## 2. Scope of version 0.1

Version 0.1 specifies one record form, the **proof bundle** (format
`cerydora-proof-bundle`, format version 1, payload schema 1), and one
verification procedure for it. It is written so that an independent party can
build a conforming verifier from this document, the schema in `schema/`, and
the examples in `examples/`. The reference verifier in `verifier/` (`ap-verify`)
is one such implementation. The field tables and test vectors are in
`FORMAT.md`.

The format identifier `cerydora-proof-bundle`, the canonicalization labels
`cerydora-authorization-json-v1` and `cerydora-authorization-snapshot-v1`,
and the title of `schema/bundle.schema.json` are **historical identifiers**.
They name the implementation in which the format was first issued, and carry
no other meaning. The format identifier and the labels are permanent under
§5.6: a bundle that changed them would be a different format.

Version 0.1 does **not** specify how a producer derives what a bundle states:
how evidence is collected, how conditions are judged, or how changes in a
grantor's status are detected. A producer is conforming if it emits bundles
that conform to §5 and mean what §3 and §4 say they mean.

## 3. What a version 0.1 record asserts

A conforming bundle makes these assertions, and only these.

**3.1 Who granted it.** The bundle carries a projection of one declared
**Authorization**: the decision, the authority it cites (role, organization,
basis), the **approver**, the bounded operation, the term, the evidence the
Authorization requires, and the roster of declared conditions. The approver
is carried as a role and an `identity_verified` flag. `identity_verified:
true` asserts that the approver's identity was verified by the organization's
identity provider when the grant was made. The role is recorded as the
Authorization declares it; the bundle does not assert that the role was
verified.

**3.2 Whether it was in force.** The bundle names one **reconciliation cycle**
and its **cutoff** (`as_of`), the Authorization's status and term, and, for
each condition the cycle judged, its **determination** as of that cutoff. A
determination of `expired` says the condition could not be judged at the
cutoff, including because the Authorization was outside its term.

**3.3 What was and was not judged.** Every declared condition appears in the
roster with one review state: `evaluated`, `not_evaluated` or `withheld`.
Coverage gaps, whether the full declared matrix was judged, and the earliest
instant at which cited evidence goes stale are carried as stated limits.

**3.4 What evidence was cited.** A citation-only manifest names each piece of
cited evidence by an opaque stable identifier, with its source, instrument,
observation time, freshness and a reference the organization can resolve. It
never carries the evidence itself.

**3.5 That it has not changed, and who sealed it.** A seal over the canonical
payload, and a signature by the issuer's key over the protected envelope
members.

### 3.6 What a version 0.1 record does not assert

- **That the grantor was authorized by the organization to make the grant.**
  The approver's institutional authority is not carried. A verifier reports
  it as not included.
- **The grantor's account status** at the grant or at the cutoff. The
  immutable identity key of the approver and that key's lifecycle are not
  carried in the examiner projection. A verifier reports them as not
  included.
- **That the actor that acted is the actor that was bound.** Actor continuity
  is not carried.
- **That a control or regulation is satisfied.** Determinations say whether
  cited evidence holds for a named condition at a named cutoff. They are not
  compliance determinations.
- **That the record is complete.** Coverage is a limit of the sources
  consumed, never a property of the estate.
- **When the bundle was sealed.** `generated_at` is asserted by the issuer.

Section 8 names vocabulary reserved for these facts so that a later version
can carry them additively.

## 4. Terms

**Authorization.** A versioned record in which an accountable official
declares what a class of non-human actor may do: purpose, limits, protected
boundary, term, required evidence, and the authority the decision cites. The
canonical Authorization does not travel in a bundle. The bundle carries its
identifier, version and digest, and an examiner-safe projection of it.

**Approver; grantor.** The human whose decision the Authorization records.

**Identity binding.** The association of a governed act with the actor's
identity as verified by the organization's identity provider, recorded at
the act.

**Reconciliation cycle; cutoff.** One comparison of observed evidence against
declared authority, judged as of one instant (the cutoff), whose result is
sealed. Everything a cycle relied on was known at or before its cutoff. A
later cycle never rewrites an earlier one.

**Condition; roster.** A declared condition is one thing the Authorization
requires to hold. The roster lists every declared condition with its review
state, so that silence is visible.

**Determination.** The result of judging one condition in one cycle (§6).

**Not evaluated.** The result for a condition that could not be judged from
what was cited. It is never a pass and never a failure. Each such result
carries its reason.

**Issuer.** The deployment that sealed the bundle, identified by a deployment
identifier and an Ed25519 public key. In version 0.1 the key is
`self-generated`: a valid signature establishes continuity (the same key
holder sealed every bundle sharing that key), not certification of who that
holder is.

**Synthetic.** A sealed flag stating that a bundle was built from fictional
data. Because the signature covers it, a demonstration bundle cannot be
relabelled as production evidence without failing verification.

## 5. Record format

### 5.1 Envelope

A bundle is one UTF-8 JSON document whose top level has **exactly seven**
members:

| Member | Content |
|---|---|
| `format` | `"cerydora-proof-bundle"` |
| `format_version` | `1` |
| `payload` | the sealed payload (§5.2) |
| `issuer` | `deployment_id`; `public_key` (raw Ed25519, 64 lower-case hex); `key_id` (`"sha256:"` + lower-case hex SHA-256 of the key bytes); `identity_class` (`"self-generated"`) |
| `entitlement` | `state` (issuer-asserted; reported, never judged); `schema` (integer, `1`) |
| `seal` | exactly `algorithm` (`"sha256"`) and `digest` (64 lower-case hex) |
| `signature` | exactly `algorithm` (`"ed25519"`), `key_id` (equal to `issuer.key_id`), `signature` (128 lower-case hex) |

A missing or extra top-level member, a `seal` or `signature` block with any
other member, or a `null` signature makes the envelope nonconforming. Every
conforming bundle is signed. The file MAY carry any whitespace; only the
canonical forms in §5.4 are byte-exact.

### 5.2 Payload, schema 1

All 21 members are present. `null` marks absence; omission is
nonconforming.

| Member | Meaning |
|---|---|
| `payload_schema` | `1` |
| `bundle_id` | opaque identifier |
| `view` | `examiner` or `internal` |
| `generated_at` | issuer-asserted generation time |
| `synthetic` | boolean (§4) |
| `authorization_source` | identifier, version and algorithm-qualified digest of the canonical Authorization |
| `authorization_snapshot` | the `examiner-core-v1` projection (§3.1), including `source` (equal to `authorization_source`), the condition roster, and the profile's fixed list of omitted categories |
| `authorization_snapshot_digest` | SHA-256 of the canonical snapshot, with algorithm `sha256` and canonicalization `cerydora-authorization-snapshot-v1` |
| `evidence_manifest` | the `citation-v1` manifest (§3.4) |
| `cycle_id`, `as_of` | the packaged cycle and its cutoff |
| `attestations`, `remediation`, `open_findings` | determinations; each entry joins one roster condition by `declared_state_ref` |
| `working_state_summary` | counts of work in flight |
| `coverage_gaps`, `complete_coverage`, `valid_until` | stated limits (§3.3) |
| `policy`, `ledger`, `disclosure` | the disclosure policy applied; integrity facts about the issuer's internal record (included only as policy permits); the curation declaration |

The structural schema is `schema/bundle.schema.json` (JSON Schema). The
schema checks structure. The seal, not the schema, is the integrity check:
`examples/negative/corrupted-tampered-payload.json` is schema-valid and fails
verification.

### 5.3 Value rules

Timestamps are RFC 3339 UTC with exactly six fractional digits and `Z`.
Dates are `YYYY-MM-DD`. No JSON number is a float: fractional quantities are
decimal strings, and every number is an integer. Enumerations are lower-case
strings.

### 5.4 Canonical serialization

The canonical serialization of a JSON value is:

1. UTF-8, no byte-order mark.
2. Objects: members in ascending order of the UTF-8 bytes of the member name,
   as `name:value` separated by `,`, inside `{` `}`. Duplicate member names
   are prohibited.
3. Arrays: elements in their given order, separated by `,`, inside `[` `]`.
   Element order is significant and never sorted.
4. Strings: exactly these escapes — `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`,
   and `\u00XX` (lower-case hex) for the remaining characters U+0000–U+001F.
   All other characters, including all non-ASCII characters, are literal
   UTF-8.
5. Numbers: base-10 integers, no leading zeros, no sign other than `-`, no
   decimal point, no exponent, no negative zero.
6. Literals: `true`, `false`, `null`.
7. No whitespace outside strings.

This is **not** RFC 8785 (JCS), which orders members by UTF-16 code units and
admits non-integer numbers. A JCS implementation produces different bytes.

### 5.5 Seal and signature

`seal.digest` is the lower-case hex SHA-256 of the canonical serialization of
`payload`. It MUST be exactly 64 lowercase hex characters. A verifier MUST
fail any other spelling with `MALFORMED_ENVELOPE` at §7.2 step 2, before any
digest is computed; the step 8 comparison is then byte-exact.

The signing input is the canonical serialization of the object with exactly
the members `entitlement`, `format`, `format_version`, `issuer` and `seal`,
taken from the envelope. `signature.signature` is the pure Ed25519 signature
(RFC 8032, empty context) over those bytes, by the private key matching
`issuer.public_key`, as exactly 128 lowercase hex characters. Uppercase,
whitespace, a different length or any non-hex character is
`MALFORMED_ENVELOPE` at §7.2 step 2: one sealed bundle has exactly one
byte-exact conforming file, so no verifying variant of it can circulate. The
payload is protected through the seal.

An issuer public key that is a small-order point MUST NOT be used and MUST be
rejected. The prohibited encodings are the eight canonical small-order
encodings and the two parseable non-canonical variants (the libsodium
blocklist); the reference verifier lists them.

### 5.6 Versioning

Once a format version is published or a bundle under it is issued, its
verification contract is permanent. A verifier for version N implements
every published version up to N. New members inside `payload`, `issuer` or
`entitlement`, and new enumeration values, are additive: verifiers tolerate
them, report them verbatim, and include them in the digest. Any change to
canonical serialization, seal or signing input, algorithms, the top-level
member set, or the meaning of an existing envelope member requires a new
`format_version`. Algorithms are fixed per version; there is no negotiation.

`FORMAT.md` §1.12 names three optional payload members that a verifier may
read and report and must not require.

## 6. Determinations and evaluation states

### 6.1 Determination values carried in version 0.1

| Value | Meaning |
|---|---|
| `conformant` | The condition was judged, and the declared condition held. |
| `unauthorized` | The condition was judged and did not hold; the Authorization classes this failure as unauthorized. |
| `drifted` | The condition was judged and did not hold; the Authorization classes this failure as drift. |
| `expired` | The condition could not be judged at the cutoff. It is not a pass and not a violation. |

`conformant` asserts that evidence of the instrument the Authorization
declares, within the freshness it declares, showed the condition held.
`expired` covers evidence that is absent, stale beyond its declared
freshness, from an instrument other than the declared one, or an
Authorization outside its term, and an `expiry_kind` member says which.

### 6.2 Reading determinations as evaluation states

Every judged condition reads as exactly one of three states. There is no
fourth state, no score and no partial credit.

| State | Label a reader sees | Version 0.1 determinations |
|---|---|---|
| `satisfied` | **Cited evidence holds** | `conformant` |
| `not_satisfied` | **Cited evidence does not hold** | `unauthorized`, `drifted` |
| `not_evaluated` | **Not evaluated** | `expired`; and every roster condition whose review state is `not_evaluated` |

A rendering SHOULD carry the caption "cited-evidence result, not a compliance
determination". A `withheld` roster condition was judged and its result is
not disclosed; it reads as withheld, not as any of the three states.

### 6.3 The honesty rule

No evidence is not evidence of conformance. Absent, stale, unattributable or
conflicting evidence yields **not evaluated**, never a pass. None of the
following can supply a positive result: a count of records, the existence of
a platform capability, the integrity of the issuer's internal record, or time
passing without objection. A result a sealed cycle reported as not satisfied
stays so in that cycle; later evidence produces a later cycle.

A rendering SHOULD group not-evaluated results by reason, so a reader can
see why: **no record of authorization**, **evidence insufficient**,
**evidence stale**, **evidence in conflict**. The groups describe the gap.
They never change the state. In a version 0.1 bundle the reasons a reader can
see are the `expiry_kind` of each `expired` determination and the counts in
`coverage_gaps`.

## 7. Verification

### 7.1 Inputs and results

Input: the bundle file and, optionally, an issuer public key the verifier
obtained through a channel other than the bundle. A verifier MUST NOT
require network access, an account with the issuer, or any component of the
issuer's software.

A verifier reports four results, separately:

| Result | Values | Question answered |
|---|---|---|
| CONFORMANCE | `PASS`, `FAIL` | Does the envelope and payload obey §5, does the projection bind to its source, and does every determination and citation resolve? |
| INTEGRITY | `PASS`, `FAIL`, `NOT_ESTABLISHED` | Do the canonical payload bytes match the seal? |
| SIGNATURE | `VALID`, `INVALID`, `NOT_ESTABLISHED` | Does the signature validate under the key the envelope carries? |
| ISSUER TRUST | `TRUSTED`, `NOT_ESTABLISHED`, `MISMATCH` | Does that key match a key obtained out of band? |

`NOT_ESTABLISHED` is never a pass. A verifier MUST NOT present a single
"verified" result. SIGNATURE `VALID` with ISSUER TRUST `NOT_ESTABLISHED`
means that the key inside the envelope signed it, and MUST NOT be rendered
as more.

### 7.2 Procedure

1. **Limits and parse.** Reject input over 32 MiB, and nesting deeper than 64
   levels, as `MALFORMED_ENVELOPE`. Parse as UTF-8 JSON with a parser that
   rejects duplicate member names and any number token that is not a bare
   integer, at parse time. Unreadable input: `MALFORMED_ENVELOPE`, stop. A
   duplicate name or non-integer number: `CANONICALIZATION_FAILURE`
   (CONFORMANCE and INTEGRITY fail), stop. A parser that resolves duplicates
   last-wins, or that reads `1.0` as `1`, is not conforming: it can
   re-canonicalize an altered document back to the sealed bytes.
2. **Envelope.** Check the seven-member envelope and the closed `seal` and
   `signature` blocks with their fixed algorithms, including that
   `seal.digest` is exactly 64 lowercase hex characters and
   `signature.signature` is exactly 128 lowercase hex characters. A `null`
   signature: `SIGNATURE_MISSING`; any other violation:
   `MALFORMED_ENVELOPE`. Stop.
3. **Format.** `format` and `format_version` must be ones the verifier
   implements; otherwise `UNSUPPORTED_VERSION`, stop.
4. **Issuer and entitlement.** Check the required members and types. An
   unknown `entitlement.schema`: `UNSUPPORTED_VERSION`, stop. Unknown
   additional members are tolerated.
5. **Payload.** Check every §5.2 member and its type, and the snapshot and
   manifest schema and profile; digest strings have valid algorithm syntax
   and, for `content_digest`, exactly 64 lowercase hex characters. Failure:
   `PAYLOAD_SCHEMA_VIOLATION`; continue.
6. **Projection binding.** Check that the snapshot's `source` equals
   `authorization_source`, and recompute the snapshot digest. Failure:
   `PROJECTION_BINDING_VIOLATION`; continue.
7. **References.** Check that roster `condition_ref` values and manifest
   `evidence_id` values are unique and sorted by UTF-8 bytes; that each
   determination's `declared_state_ref` matches exactly one roster entry;
   that every citing claim identifier is disclosed; and that digests have
   valid syntax, with every non-null `content_digest` in the `FORMAT.md` §1.5
   syntax (lowercase). Failure: `REFERENCE_RESOLUTION_VIOLATION`; continue.
8. **Seal.** Canonicalize the payload (§5.4) and compare its SHA-256 with
   `seal.digest`, byte-exact; step 2 already required the lowercase
   spelling. Mismatch: `DIGEST_MISMATCH`. This is computed even when steps
   5–7 failed.
9. **Key binding.** Reject a small-order key, and check that `key_id` is the
   SHA-256 of the key bytes. Failure: `KEY_MISMATCH` (SIGNATURE
   `NOT_ESTABLISHED`); go to step 11.
10. **Signature.** Check that `signature.key_id` equals `issuer.key_id`, then
    verify the signature over the signing input (§5.5). Failure:
    `SIGNATURE_INVALID`.
11. **Issuer trust.** No key supplied: `NOT_ESTABLISHED`. Supplied and equal:
    `TRUSTED`. Supplied and different: `ISSUER_TRUST_MISMATCH`.
12. **Report** the four results, every failure code, and the facts the
    bundle carries: issuer, entitlement (as issuer-asserted), Authorization
    identifier, version and source digest, snapshot profile and roster
    counts, manifest entry count, view, generation time (as issuer-asserted),
    `synthetic`, coverage, curation, and the authority facts as carried:
    Authorization status, cycle and cutoff, the approver block,
    determination counts by value, and the omitted categories. Each fact the
    bundle does not carry (§3.6) MUST be reported as not included. A
    verifier MUST NOT obtain it from anywhere else.

### 7.3 Exit codes

A command-line verifier MUST exit:

| Exit | Meaning |
|---|---|
| `0` | CONFORMANCE PASS, INTEGRITY PASS, SIGNATURE VALID, and ISSUER TRUST not MISMATCH |
| `1` | any other completed verification |
| `2` | unreadable or structurally nonconforming input: `MALFORMED_ENVELOPE`, `UNSUPPORTED_VERSION`, `SIGNATURE_MISSING` |

### 7.4 What passing proves

A bundle that passes proves that it conforms to this format and is exactly
what the holder of the enclosed key sealed, under the issuer-asserted
entitlement state. With a matching out-of-band key, it also proves that the
enclosed key is the one the verifier already trusted.

It does not prove the truth of the determinations, the completeness of
sources the bundle does not disclose, the legal sufficiency of the
Authorization, when the bundle was sealed, or, without the source
Authorization, that the projection is a complete rendering of it.

## 8. Reserved vocabulary

These terms are reserved so that a later version can carry them as additive
members (§5.6). A version 0.1 bundle does not carry them, and a version 0.1
verifier reports them as not included. They are named here, not specified.

- **Authorizer reference.** The approver's immutable identity key, as
  distinct from a reusable label.
- **Authorizer lifecycle.** The status history of that identity: active,
  disabled, expired, deleted.
- **Standing.** Whether a grant, and the grantor behind it, can still be
  relied upon at a given moment.
- **Grant standing.** Whether the grantor held the organization's authority
  to make the grant, as the organization declares that authority.
- **Actor continuity.** Whether the actor that acted is the actor that was
  bound: `attested`, `unattested`, or `not-evaluated`.
- **Revalidation.** A recorded human decision that restores reliance on a
  grant after something it depends on changed.
- **Drift states.** Named departures of observed state from declared
  authority.

A later version that carries any of these will state how each is
reported, and bundles issued before it will verify unchanged.

## 9. Conformance

**A conforming bundle** satisfies §5.

**A conforming verifier** implements §7 in full for every version it claims,
reports the four results separately, uses the exit codes of §7.3, and passes
the examples in `examples/` with the results stated in `examples/README.md`.

**A conforming producer** emits only conforming bundles, signs every bundle,
seals the `synthetic` flag truthfully, and never presents a determination as
a compliance determination.

## 10. Security and privacy considerations

- **Key trust.** A self-presented key proves possession, not identity.
  Obtain the issuer key through a contract, a prior independently retained
  bundle, or a published key record, and supply it to the verifier.
- **Hostile input.** The size and depth limits, the strict parser and the
  closed envelope blocks keep a bundle from altering a verifier's result or
  its terminal. A verifier SHOULD escape control and bidirectional characters
  in any bundle-carried string it prints.
- **Personal data.** The `examiner-core-v1` projection carries roles and
  organizations, not personal names, and lists the categories it omits. The
  manifest carries citations, never raw evidence, prompts, responses,
  credentials, IP addresses or tenant identifiers.
- **Synthetic data.** Every example in this repository is synthetic and
  says so in its sealed `synthetic` flag.

## 11. References

- RFC 2119, RFC 8174 — requirement key words.
- RFC 3339 — timestamps.
- RFC 8032 — Ed25519.
- RFC 8785 — JSON Canonicalization Scheme (cited to state that it is not
  used).
- Singletary, C. *Authority Provenance: Standing of Delegated Authority
  Behind Non-Person Actor Actions*, v0.3, 2026-10-02.
  doi:10.5281/zenodo.23105657.

## 12. Changes

- **v0.1.1** (2026-10-25). Editorial. `FORMAT.md` §1.12 names the optional
  payload members the reference verifier reads, and §5.6 points to it. The
  reference verifier's docstring no longer uses an undefined term, and its
  `pyproject.toml` no longer names a `tests/` path the package does not ship
  (issue #1). No change to the format, the record's assertions (§3), the
  verification procedure (§7), any result or any example.
