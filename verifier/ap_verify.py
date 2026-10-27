#!/usr/bin/env python3
"""Reference verifier for Authority Provenance bundles.

Implements Authority Provenance bundle v0.1.1 (SPEC.md and FORMAT.md), format
`cerydora-proof-bundle`,
version 1 (payload schema 1), from the specification alone. This
tool deliberately imports NOTHING from the Cerydora engine and nothing
that can reach a network: verification works offline, without an account,
a subscription, or Cerydora's continued existence, indefinitely after a
bundle is issued.

Verification reports FOUR dimensions separately (SPEC.md §7):

  CONFORMANCE   the envelope and payload obey the specification
  INTEGRITY     the disclosed canonical payload matches the sealed digest
  SIGNATURE     the signature validates under the key the envelope carries
  ISSUER TRUST  whether that key matched one obtained OUT OF BAND

A valid signature under the envelope's self-presented key proves possession
of that key, never issuer identity — issuer trust is NOT_ESTABLISHED until
you supply `--key` from an independent channel.

Usage:
    <verifier> bundle.json [--key ISSUER_PUBLIC_KEY] [--json]

(The program name printed is the name the verifier was invoked under.)

Exit codes (SPEC.md §7.3): 0 CONFORMANCE PASS ∧ INTEGRITY PASS ∧ SIGNATURE
VALID ∧ ISSUER_TRUST ≠ MISMATCH; 1 verification failed; 2 unreadable or
structurally nonconforming input (including unsigned envelopes — every
conforming v1 proof bundle is signed).

Dependency: `cryptography` (Ed25519 only). Everything else is stdlib.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

FORMAT_ID = "cerydora-proof-bundle"
SUPPORTED_VERSIONS = (1,)
SUPPORTED_ENTITLEMENT_SCHEMAS = (1,)
ENVELOPE_MEMBERS = frozenset(
    {"format", "format_version", "payload", "issuer", "entitlement", "seal", "signature"}
)
SAFE_INT = 2**53 - 1

# Robustness limits (SPEC.md §7.2 step 1): hostile input must not be interesting.
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
MAX_JSON_DEPTH = 64

CONDITION_TYPES = frozenset(
    {"evidence_requirement", "prohibited_flow", "activity_rule", "exception"}
)
REVIEW_STATES = frozenset({"evaluated", "not_evaluated", "withheld"})

# SPEC.md §5.5 — small-order Ed25519 point encodings. Anyone can forge
# signatures under these keys, so they never carry the continuity property.
SMALL_ORDER_POINTS = frozenset(
    bytes.fromhex(encoded)
    for encoded in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    )
)

# FORMAT.md §1.1 — required top-level payload members and their JSON types.
PAYLOAD_SCHEMA = {
    "payload_schema": (int,),
    "bundle_id": (str,),
    "view": (str,),
    "generated_at": (str,),
    "synthetic": (bool,),
    "authorization_source": (dict,),
    "authorization_snapshot": (dict,),
    "authorization_snapshot_digest": (dict,),
    "evidence_manifest": (dict,),
    "cycle_id": (str,),
    "as_of": (str,),
    "attestations": (list,),
    "remediation": (list,),
    "open_findings": (list,),
    "working_state_summary": (dict,),
    "coverage_gaps": (dict,),
    "complete_coverage": (bool, type(None)),
    "valid_until": (str, type(None)),
    "policy": (dict,),
    "ledger": (dict,),
    "disclosure": (dict,),
}

SNAPSHOT_SCHEMA = {
    "schema": (int,),
    "profile": (str,),
    "source": (dict,),
    "decision": (dict,),
    "authority": (dict,),
    "approver": (dict,),
    "bounded_operation": (dict,),
    "term": (dict,),
    "evidence_requirements": (list,),
    "condition_roster": (list,),
    "omitted_authorization_categories": (list,),
}

MANIFEST_SCHEMA = {
    "schema": (int,),
    "profile": (str,),
    "entries": (list,),
}


class CanonError(ValueError):
    """A value the canonical form cannot express (SPEC.md §5.3, §5.4)."""


class DuplicateKey(ValueError):
    pass


class NonIntegerNumber(ValueError):
    pass


def parse_document(raw: bytes):
    """SPEC.md §7.2 step 1: UTF-8 JSON with duplicate member names and
    non-integer number tokens rejected AT PARSE TIME — a stock parser that
    collapses `1` and `1.0`, or resolves duplicates last-wins, destroys the
    evidence SPEC.md §5.3/§5.4 require the verifier to detect."""

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise DuplicateKey(key)
            out[key] = value
        return out

    def reject_number(text):
        raise NonIntegerNumber(text)

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=pairs,
        parse_float=reject_number,
        parse_constant=reject_number,
    )


def json_depth(value, level=0):
    if level > MAX_JSON_DEPTH:
        return level
    if isinstance(value, dict):
        return max((json_depth(v, level + 1) for v in value.values()), default=level)
    if isinstance(value, list):
        return max((json_depth(v, level + 1) for v in value), default=level)
    return level


def canonical_bytes(value) -> bytes:
    """Canonical serialization, SPEC.md §5.4. Integer-only numbers (§5.3).
    NOTE: this is deliberately NOT RFC 8785 (JCS) — see SPEC.md §5.4."""
    _check(value)
    text = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    )
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        # A lone UTF-16 surrogate: JSON admits the escape, UTF-8 cannot carry
        # it. A CANONICALIZATION_FAILURE verdict, never a crash.
        raise CanonError("string contains a lone UTF-16 surrogate, which UTF-8 cannot carry (SPEC.md §5.4)") from None


def _check(value) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, float):
        raise CanonError("non-integer JSON numbers are prohibited (SPEC.md §5.3)")
    if isinstance(value, int):
        if abs(value) > SAFE_INT:
            raise CanonError("integer outside the ±(2^53-1) safe range")
        return
    if isinstance(value, dict):
        for item in value.values():
            _check(item)
        return
    if isinstance(value, list):
        for item in value:
            _check(item)
        return
    raise CanonError(f"{type(value).__name__} is not a JSON value")


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if public_key in SMALL_ORDER_POINTS:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def nonempty_string(value) -> bool:
    return isinstance(value, str) and value != ""


def hexn(value, length) -> bool:
    """Exactly `length` lowercase hex characters (SPEC.md §5.5): one
    sealed bundle has one byte-exact spelling of its digests and signature."""
    if not isinstance(value, str) or len(value) != length:
        return False
    return all(c in "0123456789abcdef" for c in value)


def hex64(value) -> bool:
    return hexn(value, 64)


def items(value):
    """Document-derived members the reports iterate: a list, or nothing."""
    return value if isinstance(value, (list, tuple)) else ()


def typed(value, types) -> bool:
    if not isinstance(value, types):
        return False
    return not (isinstance(value, bool) and bool not in types)


def members_conform(obj, schema) -> bool:
    for member, types in schema.items():
        if member not in obj or not typed(obj[member], types):
            return False
    return True


def qualified_digest_conforms(obj, canonicalization) -> bool:
    return (
        isinstance(obj, dict)
        and obj.get("algorithm") == "sha256"
        and obj.get("canonicalization") == canonicalization
        and isinstance(obj.get("digest"), str)
        and hex64(obj["digest"].lower())
    )


def envelope_shape(envelope):
    """SPEC.md §7.2 step 2. Returns a failure code, or None when well-shaped.
    A null signature is nonconforming v1 — every conforming proof bundle is
    signed."""
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_MEMBERS:
        return "MALFORMED_ENVELOPE"
    if not (
        isinstance(envelope["format"], str)
        and typed(envelope["format_version"], (int,))
        and isinstance(envelope["payload"], dict)
        and isinstance(envelope["issuer"], dict)
        and isinstance(envelope["entitlement"], dict)
    ):
        return "MALFORMED_ENVELOPE"
    seal = envelope["seal"]
    if not (
        isinstance(seal, dict)
        and set(seal) == {"algorithm", "digest"}
        and seal["algorithm"] == "sha256"
        and hexn(seal["digest"], 64)  # exactly 64 lowercase hex
    ):
        return "MALFORMED_ENVELOPE"
    signature = envelope["signature"]
    if signature is None:
        return "SIGNATURE_MISSING"
    if not (
        isinstance(signature, dict)
        and set(signature) == {"algorithm", "key_id", "signature"}
        and signature["algorithm"] == "ed25519"
        and isinstance(signature["key_id"], str)
        and hexn(signature["signature"], 128)  # exactly 128 lowercase hex
    ):
        return "MALFORMED_ENVELOPE"
    return None


def payload_conforms(payload) -> bool:
    """SPEC.md §7.2 step 5 — FORMAT.md §1.1 members plus the §1.2–§1.5 nested contracts."""
    if not members_conform(payload, PAYLOAD_SCHEMA):
        return False
    if payload["payload_schema"] != 1:
        return False

    source = payload["authorization_source"]
    if not (
        nonempty_string(source.get("authorization_id"))
        and nonempty_string(source.get("authorization_version"))
        and qualified_digest_conforms(
            source.get("digest"), "cerydora-authorization-json-v1"
        )
    ):
        return False

    snapshot = payload["authorization_snapshot"]
    if not members_conform(snapshot, SNAPSHOT_SCHEMA):
        return False
    if snapshot["schema"] != 1 or snapshot["profile"] != "examiner-core-v1":
        return False
    for entry in snapshot["condition_roster"]:
        if not (
            isinstance(entry, dict)
            and nonempty_string(entry.get("condition_ref"))
            and isinstance(entry.get("condition_type"), str)  # a list here is a violation, not a TypeError
            and entry["condition_type"] in CONDITION_TYPES
            and isinstance(entry.get("summary"), str)
            and isinstance(entry.get("review_state"), str)
            and entry["review_state"] in REVIEW_STATES
        ):
            return False
    if not all(isinstance(item, str) for item in snapshot["omitted_authorization_categories"]):
        return False
    # The disclosed entries that step 7 joins and the report walks must be
    # objects with string ids.
    for bucket in ("attestations", "remediation", "open_findings"):
        for entry in payload[bucket]:
            if not (
                isinstance(entry, dict)
                and nonempty_string(entry.get("claim_id"))
                and nonempty_string(entry.get("declared_state_ref"))
                and ("disposition" not in entry or isinstance(entry["disposition"], str))
            ):
                return False

    if not qualified_digest_conforms(
        payload["authorization_snapshot_digest"],
        "cerydora-authorization-snapshot-v1",
    ):
        return False

    manifest = payload["evidence_manifest"]
    if not members_conform(manifest, MANIFEST_SCHEMA):
        return False
    if manifest["schema"] != 1 or manifest["profile"] != "citation-v1":
        return False
    for entry in manifest["entries"]:
        if not (
            isinstance(entry, dict)
            and nonempty_string(entry.get("evidence_id"))
            and nonempty_string(entry.get("source"))
            and isinstance(entry.get("cited_by_claim_ids"), list)
            and all(isinstance(claim_id, str) for claim_id in entry["cited_by_claim_ids"])  # string ids only
        ):
            return False
        reference = entry.get("reference")
        if reference is not None and not (
            isinstance(reference, dict)
            and nonempty_string(reference.get("kind"))
            and nonempty_string(reference.get("value"))
        ):
            return False
        content_digest = entry.get("content_digest")
        if content_digest is not None and not (
            isinstance(content_digest, dict)
            and content_digest.get("algorithm") == "sha256"
            and hex64(content_digest.get("digest"))  # lowercase only (FORMAT.md §1.5)
        ):
            return False
    return True


def projection_binds(payload) -> bool:
    """SPEC.md §7.2 step 6: source equality; snapshot digest recomputes."""
    snapshot = payload["authorization_snapshot"]
    if snapshot["source"] != payload["authorization_source"]:
        return False
    try:
        recomputed = hashlib.sha256(canonical_bytes(snapshot)).hexdigest()
    except CanonError:
        return False
    return recomputed == payload["authorization_snapshot_digest"]["digest"].lower()


def references_resolve(payload) -> bool:
    """SPEC.md §7.2 step 7: roster/manifest ordering plus the equality joins."""
    roster = payload["authorization_snapshot"]["condition_roster"]
    refs = [entry["condition_ref"] for entry in roster]
    if len(set(refs)) != len(refs) or refs != sorted(
        refs, key=lambda r: r.encode("utf-8")
    ):
        return False

    disclosed = set()
    roster_refs = set(refs)
    for bucket in ("attestations", "remediation", "open_findings"):
        for entry in payload[bucket]:
            if not isinstance(entry, dict):
                return False
            claim_id = entry.get("claim_id")
            declared = entry.get("declared_state_ref")
            if not (nonempty_string(claim_id) and nonempty_string(declared)):
                return False
            if declared not in roster_refs:
                return False
            disclosed.add(claim_id)

    entries = payload["evidence_manifest"]["entries"]
    ids = [entry["evidence_id"] for entry in entries]
    if len(set(ids)) != len(ids) or ids != sorted(ids, key=lambda i: i.encode("utf-8")):
        return False
    for entry in entries:
        for claim_id in entry["cited_by_claim_ids"]:
            if claim_id not in disclosed:
                return False
    return True


def roster_counts(payload):
    snapshot = payload.get("authorization_snapshot")
    if not isinstance(snapshot, dict):
        return None
    roster = snapshot.get("condition_roster")
    if not isinstance(roster, list):
        return None
    counts = {"evaluated": 0, "not_evaluated": 0, "withheld": 0}
    for entry in roster:
        state = entry.get("review_state") if isinstance(entry, dict) else None
        if isinstance(state, str) and state in counts:  # an unhashable state is not a count
            counts[state] += 1
    return counts


DISPOSITIONS = ("conformant", "unauthorized", "drifted", "expired")


def determination_counts(payload):
    """Disclosed determinations by disposition, across the three entry arrays.
    Reported, not judged — the verifier does not recompute any disposition."""
    counts = {name: 0 for name in DISPOSITIONS}
    counts["other"] = 0
    disclosed = 0
    for member in ("attestations", "remediation", "open_findings"):
        entries = payload.get(member)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            disposition = entry.get("disposition") if isinstance(entry, dict) else None
            counts[disposition if isinstance(disposition, str) and disposition in counts else "other"] += 1
            disclosed += 1
    counts["disclosed"] = disclosed
    return counts


def optional_list(payload, name):
    """An additive payload member (SPEC.md §5.6) that format version 1 does not
    define. Returned only when present as a list; absence is reported as
    not-included, never defaulted."""
    value = payload.get(name)
    return value if isinstance(value, list) else None


def verify(raw: bytes, trusted_key_hex=None) -> dict:
    """SPEC.md §7.2, complete. Four dimensions, reported separately; the only
    aggregate is the exit-code contract (§7.3). Entitlement is
    issuer-asserted and never consulted for any dimension (SPEC.md §5.1)."""
    result = {
        "conformance": "FAIL",
        "integrity": "NOT_ESTABLISHED",
        "signature": "NOT_ESTABLISHED",
        "issuer_trust": "NOT_ESTABLISHED",
        "failures": [],
        "facts": {},
    }

    # Step 1 — limits and parse.
    if len(raw) > MAX_DOCUMENT_BYTES:
        result["failures"].append("MALFORMED_ENVELOPE")
        return result
    try:
        envelope = parse_document(raw)
    except (DuplicateKey, NonIntegerNumber):
        result["integrity"] = "FAIL"
        result["failures"].append("CANONICALIZATION_FAILURE")
        return result
    except (ValueError, UnicodeDecodeError, RecursionError):
        # RecursionError: nesting deep enough to exhaust the parser's stack
        # is hostile structure, not a crash.
        result["failures"].append("MALFORMED_ENVELOPE")
        return result
    if json_depth(envelope) > MAX_JSON_DEPTH:
        result["failures"].append("MALFORMED_ENVELOPE")
        return result

    # Step 2 — envelope shape (closed seal/signature blocks, signed-only).
    shape = envelope_shape(envelope)
    if shape is not None:
        result["failures"].append(shape)
        return result

    # Step 3 — format identity and version.
    if envelope["format"] != FORMAT_ID or envelope["format_version"] not in SUPPORTED_VERSIONS:
        result["failures"].append("UNSUPPORTED_VERSION")
        return result

    # Step 4 — issuer and entitlement required members.
    issuer = envelope["issuer"]
    entitlement = envelope["entitlement"]
    if not (
        nonempty_string(issuer.get("deployment_id"))
        and nonempty_string(issuer.get("identity_class"))
        and hex64(issuer.get("public_key"))
        and isinstance(issuer.get("key_id"), str)
        and nonempty_string(entitlement.get("state"))
        and typed(entitlement.get("schema"), (int,))
    ):
        result["failures"].append("MALFORMED_ENVELOPE")
        return result
    if entitlement["schema"] not in SUPPORTED_ENTITLEMENT_SCHEMAS:
        result["failures"].append("UNSUPPORTED_VERSION")
        return result

    payload = envelope["payload"]
    public_key = issuer["public_key"]

    if trusted_key_hex is None:
        trusted_key = "not supplied"
    elif trusted_key_hex.lower() == public_key.lower():
        trusted_key = "matched"
    else:
        trusted_key = "mismatched"
    source = payload.get("authorization_source")
    snapshot = payload.get("authorization_snapshot")
    manifest = payload.get("evidence_manifest")
    disclosure = payload.get("disclosure")
    result["facts"] = {
        "format": envelope["format"],
        "format_version": envelope["format_version"],
        "payload_schema": payload.get("payload_schema"),
        "deployment_id": issuer.get("deployment_id"),
        "key_id": issuer.get("key_id"),
        "identity_class": issuer.get("identity_class"),
        "trusted_key": trusted_key,
        "entitlement_state": entitlement.get("state"),
        "entitlement_schema": entitlement.get("schema"),
        "authorization_source": source if isinstance(source, dict) else None,
        "snapshot_profile": (
            snapshot.get("profile") if isinstance(snapshot, dict) else None
        ),
        "roster_review_states": roster_counts(payload),
        "manifest_entries": (
            len(manifest["entries"])
            if isinstance(manifest, dict) and isinstance(manifest.get("entries"), list)
            else None
        ),
        "view": payload.get("view"),
        "generated_at": payload.get("generated_at"),
        "synthetic": payload.get("synthetic"),
        "complete_coverage": payload.get("complete_coverage"),
        "coverage_gaps": payload.get("coverage_gaps"),
        "curation_policy": (
            disclosure.get("policy_name") if isinstance(disclosure, dict) else None
        ),
        # Authority-chain facts: what the bundle carries about the declared
        # authority, reported verbatim. Members the bundle does not carry are
        # reported as not-included by render(); nothing is fetched or inferred.
        "bundle_id": payload.get("bundle_id"),
        "cycle_id": payload.get("cycle_id"),
        "as_of": payload.get("as_of"),
        "decision_status": (
            snapshot["decision"].get("status")
            if isinstance(snapshot, dict) and isinstance(snapshot.get("decision"), dict)
            else None
        ),
        "approver": (
            snapshot.get("approver")
            if isinstance(snapshot, dict) and isinstance(snapshot.get("approver"), dict)
            else None
        ),
        "omitted_categories": (
            snapshot.get("omitted_authorization_categories")
            if isinstance(snapshot, dict)
            and isinstance(snapshot.get("omitted_authorization_categories"), list)
            else None
        ),
        "determinations": determination_counts(payload),
        "ledger": payload.get("ledger") if isinstance(payload.get("ledger"), dict) else None,
        "principal_results": optional_list(payload, "principal_results"),
        "execution_results": optional_list(payload, "execution_results"),
        "revalidation_results": optional_list(payload, "revalidation_results"),
    }

    conformance = "PASS"

    # Step 5 — payload schema (deep); steps 6–7 need a traversable shape.
    if not payload_conforms(payload):
        conformance = "FAIL"
        result["failures"].append("PAYLOAD_SCHEMA_VIOLATION")
    else:
        # Step 6 — projection binding.
        if not projection_binds(payload):
            conformance = "FAIL"
            result["failures"].append("PROJECTION_BINDING_VIOLATION")
        # Step 7 — reference resolution.
        if not references_resolve(payload):
            conformance = "FAIL"
            result["failures"].append("REFERENCE_RESOLUTION_VIOLATION")

    # Step 8 — integrity: the digest question only.
    try:
        digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    except CanonError:
        result["integrity"] = "FAIL"
        result["failures"].append("CANONICALIZATION_FAILURE")
    else:
        if digest == envelope["seal"]["digest"]:  # the shape check already requires lowercase hex
            result["integrity"] = "PASS"
        else:
            result["integrity"] = "FAIL"
            result["failures"].append("DIGEST_MISMATCH")

    # Steps 9–10 — key binding, then the signature. A broken identity
    # assertion is a conformance failure; the signature cannot be
    # meaningfully evaluated under it.
    key_bytes = bytes.fromhex(public_key)
    signature = envelope["signature"]
    if (
        key_bytes in SMALL_ORDER_POINTS
        or "sha256:" + hashlib.sha256(key_bytes).hexdigest() != issuer.get("key_id")
        or signature["key_id"] != issuer.get("key_id")
    ):
        conformance = "FAIL"
        result["failures"].append("KEY_MISMATCH")
    else:
        try:
            message = canonical_bytes(
                {
                    "entitlement": entitlement,
                    "format": envelope["format"],
                    "format_version": envelope["format_version"],
                    "issuer": issuer,
                    "seal": envelope["seal"],
                }
            )
            signature_bytes = bytes.fromhex(signature["signature"])
        except (ValueError, CanonError):
            result["signature"] = "INVALID"
            result["failures"].append("SIGNATURE_INVALID")
        else:
            if ed25519_verify(key_bytes, signature_bytes, message):
                result["signature"] = "VALID"
            else:
                result["signature"] = "INVALID"
                result["failures"].append("SIGNATURE_INVALID")

    # Step 11 — issuer trust, never established by the envelope alone.
    if trusted_key == "not supplied":
        result["issuer_trust"] = "NOT_ESTABLISHED"
    elif trusted_key == "matched":
        result["issuer_trust"] = "TRUSTED"
    else:
        result["issuer_trust"] = "MISMATCH"
        result["failures"].append("ISSUER_TRUST_MISMATCH")

    result["conformance"] = conformance
    return result


CONTINUITY_NOTE = (
    "self-generated key — a valid signature is continuity, not certification"
)

NO_TRUST_ANCHOR_NOTE = """\
NOTE: no trusted issuer key was supplied (--key). SIGNATURE VALID means the
key carried INSIDE this envelope signed it — that proves possession of that
key, not who the issuer is. ISSUER TRUST stays NOT_ESTABLISHED until you
compare the key_id above against one received through a channel other than
this bundle (contract, prior bundle, published key record).
"""

WHAT_THIS_PROVES = """\
A fully passing verification proves the package conforms to the format and
is exactly what the holder of the enclosed key sealed, under the
issuer-asserted entitlement state. It does NOT prove the truth of the
underlying determinations, the completeness of undisclosed sources, the
legal sufficiency of the Authorization, when the bundle was sealed, or —
without the source Authorization — that the projection is a complete
derivation of it.
"""


AUTHORITY_CHAIN_NOTE = """\
The authority-chain lines report only what the envelope carries. The verifier
never reaches past the export to the serving platform; a member the bundle does
not carry is reported as not-included — never inferred, never defaulted. In
format version 1 the authorizer's immutable reference and lifecycle, the
actor-continuity states (attested / unattested / not-evaluated), the drift
states, and revalidation are internal ledger slots; an examiner-mode export
omits them by design.
"""

NOT_INCLUDED = "not-included"


def _principal_lines(rows):
    lines = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        roles = ",".join(str(role) for role in items(row.get("roles_in_authorization")))
        states = ",".join(str(state) for state in items(row.get("states"))) or "none"
        lines.append(
            f"    {row.get('principal_id')} roles={roles or '?'} "
            f"lifecycle={row.get('lifecycle_state')} currency={row.get('currency')} "
            f"states={states}"
        )
    return lines or ["    (empty)"]


def _execution_lines(rows):
    lines = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        states = list(items(row.get("states")))
        if states:
            basis = ",".join(str(item) for item in items(row.get("unattested_basis"))) or "-"
            outcome = f"unattested ({','.join(str(s) for s in states)}; basis {basis})"
        elif row.get("fingerprint_declared") is True:
            outcome = "attested"
        else:
            outcome = "not-evaluated"
        lines.append(f"    {row.get('binding_id') or row.get('binding_ref')}: {outcome}")
    return lines or ["    (empty)"]


def _revalidation_lines(rows):
    lines = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("states"):
            status = "open"
        else:
            attester = row.get("attested_by") or row.get("attestation_ref") or "not-recorded"
            status = f"closed (attesting human reference: {attester})"
        lines.append(f"    signal {row.get('signal_ref')}: {status}")
    return lines or ["    (empty)"]


def render_authority_chain(facts: dict) -> list:
    source = facts.get("authorization_source") if isinstance(facts.get("authorization_source"), dict) else {}
    approver = facts.get("approver")
    counts = facts.get("determinations") or {}
    roster = facts.get("roster_review_states") or {}
    ledger = facts.get("ledger") if isinstance(facts.get("ledger"), dict) else {}
    lines = [
        "",
        "authority chain (as carried by this bundle):",
        f"  authorization:    {source.get('authorization_id')} v{source.get('authorization_version')}"
        f" · status {facts.get('decision_status')}",
        f"  cycle:            {facts.get('cycle_id')} · as of {facts.get('as_of')}",
    ]
    if isinstance(approver, dict):
        lines.append(
            f"  approver:         role {approver.get('role')!r} · "
            f"identity_verified={approver.get('identity_verified')}"
        )
    else:
        lines.append(f"  approver:         {NOT_INCLUDED}")
    principals = facts.get("principal_results")
    if principals is None:
        lines.append(f"  authorizer ref:   {NOT_INCLUDED} (immutable directory key is an internal slot)")
        lines.append(f"  lifecycle:        {NOT_INCLUDED}")
    else:
        lines.append("  authorizer ref / lifecycle (additive member, reported verbatim):")
        lines += _principal_lines(principals)
    lines.append(
        f"  determinations:   {counts.get('disclosed', 0)} disclosed — "
        + " ".join(f"{name}={counts.get(name, 0)}" for name in DISPOSITIONS)
    )
    lines.append(
        f"  conditions:       evaluated={roster.get('evaluated')} "
        f"not_evaluated={roster.get('not_evaluated')} withheld={roster.get('withheld')} "
        "(roster; not_evaluated is silence, never a pass)"
    )
    executions = facts.get("execution_results")
    if executions is None:
        lines.append(
            f"  actor continuity: {NOT_INCLUDED} "
            "(attested / unattested / not-evaluated are internal slots)"
        )
    else:
        lines.append("  actor continuity (additive member, reported verbatim):")
        lines += _execution_lines(executions)
    revalidation = facts.get("revalidation_results")
    if revalidation is None:
        lines.append(f"  drift states:     {NOT_INCLUDED}")
        lines.append(f"  revalidation:     {NOT_INCLUDED}")
    else:
        lines.append("  revalidation (additive member, reported verbatim):")
        lines += _revalidation_lines(revalidation)
    lines.append(
        f"  ledger:           verify={ledger.get('verify', NOT_INCLUDED)} "
        f"chain={ledger.get('chain_algorithm', NOT_INCLUDED)} "
        f"records_verified={ledger.get('records_verified', NOT_INCLUDED)} "
        f"head_hash={ledger.get('head_hash', NOT_INCLUDED)}"
    )
    omitted = items(facts.get("omitted_categories"))
    lines.append(
        "  omitted by profile: " + (", ".join(str(item) for item in omitted) if omitted else NOT_INCLUDED)
    )
    lines += ["", AUTHORITY_CHAIN_NOTE.rstrip()]
    return lines


# Characters a terminal or a reader's eye can be steered by: C0 (including
# newline and ESC), DEL, C1, and the bidi embedding/override/isolate marks.
_UNSAFE_CODEPOINTS = frozenset(
    [*range(0x00, 0x20), *range(0x7F, 0xA0), 0x061C, 0x200E, 0x200F,
     *range(0x202A, 0x202F), *range(0x2066, 0x206A)]
)


def printable(value):
    """Document-derived text, made inert for human output:
    every unsafe code point is shown as a visible \\uXXXX escape."""
    if isinstance(value, str):
        # Lone surrogates are shown as escapes too: a text report
        # must reach stdout in UTF-8 whatever the document carried.
        return "".join(f"\\u{ord(c):04x}" if ord(c) in _UNSAFE_CODEPOINTS or 0xD800 <= ord(c) <= 0xDFFF else c
                       for c in value)
    if isinstance(value, dict):
        return {printable(k): printable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [printable(item) for item in value]
    return value


def program_name(argv0=None) -> str:
    """The name this verifier was invoked under: the basename of argv[0],
    without ".py". A package `__main__`, or no usable argv[0], falls back to
    this module's own name. The tool hardcodes no name of its own."""
    if argv0 is None:
        argv0 = sys.argv[0] if sys.argv else ""
    name = os.path.basename(argv0)
    if name.endswith(".py"):
        name = name[: -len(".py")]
    if name in ("", "-c", "__main__"):
        name = os.path.splitext(os.path.basename(__file__))[0]
    return name


def render(result: dict, prog=None) -> str:
    # Every fact is document-derived; dimensions and failure codes are ours.
    facts = printable(result["facts"])
    lines = [f"{prog or program_name()} — proof bundle verification", ""]
    if facts:
        lines.append(
            f"format:        {facts['format']} v{facts['format_version']} "
            f"(payload schema {facts.get('payload_schema')})"
        )
    lines.append(f"CONFORMANCE:   {result['conformance']}")
    lines.append(f"INTEGRITY:     {result['integrity']}")
    signature = result["signature"]
    if signature == "VALID" and facts.get("identity_class") == "self-generated":
        lines.append(f"SIGNATURE:     {signature} ({CONTINUITY_NOTE})")
    else:
        lines.append(f"SIGNATURE:     {signature}")
    lines.append(f"ISSUER TRUST:  {result['issuer_trust']}")
    if result["failures"]:
        lines.append(f"failures:      {', '.join(result['failures'])}")
    if facts:
        source = facts.get("authorization_source") if isinstance(facts.get("authorization_source"), dict) else {}
        digest = source.get("digest").get("digest") if isinstance(source.get("digest"), dict) else None
        roster = facts.get("roster_review_states") or {}
        lines += [
            "",
            f"issuer:        {facts.get('deployment_id')}",
            f"               {facts.get('key_id')} ({facts.get('identity_class')})",
            f"trust anchor:  {facts.get('trusted_key')}",
            f"entitlement:   {facts.get('entitlement_state')} "
            "(issuer-asserted; reported, not judged)",
            f"authorization: {source.get('authorization_id')} "
            f"v{source.get('authorization_version')}",
            f"               source digest {digest}",
            f"projection:    {facts.get('snapshot_profile')} — conditions "
            f"evaluated={roster.get('evaluated')} "
            f"not_evaluated={roster.get('not_evaluated')} "
            f"withheld={roster.get('withheld')}",
            f"evidence:      {facts.get('manifest_entries')} cited "
            "(citation-only manifest — no replay or completeness claim)",
            f"view:          {facts.get('view')}",
            f"generated at:  {facts.get('generated_at')} (issuer-asserted)",
            f"synthetic:     {facts.get('synthetic')}",
            f"coverage:      complete={facts.get('complete_coverage')} "
            f"gaps={facts.get('coverage_gaps')}",
            f"curation:      {facts.get('curation_policy')}",
        ]
        lines += render_authority_chain(facts)
        if facts.get("trusted_key") == "not supplied":
            lines += ["", NO_TRUST_ANCHOR_NOTE.rstrip()]
    lines += ["", WHAT_THIS_PROVES.rstrip()]
    return "\n".join(lines)


def read_key(argument: str) -> str:
    """`--key` accepts a hex string or a path to a file holding one."""
    if os.path.exists(argument):
        with open(argument, "r", encoding="utf-8") as handle:
            argument = handle.read().strip()
    key = argument.strip().lower()
    try:
        if len(bytes.fromhex(key)) != 32:
            raise ValueError
    except ValueError:
        raise SystemExit("--key is not a 64-hex-character Ed25519 public key")
    return key


def main(argv=None) -> int:
    prog = program_name()
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Authority Provenance bundle v0.1.1; see SPEC.md and FORMAT.md.",
    )
    parser.add_argument("bundle", help="path to the sealed bundle JSON file")
    parser.add_argument(
        "--key",
        help="trusted issuer public key obtained OUT OF BAND: 64 hex "
        "characters, or a file containing them",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the verification result as ASCII-only JSON instead of text",
    )
    arguments = parser.parse_args(argv)

    try:
        with open(arguments.bundle, "rb") as handle:
            # One byte past the limit is enough to refuse.
            raw = handle.read(MAX_DOCUMENT_BYTES + 1)
    except OSError as error:
        print(f"cannot read {arguments.bundle}: {error}", file=sys.stderr)
        return 2

    trusted = read_key(arguments.key) if arguments.key else None
    result = verify(raw, trusted_key_hex=trusted)
    if arguments.json:
        print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    else:
        print(render(result, prog))

    # Exit codes per SPEC.md §7.3.
    if {"MALFORMED_ENVELOPE", "UNSUPPORTED_VERSION", "SIGNATURE_MISSING"} & set(
        result["failures"]
    ):
        return 2
    passed = (
        result["conformance"] == "PASS"
        and result["integrity"] == "PASS"
        and result["signature"] == "VALID"
        and result["issuer_trust"] != "MISMATCH"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
