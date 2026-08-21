"""Transparent rules for candidate endpoint evidence relations."""

RULESET_VERSION = "1.0"

SIGNAL_CLASS = {
    "tls_certificate_sha256": "strong_for_relation",
    "neighbor_link_layer_sha256": "strong_for_relation",
    "http_body_prefix_sha256": "supporting",
    "ptr_name": "weak",
    "service_hint": "weak",
    "address": "supporting",
}

RELATION_LIMITATIONS = [
    "candidate_relation_does_not_confirm_identity",
    "shared_evidence_does_not_confirm_physical_device",
    "forex_must_interpret_relation_in_context",
]
