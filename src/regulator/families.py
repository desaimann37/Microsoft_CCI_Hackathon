"""Mapping SCuBA subject matter to NIST SP 800-53 control families.

This encodes what a practitioner knows: a policy about multi-factor
authentication belongs near the IA (Identification and Authentication) family,
one about log collection near AU (Audit and Accountability), and so on.

It exists because pure lexical retrieval fails on exactly the cases that matter
most. "Phishing-resistant MFA SHALL be enforced for all users" shares almost no
vocabulary with ia-2(1) "Multi-factor Authentication to Privileged Accounts",
so a token-overlap search never surfaces it - and the crosswalk agent can only
propose controls it has been shown.

Deliberately *not* derived from CISA's published mapping. That mapping is the
ground truth the crosswalk is measured against; deriving retrieval from it would
leak the answer and make the evaluation meaningless.
"""

from __future__ import annotations

#: 800-53 family -> vocabulary that suggests it.
FAMILY_HINTS: dict[str, tuple[str, ...]] = {
    "ia": (
        "authentication", "authenticate", "mfa", "multifactor", "multi-factor",
        "phishing", "password", "credential", "identity", "sign-in", "signin",
        "login", "passkey", "fido", "certificate-based", "cba", "piv",
        "authenticator", "token",
    ),
    "ac": (
        "access", "role", "privilege", "privileged", "administrator", "admin",
        "consent", "guest", "permission", "account", "session", "least privilege",
        "assignment", "elevation", "pam", "just-in-time",
    ),
    "au": (
        "log", "logging", "logs", "audit", "monitor", "monitoring", "alert",
        "event", "soc", "telemetry", "record",
    ),
    "cm": (
        "configuration", "setting", "legacy", "protocol", "baseline",
        "disable", "block", "restrict", "registration",
        "allowlist", "denylist", "inventory",
    ),
    "si": (
        "malware", "threat", "risk", "detection", "integrity", "spam",
        "phishing", "anomalous", "suspicious", "quarantine",
    ),
    "sc": (
        "encryption", "encrypt", "tls", "certificate", "boundary",
        "transmission", "confidentiality", "cryptographic",
    ),
    "ra": ("risk assessment", "vulnerability", "scanning", "risk-based"),
    "at": ("training", "awareness"),
    "ir": ("incident", "response", "breach"),
    "pm": ("program", "governance", "policy management"),
}


def likely_families(text: str) -> set[str]:
    """Return the 800-53 families a policy's subject matter suggests."""
    lowered = text.lower()
    return {
        family
        for family, keywords in FAMILY_HINTS.items()
        if any(keyword in lowered for keyword in keywords)
    }
