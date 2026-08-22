"""Vulnerability category taxonomy - 130+ entries across all domains."""

CATEGORIES = {
    "web": [
        "injection-sql", "injection-nosql", "injection-ldap", "injection-command",
        "xss-reflected", "xss-stored", "xss-dom", "xxe-classic", "xxe-oob",
        "ssrf-server", "ssrf-blind", "idor", "access-control-broken",
        "auth-broken", "session-fixation", "csrf", "open-redirect",
        "path-traversal", "lfi-rfi", "deserialization-insecure",
        "security-misconfiguration", "headers-missing", "cors-wildcard",
        "clickjacking", "cache-poisoning", "request-smuggling",
        "response-splitting", "template-injection-ssti", "crlf-injection",
        "graphql-introspection", "graphql-batching-abuse",
    ],
    "api": [
        "api-auth-missing", "api-rate-limit-absent", "api-versioning-weak",
        "api-mass-assignment", "api-excessive-data-exposure",
        "websocket-no-origin-check", "graphql-field-suggestion",
    ],
    "business_logic": [
        "race-condition-tou", "state-machine-violation", "workflow-bypass",
        "price-tampering", "quantity-negative", "coupon-stacking",
        "multi-tenant-isolation", "defi-reentrancy", "refund-double-spend",
        "vote-rigging", "trial-abuse", "loyalty-points-manipulation",
    ],
    "supply_chain": [
        "dependency-confusion", "typosquatting-package", "cicd-pipeline-poisoning",
        "artifact-tampering", "signature-missing", "sbom-drift",
        "registry-pin-absent", "lockfile-divergence", "postinstall-script-risk",
        "transitive-dep-unpinned", "provenance-attestation-missing",
    ],
    "cloud": [
        "iam-overprivileged", "iam-keys-committed", "s3-public-read",
        "s3-public-write", "sg-open-ingress", "sg-open-egress",
        "metadata-v1-enabled", "kms-unencrypted-volume", "rds-public",
        "lambda-env-secrets", "k8s-privileged-pod", "k8s-hostmount",
        "terraform-state-secrets", "azure-runbook-creds",
    ],
    "ai_llm": [
        "prompt-injection-direct", "prompt-injection-indirect",
        "system-prompt-leak", "jailbreak-roleplay", "secret-fishing",
        "rag-poisoning", "training-data-extraction", "model-inversion",
        "adversarial-example-evasion", "llm-output-xss",
        "llm-tool-abuse", "excessive-agency",
    ],
    "mobile": [
        "apk-permission-dangerous", "apk-debuggable", "apk-backup-allowed",
        "apk-unsigned", "exported-component", "deeplink-hijack",
        "hardcoded-secret-mobile", "insecure-local-storage",
    ],
    "desktop": [
        "pe-unsigned-binary", "pe-debug-artifacts", "electron-nodeintegration",
        "electron-csp-unsafe", "updater-no-signature-check",
        "installer-weak-acl",
    ],
    "network_tls": [
        "tls-legacy-protocol", "tls-cert-expired", "tls-cert-expiring",
        "tls-weak-cipher", "hsts-missing", "cert-hostname-mismatch",
    ],
    "cookies_session": [
        "cookie-no-secure", "cookie-no-httponly", "cookie-no-samesite",
        "session-token-entropy-low", "session-no-expiry",
    ],
    "post_exploitation": [
        "cred-dumping-opportunity", "kerberoastable-accounts",
        "asreproastable-accounts", "pass-the-hash-path",
        "lateral-movement-path", "persistence-startup-entry",
        "edr-logging-gaps", "data-staging-area",
    ],
    "firmware": [
        "fw-unsigned-image", "fw-hardcoded-creds-string",
        "fw-debug-uart-strings", "fw-old-kernel-version",
        "fw-default-config-backdoor",
    ],
    "extension": [
        "ext-permissions-overbroad", "ext-remote-code-eval",
        "ext-csp-missing", "ext-update-url-http", "ext-key-hardcoded",
        "ext-content-script-injection", "ext-webrequest-tap",
    ],
    "misc": [
        "info-disclosure-comments", "info-disclosure-stacktrace",
        "email-harvest", "subdomain-takeover-prereq",
        "dns-zone-transfer", "whois-privacy-absent",
    ],
}


def flat():
    out = []
    for domain, cats in CATEGORIES.items():
        for c in cats:
            out.append({"domain": domain, "id": f"{domain}.{c}"})
    return out


def count():
    return len(flat())


if __name__ == "__main__":
    f = flat()
    print(f"{len(f)} categories across {len(CATEGORIES)} domains")
