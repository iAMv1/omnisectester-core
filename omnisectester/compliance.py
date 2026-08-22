"""CWE -> compliance control mapping (PCI DSS, NIST 800-53, SOC 2, ISO 27001).

Static deterministic mapping for the CWEs our scanners emit. Unknown CWEs
return a generic secure-development control reference.
"""

MAPPING = {
    "CWE-79":  {"pci_dss": "6.5.1", "nist_800_53": "SI-10",
                "soc2": "CC8.1", "iso27001": "A.8.28",
                "name": "Injection/XSS coding flaw"},
    "CWE-89":  {"pci_dss": "6.5.1", "nist_800_53": "SI-10",
                "soc2": "CC8.1", "iso27001": "A.8.28",
                "name": "SQL injection"},
    "CWE-601": {"pci_dss": "6.5.1", "nist_800_53": "SC-23",
                "soc2": "CC6.7", "iso27001": "A.8.25",
                "name": "Open redirect"},
    "CWE-319": {"pci_dss": "4.1", "nist_800_53": "SC-8",
                "soc2": "CC6.7", "iso27001": "A.8.24",
                "name": "Cleartext transmission"},
    "CWE-352": {"pci_dss": "6.5.9", "nist_800_53": "SC-23",
                "soc2": "CC6.1", "iso27001": "A.8.25",
                "name": "CSRF"},
    "CWE-538": {"pci_dss": "3.4", "nist_800_53": "AC-3",
                "soc2": "CC6.1", "iso27001": "A.5.15",
                "name": "Sensitive file exposure"},
    "CWE-200": {"pci_dss": "6.5.5", "nist_800_53": "SC-13",
                "soc2": "CC6.7", "iso27001": "A.8.9",
                "name": "Information disclosure"},
    "CWE-1021": {"pci_dss": "6.5.1", "nist_800_53": "SC-5",
                 "soc2": "CC6.6", "iso27001": "A.8.29",
                 "name": "Clickjacking / framing"},
    "CWE-693": {"pci_dss": "2.2", "nist_800_53": "CM-7",
                "soc2": "CC6.8", "iso27001": "A.8.9",
                "name": "Protection mechanism failure"},
    "CWE-327": {"pci_dss": "4.1", "nist_800_53": "SC-13",
                "soc2": "CC6.7", "iso27001": "A.8.24",
                "name": "Broken crypto / weak TLS"},
    "CWE-298": {"pci_dss": "4.1", "nist_800_53": "SC-12",
                "soc2": "CC6.7", "iso27001": "A.8.24",
                "name": "Certificate lifecycle failure"},
    "CWE-1427": {"pci_dss": "6.4.2", "nist_800_53": "AT-2",
                 "soc2": "CC8.1", "iso27001": "A.8.28",
                 "name": "LLM prompt injection"},
    "CWE-614": {"pci_dss": "3.4", "nist_800_53": "SC-9",
                "soc2": "CC6.7", "iso27001": "A.8.24",
                "name": "Sensitive cookie without Secure"},
    "CWE-1004": {"pci_dss": "3.4", "nist_800_53": "SC-9",
                 "soc2": "CC6.6", "iso27001": "A.8.24",
                 "name": "Cookie without HttpOnly"},
    "CWE-1275": {"pci_dss": "6.5.9", "nist_800_53": "SC-23",
                 "soc2": "CC6.6", "iso27001": "A.8.25",
                 "name": "Cookie SameSite absent"},
    "CWE-0":   {"pci_dss": "6.3", "nist_800_53": "RA-5",
                "soc2": "CC7.1", "iso27001": "A.8.8",
                "name": "General/unknown"},
}


def map_finding(cwe: str) -> dict:
    """Return compliance control references for one finding's CWE."""
    entry = MAPPING.get((cwe or "CWE-0").upper(), MAPPING["CWE-0"])
    return {
        "pci_dss": f"Req {entry['pci_dss']}",
        "nist_800_53": entry["nist_800_53"],
        "soc2": entry["soc2"],
        "iso27001": entry["iso27001"],
        "control_name": entry["name"],
    }


def attach(result: dict) -> dict:
    """Attach a compliance list to every finding in-place; return result."""
    for f in result.get("findings", []):
        f["compliance"] = map_finding(f.get("cwe"))
    return result
