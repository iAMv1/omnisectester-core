"""Cloud infrastructure config auditor - offline file inspection.

Scans IaC/config files for well-known dangerous patterns:
  Terraform (.tf):
    C001  S3 bucket ACL public-read/public-read-write
    C002  security group ingress 0.0.0.0/0 on port 22 or 3389
  Kubernetes (.yaml/.yml with kind: Pod/Deployment):
    C004  privileged: true container
    C005  containers running as root without runAsNonRoot
  AWS credentials file:
    C006  long-lived access keys present on disk

Deterministic regex/heuristic level - not a policy engine.
"""

import os
import re

from .scanner import _finding, _sort

from .scanner import _finding, _sort

TF_PUBLIC_ACL = re.compile(
    r"acl\s*=\s*\"(public-read|public-read-write)\"", re.I)
TF_SG_CIDR = re.compile(r"cidr_blocks\s*=\s*\"0\.0\.0\.0/0\"", re.I)
TF_PORT_22 = re.compile(r"from_port\s*=\s*(22|3389)\b")
TF_ENCRYPT = re.compile(r"encrypt\s*=\s*true", re.I)
TF_BUCKET_BLOCK = re.compile(
    r"resource\s+\"aws_s3_bucket\"\s+\"([^\"]+)\"", re.I)

K8S_PRIVILEGED = re.compile(r"privileged\s*:\s*true", re.I)
KIND_RE = re.compile(r"^kind:\s*(\w+)", re.M)
RUNASNONROOT = re.compile(r"runAsNonRoot\s*:\s*true")

AWS_KEY_FILE_SECTION = re.compile(r"^\[", re.M)
AWS_KEY_LINE = re.compile(r"aws_access_key_id\s*=", re.I)


def _iter_files(root, exts):
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        for f in files:
            if f.endswith(exts):
                yield os.path.join(base, f)


def scan_tf_file(path, content, findings):
    # public ACL anywhere in the file
    if TF_PUBLIC_ACL.search(content):
        findings.append(_finding(
            "C001", "S3 bucket ACL is public", "high",
            f"{path}: acl = public-read(-write).",
            "Remove the public ACL; use CloudFront/OAC if serving publicly.",
            path))

    # open SG port 22/3389 requires both cidr 0.0.0.0/0 AND the port nearby
    blocks = re.split(r"(?=resource\s)", content)
    for block in blocks:
        if TF_SG_CIDR.search(block) and TF_PORT_22.search(block):
            name_m = re.search(r"resource\s+\"([^\"]+)\"\s+\"([^\"]+)\"", block)
            res = f"{name_m.group(1)}.{name_m.group(2)}" if name_m else "security rule"
            findings.append(_finding(
                "C002", f"Open management port to the internet ({res})",
                "high", f"{path}: 0.0.0.0/0 on port 22/3389.",
                "Restrict CIDR to bastion/VPN ranges; use SSM Session Manager.",
                path))

    # unencrypted buckets: aws_s3_bucket block without encrypt=true nearby
    # (dropped as a finding: S3 defaults to SSE-S3 since Jan 2023 -
    #  flagging every bucket without an explicit block was pure noise)


def scan_k8s_file(path, content, findings):
    kind_m = KIND_RE.search(content)
    if not kind_m:
        return
    if kind_m.group(1) not in ("Pod", "Deployment", "StatefulSet", "DaemonSet", "Job"):
        return
    if K8S_PRIVILEGED.search(content):
        findings.append(_finding(
            "C004", "Privileged container", "high",
            f"{path}: privileged: true.",
            "Drop privileges; use granular capabilities instead.",
            path))
    if not RUNASNONROOT.search(content):
        findings.append(_finding(
            "C005", "Pod does not enforce non-root user", "medium",
            f"{path}: no runAsNonRoot: true in securityContext.",
            "Set runAsNonRoot: true plus a numeric runAsUser.", path))


def scan_aws_credentials(path, content, findings):
    if AWS_KEY_LINE.search(content):
        findings.append(_finding(
            "C006", "Long-lived AWS access key stored on disk", "high",
            f"{path}: static aws_access_key_id found.",
            "Migrate to short-term roles / SSO; delete static keys.", path))


def run_cloud_scan(root: str) -> dict:
    findings = []
    tf_exts = (".tf",)
    yaml_exts = (".yaml", ".yml")
    for path in _iter_files(root, tf_exts):
        content = _read_file(path)
        scan_tf_file(path, content, findings)
    for path in _iter_files(root, yaml_exts):
        content = _read_file(path)
        if re.search(r"\bapiVersion\b", content):
            scan_k8s_file(path, content, findings)
    for home_name in (".aws",):
        cred = os.path.join(os.path.expanduser("~"), home_name, "credentials")
        if os.path.isfile(cred):
            scan_aws_credentials(cred, _read_file(cred), findings)
    return {
        "command": "scan", "platform": "cloud", "target": root, "ok": True,
        "findings": _sort(findings),
        "stats": {"requests": 0, "total": len(findings),
                  "critical": sum(1 for f in findings if f["severity"] == "critical"),
                  "high": sum(1 for f in findings if f["severity"] == "high")},
    }


def _read_file(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""
