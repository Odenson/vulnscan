"""Detect hardcoded secrets / credentials committed to source.

Regex-based, tuned to keep false positives manageable. Detected values are
masked in the report so the dashboard JSON never stores the full secret.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ..core.models import Finding, Project
from .base import Scanner

SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".lock",
    ".min.js", ".map", ".ico", ".woff", ".woff2", ".ttf",
}

# (id, severity, regex, title)
RULES: list[tuple[str, str, re.Pattern, str]] = [
    ("aws-access-key", "critical",
     re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
     "AWS access key ID"),
    ("github-token", "critical",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
     "GitHub personal access token"),
    ("slack-token", "high",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
     "Slack token"),
    ("google-api-key", "high",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     "Google API key"),
    ("private-key", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     "Private key material"),
    ("jwt", "medium",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     "Hardcoded JWT"),
    ("generic-assignment", "high",
     re.compile(
         r"""(?ix)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|
             client[_-]?secret)\b\s*[:=]\s*['"][^'"\s]{8,}['"]"""),
     "Hardcoded credential in assignment"),
]

# Used to filter obvious placeholders in generic-assignment matches.
PLACEHOLDERS = re.compile(
    r"(?i)(your[_-]?|example|changeme|placeholder|xxx+|<.*>|\$\{|env\[|process\.env|os\.environ)"
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _mask(value: str) -> str:
    value = value.strip("'\"")
    if len(value) <= 8:
        return value[0] + "***"
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


class SecretsScanner(Scanner):
    name = "secrets"
    description = "Detects hardcoded credentials and key material in source."

    def scan(self, project: Project) -> list[Finding]:
        findings: list[Finding] = []
        for path in project.iter_files():
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            rel = project.rel(path)
            for lineno, line in enumerate(lines, 1):
                if len(line) > 4000:
                    continue
                for rule_id, sev, pattern, title in RULES:
                    m = pattern.search(line)
                    if not m:
                        continue
                    matched = m.group(0)
                    if rule_id == "generic-assignment":
                        if PLACEHOLDERS.search(line):
                            continue
                        # require some entropy to avoid catching "password=password"
                        quoted = re.search(r"['\"]([^'\"]{8,})['\"]", line)
                        if quoted and _shannon_entropy(quoted.group(1)) < 3.0:
                            continue
                    findings.append(Finding(
                        scanner=self.name,
                        severity=sev,
                        title=title,
                        description=f"Potential secret: {_mask(matched)}",
                        file=rel,
                        line=lineno,
                        vulnerability_id=rule_id,
                        recommendation=(
                            "Remove the secret from source, rotate it immediately, "
                            "and load it from an environment variable or secret manager."
                        ),
                    ))
        return findings
