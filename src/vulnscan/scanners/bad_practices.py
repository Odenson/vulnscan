"""Flag risky / insecure coding patterns via lightweight pattern matching.

This is intentionally dependency-free (regex over source files). It is a
first-pass triage aid, not a replacement for a full SAST tool like Semgrep
or CodeQL. Patterns are conservative to keep false positives low.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..core.models import Finding, Project
from .base import Scanner

SOURCE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".rb", ".go",
    ".php", ".cs", ".c", ".cpp", ".sh",
}

# (id, severity, suffixes, regex, title, recommendation)
RULES: list[tuple] = [
    ("py-eval", "high", {".py"},
     re.compile(r"\beval\s*\("),
     "Use of eval()",
     "Avoid eval(); parse input explicitly or use ast.literal_eval for literals."),
    ("py-exec", "high", {".py"},
     re.compile(r"\bexec\s*\("),
     "Use of exec()",
     "Avoid exec() on dynamic input; it allows arbitrary code execution."),
    ("py-pickle", "medium", {".py"},
     re.compile(r"\bpickle\.loads?\s*\("),
     "Insecure deserialization with pickle",
     "Never unpickle untrusted data; use JSON or a safe serializer."),
    ("py-shell-true", "high", {".py"},
     re.compile(r"subprocess\.(?:run|call|Popen|check_output)\([^)]*shell\s*=\s*True"),
     "subprocess called with shell=True",
     "Pass an argument list and shell=False to avoid command injection."),
    ("py-yaml-load", "medium", {".py"},
     re.compile(r"yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)"),
     "Unsafe yaml.load()",
     "Use yaml.safe_load() to avoid arbitrary object construction."),
    ("py-md5", "low", {".py"},
     re.compile(r"hashlib\.(?:md5|sha1)\s*\("),
     "Weak hash algorithm (MD5/SHA1)",
     "Use SHA-256+ for integrity, and a KDF (bcrypt/argon2) for passwords."),
    ("js-eval", "high", {".js", ".jsx", ".ts", ".tsx"},
     re.compile(r"\beval\s*\("),
     "Use of eval()",
     "Avoid eval(); it enables code injection. Use JSON.parse / explicit logic."),
    ("js-inner-html", "medium", {".js", ".jsx", ".ts", ".tsx"},
     re.compile(r"\.innerHTML\s*="),
     "Direct innerHTML assignment (possible XSS)",
     "Use textContent or a sanitizer; avoid injecting unescaped HTML."),
    ("js-child-process", "medium", {".js", ".ts"},
     re.compile(r"child_process\.exec\s*\("),
     "child_process.exec() with shell",
     "Prefer execFile/spawn with an argument array to avoid command injection."),
    ("generic-http", "low", SOURCE_SUFFIXES,
     re.compile(r"https?://[^\s\"')]+", re.I),
     None,  # handled specially below
     None),
    ("tls-verify-off", "high", SOURCE_SUFFIXES,
     re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true", re.I),
     "TLS certificate verification disabled",
     "Re-enable certificate verification; disabling it allows MITM attacks."),
]


class BadPracticesScanner(Scanner):
    name = "bad-practices"
    description = "Flags insecure/risky coding patterns via static pattern matching."

    def scan(self, project: Project) -> list[Finding]:
        findings: list[Finding] = []
        for path in project.iter_files(SOURCE_SUFFIXES):
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            rel = project.rel(path)
            for lineno, line in enumerate(lines, 1):
                if len(line) > 2000:
                    continue  # skip minified/generated lines
                for rule_id, sev, suffixes, pattern, title, rec in RULES:
                    if path.suffix.lower() not in suffixes:
                        continue
                    if rule_id == "generic-http":
                        continue  # noisy; left disabled by default
                    if pattern.search(line):
                        findings.append(Finding(
                            scanner=self.name,
                            severity=sev,
                            title=title,
                            description=f"`{line.strip()[:160]}`",
                            file=rel,
                            line=lineno,
                            recommendation=rec,
                            vulnerability_id=rule_id,
                        ))
        return findings
