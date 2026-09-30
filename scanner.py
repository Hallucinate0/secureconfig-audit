import json
import re
from pathlib import Path
from typing import Iterable, List

from .models import Finding


SECRET_PATTERNS = [
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GENERIC_API_KEY", re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"
    )),
    ("PASSWORD_VALUE", re.compile(
        r"(?i)\bpassword\b\s*[:=]\s*['\"]?[^'\"\s]{8,}"
    )),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

TEXT_EXTENSIONS = {
    ".env", ".ini", ".cfg", ".conf", ".txt", ".yaml", ".yml",
    ".json", ".toml", ".properties"
}


def _finding(rule, severity, path, line, message):
    return Finding(rule, severity, str(path), line, message)


def scan_text(path: Path, text: str) -> List[Finding]:
    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(_finding(
                    rule, "high", path, number,
                    "Potential hard-coded secret or credential detected."
                ))
                break

        if re.search(r"(?i)\bhttp://(?!localhost\b)", line):
            findings.append(_finding(
                "INSECURE_HTTP", "medium", path, number,
                "Insecure HTTP URL detected; prefer HTTPS."
            ))

        if re.search(r"(?i)\b(?:debug|development_mode)\b\s*[:=]\s*(?:true|1|yes|on)\b", line):
            findings.append(_finding(
                "DEBUG_ENABLED", "high", path, number,
                "Debug/development mode appears to be enabled."
            ))

        if re.search(r"(?i)\b(?:allow_all|allow_origins)\b\s*[:=]\s*[*'\"]?\s*\*[*'\"]?", line):
            findings.append(_finding(
                "PERMISSIVE_ORIGINS", "medium", path, number,
                "Configuration appears to allow requests from all origins."
            ))

    return findings


def scan_json(path: Path, text: str) -> List[Finding]:
    findings = scan_text(path, text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return findings

    def walk(value, key_path=""):
        if isinstance(value, dict):
            for key, child in value.items():
                current = f"{key_path}.{key}" if key_path else key
                if isinstance(child, bool) and child is True and key.lower() in {
                    "debug", "development", "insecure"
                }:
                    findings.append(_finding(
                        "UNSAFE_BOOLEAN", "high", path, 1,
                        f"Unsafe boolean setting enabled: {current}"
                    ))
                walk(child, current)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{key_path}[{index}]")

    walk(data)
    return findings


def scan_file(path: Path) -> List[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    if path.suffix.lower() == ".json":
        return scan_json(path, text)
    return scan_text(path, text)


def iter_files(target: Path) -> Iterable[Path]:
    if target.is_file():
        yield target
        return

    ignored = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules"}
    for path in target.rglob("*"):
        if path.is_file() and path.parent.name not in ignored:
            if path.suffix.lower() in TEXT_EXTENSIONS or path.name == ".env":
                yield path


def scan(target: str) -> List[Finding]:
    path = Path(target)
    findings = []
    for file_path in iter_files(path):
        findings.extend(scan_file(file_path))
    return findings
