#!/usr/bin/env python3
"""
OWL-174 / WEI-218 retroactive redaction for Paperclip run-logs AND Claude transcripts.

For each matching file under --scan-dir (default glob *.ndjson for run-logs; pass
--glob '*.jsonl' to scrub Claude transcripts under ~/.claude/projects), scan for
secret patterns. On match:
  1. Copy the original file to quarantine dir (preserving relative path) for audit.
  2. Rewrite the file in-place with all token matches replaced by ***REDACTED:<tag>***
  3. Append a JSON record to the audit log with original sha256, redacted sha256, and match count.

Patterns (must mirror server/src/services/secret-redaction.ts):
  - Inline URL credentials: scheme://user:secret@host (password redacted even when low-entropy)
  - GitHub: ghp_, github_pat_, gho_, ghu_, ghs_, ghr_ followed by [A-Za-z0-9_]{20,255}
  - Cloudflare API token: cfu_ followed by [A-Za-z0-9_-]{8,255}
  - Labeled env-var secret: KEY containing TOKEN/SECRET/PASSWORD/API_KEY/... = VALUE
  - Cloudflare Access service token client_secret: 64-hex chars adjacent to "client_secret"/"CF-Access-Client-Secret"
  - Generic high-entropy: >=40 chars of [A-Za-z0-9_], rejected if mostly one char or all-digits

The content lives inside a JSON-escaped string (the ndjson "chunk" field, or a
transcript jsonl line). We operate on the raw line text — pattern hits work the same
whether content is in JSON-escape form or not, because the secret characters survive
JSON string-escaping (they're all ASCII alnum + underscore + hyphen).
"""
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

GITHUB_PREFIXES = ("ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_")

# Token: prefix + 20..255 alnum/underscore (covers classic 40 char + fine-grained 80+ char).
GITHUB_RE = re.compile(
    r"(ghp_|github_pat_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{20,255}"
)

# Cloudflare API token (user-scoped form is prefixed cfu_).
CF_API_TOKEN_RE = re.compile(r"cfu_[A-Za-z0-9_-]{8,255}")

# Inline URL credentials: scheme://user:secret@host — redact the password segment.
URL_CREDENTIAL_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@"
)

# Labeled env-var / KEY=VALUE secret whose key name contains a secret keyword anywhere.
LABELED_SECRET_RE = re.compile(
    r"\b([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)[A-Z0-9_]*)"
    r"(\s*[:=]\s*)([\"']?)([^\s\"']{6,})\3"
)

# Cloudflare Access service-token client_secret = 64 lowercase hex.
# Match only when adjacent to a known marker so we don't shred SHA-256 hashes.
CF_ACCESS_RE = re.compile(
    r"(CF-Access-Client-Secret|client_secret|access_client_secret)"
    r"([\"':=\s]+)([a-f0-9]{64})"
)

# Generic high-entropy >=40 char [A-Za-z0-9_].
# Used only when GITHUB_RE / CF_ACCESS_RE didn't match.
HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9_]{40,255}")


def is_low_entropy(s: str) -> bool:
    # Reject if it's mostly digits (looks like an ID) or mostly one character.
    if len(set(s)) < 10:
        return True
    digits = sum(c.isdigit() for c in s)
    if digits / len(s) > 0.9:
        return True
    return False


def _already_redacted(value: str) -> bool:
    return "REDACTED" in value


def redact_text(text: str) -> tuple[str, int]:
    hits = 0

    def url_sub(m):
        nonlocal hits
        if _already_redacted(m.group(3)):
            return m.group(0)
        hits += 1
        return f"{m.group(1)}{m.group(2)}:***REDACTED:url_credential***@"

    out = URL_CREDENTIAL_RE.sub(url_sub, text)

    def gh_sub(m):
        nonlocal hits
        hits += 1
        prefix = m.group(1).rstrip("_")
        return f"***REDACTED:{prefix}***"

    out = GITHUB_RE.sub(gh_sub, out)

    def cf_api_sub(m):
        nonlocal hits
        hits += 1
        return "***REDACTED:cf_api***"

    out = CF_API_TOKEN_RE.sub(cf_api_sub, out)

    def labeled_sub(m):
        nonlocal hits
        if _already_redacted(m.group(4)):
            return m.group(0)
        hits += 1
        return f"{m.group(1)}{m.group(2)}{m.group(3)}***REDACTED:env_secret***{m.group(3)}"

    out = LABELED_SECRET_RE.sub(labeled_sub, out)

    def cf_sub(m):
        nonlocal hits
        hits += 1
        return f"{m.group(1)}{m.group(2)}***REDACTED:cf_access***"

    out = CF_ACCESS_RE.sub(cf_sub, out)

    def he_sub(m):
        nonlocal hits
        s = m.group(0)
        if is_low_entropy(s):
            return s
        # Skip strings already part of a redaction marker.
        if s.startswith("REDACTED"):
            return s
        hits += 1
        return "***REDACTED:high_entropy***"

    out = HIGH_ENTROPY_RE.sub(he_sub, out)
    return out, hits


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    # --scan-dir is preferred; --run-logs-dir kept for backwards compatibility.
    parser.add_argument("--scan-dir", "--run-logs-dir", dest="scan_dir", required=True)
    parser.add_argument(
        "--glob",
        default="*.ndjson",
        help="filename glob to scan (default *.ndjson; use *.jsonl for ~/.claude/projects transcripts)",
    )
    parser.add_argument("--quarantine-dir", required=True)
    parser.add_argument("--audit-log", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    run_logs = Path(args.scan_dir)
    quarantine = Path(args.quarantine_dir)
    audit = Path(args.audit_log)
    quarantine.mkdir(parents=True, exist_ok=True)
    audit.parent.mkdir(parents=True, exist_ok=True)

    processed = 0
    redacted = 0
    total_hits = 0

    needle_patterns = [re.compile(re.escape(p)) for p in GITHUB_PREFIXES]
    # Fast pre-check markers covering every pattern above.
    hint_marker = re.compile(
        r"client_secret|CF-Access-Client-Secret|cfu_"
        r"|://[^/\s:@]+:[^/\s@]+@"
        r"|(?:TOKEN|SECRET|PASSWORD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*\s*[:=]",
        re.IGNORECASE,
    )

    with audit.open("a") as audit_fp:
        for path in run_logs.rglob(args.glob):
            processed += 1
            try:
                raw = path.read_bytes()
            except FileNotFoundError:
                continue

            text = raw.decode("utf-8", errors="replace")

            # Fast pre-check: only scan files that contain a likely secret marker.
            has_gh = any(p.search(text) for p in needle_patterns)
            has_hint = bool(hint_marker.search(text))
            if not (has_gh or has_hint):
                continue

            new_text, hits = redact_text(text)
            if hits == 0 or new_text == text:
                continue

            redacted += 1
            total_hits += hits

            rel = path.relative_to(run_logs)
            quarantine_path = quarantine / rel
            quarantine_path.parent.mkdir(parents=True, exist_ok=True)

            original_sha = sha256_bytes(raw)
            new_bytes = new_text.encode("utf-8")
            new_sha = sha256_bytes(new_bytes)

            if not args.dry_run:
                # Copy original to quarantine.
                quarantine_path.write_bytes(raw)
                # Rewrite original in-place (atomic via temp + rename).
                tmp = path.with_suffix(path.suffix + ".redact-tmp")
                tmp.write_bytes(new_bytes)
                os.replace(tmp, path)

            audit_fp.write(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "file": str(rel),
                "original_sha256": original_sha,
                "redacted_sha256": new_sha,
                "matches": hits,
                "original_bytes": len(raw),
                "redacted_bytes": len(new_bytes),
                "dry_run": args.dry_run,
            }) + "\n")

    print(json.dumps({
        "processed_files": processed,
        "redacted_files": redacted,
        "total_redactions": total_hits,
        "dry_run": args.dry_run,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
