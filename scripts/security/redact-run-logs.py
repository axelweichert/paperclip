#!/usr/bin/env python3
"""
OWL-174 retroactive redaction for Paperclip run-logs.

For each .ndjson under data/run-logs/, scan for secret patterns.
On match:
  1. Copy the original file to quarantine dir (preserving relative path) for audit.
  2. Rewrite the file in-place with all token matches replaced by ***REDACTED:<prefix>***
  3. Append a JSON record to the audit log with original sha256, redacted sha256, and match count.

Patterns (must mirror redaction.ts):
  - GitHub: ghp_, github_pat_, gho_, ghu_, ghs_, ghr_ followed by [A-Za-z0-9_]{20,255}
  - Cloudflare Access service token client_secret: 64-hex chars adjacent to "client_secret"/"CF-Access-Client-Secret"
  - Generic high-entropy: >=40 chars of [A-Za-z0-9_], rejected if mostly one char or matches a known low-entropy header

For run-log redaction, the chunk content is a JSON-escaped string (since it lives inside an ndjson "chunk" field).
We operate on the raw line bytes — pattern hits work the same whether content is in JSON-escape form or not,
because the secret characters survive JSON string-escaping (they're all ASCII alnum + underscore).
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


def redact_text(text: str) -> tuple[str, int]:
    hits = 0

    def gh_sub(m):
        nonlocal hits
        hits += 1
        prefix = m.group(1).rstrip("_")
        return f"***REDACTED:{prefix}***"

    out = GITHUB_RE.sub(gh_sub, text)

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
    parser.add_argument("--run-logs-dir", required=True)
    parser.add_argument("--quarantine-dir", required=True)
    parser.add_argument("--audit-log", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    run_logs = Path(args.run_logs_dir)
    quarantine = Path(args.quarantine_dir)
    audit = Path(args.audit_log)
    quarantine.mkdir(parents=True, exist_ok=True)
    audit.parent.mkdir(parents=True, exist_ok=True)

    processed = 0
    redacted = 0
    total_hits = 0

    needle_patterns = [re.compile(re.escape(p)) for p in GITHUB_PREFIXES]
    cf_marker = re.compile(r"client_secret|CF-Access-Client-Secret", re.IGNORECASE)

    with audit.open("a") as audit_fp:
        for path in run_logs.rglob("*.ndjson"):
            processed += 1
            try:
                raw = path.read_bytes()
            except FileNotFoundError:
                continue

            text = raw.decode("utf-8", errors="replace")

            # Fast pre-check: only scan files that contain one of the prefixes/CF markers.
            has_gh = any(p.search(text) for p in needle_patterns)
            has_cf = bool(cf_marker.search(text))
            if not (has_gh or has_cf):
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
