/**
 * Secret redaction for run-log content.
 *
 * Defence-in-depth filter applied at the platform run-log writer so agent
 * stdout/stderr that includes credentials never lands in plaintext under
 * data/run-logs/. Recurrences of OWL-66 / OWL-174 (GitHub PATs) and
 * SEC-INC 2026-05 (Cloudflare Access tokens) all trace back to the same
 * class of failure: secrets reaching the log path with no central guard.
 *
 * The filter runs on the raw chunk string before JSON serialization.
 * It is intentionally aggressive: false-positive redactions are acceptable;
 * a leaked secret is not.
 */

const GITHUB_TOKEN_RE =
  /(ghp_|github_pat_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{20,255}/g;

// Cloudflare API token. The user-scoped form is prefixed `cfu_`; we redact the
// whole token. Catches `git remote`/env dumps that print `CLOUDFLARE_API_TOKEN=cfu_…`.
// (Classic 40-char prefix-less CF API tokens are left to LABELED_SECRET_RE /
//  HIGH_ENTROPY_RE so we don't shred git SHAs and UUIDs.)
const CF_API_TOKEN_RE = /cfu_[A-Za-z0-9_-]{8,255}/g;

// Inline URL credentials: `scheme://user:secret@host`. Redact the password
// segment even when it is below the high-entropy threshold (e.g. short PATs or
// `x-access-token:<TOKEN>@github.com` from `git remote -v`).
const URL_CREDENTIAL_RE =
  /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s@]+)@/g;

// Labeled secret in an env-var / KEY=VALUE / "KEY": "VALUE" dump. Matches any
// key whose name contains TOKEN/SECRET/PASSWORD/API_KEY/etc. anywhere (so
// `GITHUB_TOKEN_AXELWEICHERTVB=…` is covered, not just suffixes), and redacts
// the assigned value regardless of its entropy. Skips values already redacted.
const LABELED_SECRET_RE =
  /\b([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)[A-Z0-9_]*)(\s*[:=]\s*)(["']?)([^\s"']{6,})\3/g;

// Cloudflare Access service-token client_secret = 64-char lowercase hex.
// Only match adjacent to a known label so SHA-256 digests aren't shredded.
const CF_ACCESS_RE =
  /(CF-Access-Client-Secret|client_secret|access_client_secret)([\s"':=]+)([a-f0-9]{64})/gi;

// Generic high-entropy fallback: >=40 chars of [A-Za-z0-9_].
const HIGH_ENTROPY_RE = /[A-Za-z0-9_]{40,255}/g;

const REDACTION_MARKER_PREFIX = "***REDACTED:";

function isAlreadyRedacted(value: string): boolean {
  return value.includes("REDACTED");
}

function isLowEntropy(s: string): boolean {
  // Reject runs that are almost all one character or almost all digits —
  // those look like IDs/counters, not secrets.
  const unique = new Set(s).size;
  if (unique < 10) return true;
  let digits = 0;
  for (const c of s) if (c >= "0" && c <= "9") digits++;
  if (digits / s.length > 0.9) return true;
  return false;
}

export function redactSecrets(input: string): string {
  if (!input) return input;

  // Inline URL credentials first, so a low-entropy password is caught before the
  // generic passes (and so an embedded PAT is redacted exactly once).
  let out = input.replace(
    URL_CREDENTIAL_RE,
    (_match, scheme: string, user: string, secret: string) => {
      if (isAlreadyRedacted(secret)) return _match;
      return `${scheme}${user}:${REDACTION_MARKER_PREFIX}url_credential***@`;
    },
  );

  out = out.replace(GITHUB_TOKEN_RE, (_match, prefix: string) => {
    const tag = prefix.replace(/_$/, "");
    return `${REDACTION_MARKER_PREFIX}${tag}***`;
  });

  out = out.replace(CF_API_TOKEN_RE, () => `${REDACTION_MARKER_PREFIX}cf_api***`);

  out = out.replace(
    LABELED_SECRET_RE,
    (_match, key: string, sep: string, quote: string, value: string) => {
      // Already-redacted values (e.g. a GitHub PAT the GITHUB_TOKEN_RE pass
      // already tagged) keep their more specific marker.
      if (isAlreadyRedacted(value)) return _match;
      return `${key}${sep}${quote}${REDACTION_MARKER_PREFIX}env_secret***${quote}`;
    },
  );

  out = out.replace(CF_ACCESS_RE, (_match, label: string, sep: string) => {
    return `${label}${sep}${REDACTION_MARKER_PREFIX}cf_access***`;
  });

  out = out.replace(HIGH_ENTROPY_RE, (match: string) => {
    if (match.startsWith("REDACTED")) return match;
    if (isLowEntropy(match)) return match;
    return `${REDACTION_MARKER_PREFIX}high_entropy***`;
  });

  return out;
}
