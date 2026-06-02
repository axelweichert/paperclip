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

// Cloudflare Access service-token client_secret = 64-char lowercase hex.
// Only match adjacent to a known label so SHA-256 digests aren't shredded.
const CF_ACCESS_RE =
  /(CF-Access-Client-Secret|client_secret|access_client_secret)([\s"':=]+)([a-f0-9]{64})/gi;

// Generic high-entropy fallback: >=40 chars of [A-Za-z0-9_].
const HIGH_ENTROPY_RE = /[A-Za-z0-9_]{40,255}/g;

const REDACTION_MARKER_PREFIX = "***REDACTED:";

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

  let out = input.replace(GITHUB_TOKEN_RE, (_match, prefix: string) => {
    const tag = prefix.replace(/_$/, "");
    return `${REDACTION_MARKER_PREFIX}${tag}***`;
  });

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
