/**
 * Secret redaction for Claude Code transcripts (`~/.claude/projects` `*.jsonl`).
 *
 * The run-log writer (run-log-store.ts) already routes every stdout/stderr chunk
 * through `redactSecrets()`. Claude Code transcripts, however, are written
 * *directly* by the harness and never pass through that guard, so credentials
 * surfaced in tool output — inline `https://x-access-token:<TOKEN>@github.com/…`
 * URLs from `git remote -v`, or env dumps like `GITHUB_TOKEN=…` /
 * `CLOUDFLARE_API_TOKEN=…` — persist there in cleartext (WEI-217 / WEI-218).
 *
 * This module is the missing guard for that persistence path. It reuses the same
 * `redactSecrets()` filter, applied to the raw `.jsonl` bytes: every secret we
 * match is ASCII alnum / `_` / `-`, so the pattern hits are identical whether the
 * value sits inside a JSON-escaped string or not, and the redaction markers
 * (`***REDACTED:…***`) are valid inside a JSON string, so rewriting in place keeps
 * the transcript parseable.
 *
 * On a hit the original file is copied to a quarantine dir for audit, rewritten
 * atomically, and a JSON record (original/redacted sha256 + byte counts) is
 * appended to an audit log — mirroring scripts/security/redact-run-logs.py.
 *
 * `startTranscriptRedactionSweeper()` wires this as a scrub-on-write guard: a
 * sweep at boot plus a short-interval periodic sweep. (A periodic sweep is used
 * rather than `fs.watch`, which is not reliably recursive on Linux; the fast
 * pre-check below means clean files are never rewritten, so the steady-state
 * cost is a cheap directory walk.)
 */
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { promises as fs } from "node:fs";
import { logger } from "../middleware/logger.js";
import { resolvePaperclipInstanceRoot } from "../home-paths.js";
import { redactSecrets } from "./secret-redaction.js";

export interface TranscriptScrubOptions {
  quarantineDir: string;
  auditLog: string;
  dryRun?: boolean;
}

export interface TranscriptScrubFileResult {
  file: string;
  changed: boolean;
  originalSha256?: string;
  redactedSha256?: string;
  originalBytes?: number;
  redactedBytes?: number;
}

export interface TranscriptScrubSummary {
  processedFiles: number;
  redactedFiles: number;
  dryRun: boolean;
}

// Cheap markers that indicate a file *might* contain a redactable secret, so we
// can skip reading/scrubbing the (vast majority of) clean transcript files.
const SECRET_HINT_RE =
  /ghp_|github_pat_|gho_|ghu_|ghs_|ghr_|cfu_|client_secret|CF-Access-Client-Secret|:\/\/[^/\s:@]+:[^/\s@]+@|(?:TOKEN|SECRET|PASSWORD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*\s*[:=]/;

function sha256(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

/**
 * Resolve the Claude transcript roots to scrub. `CLAUDE_CONFIG_DIR/projects`
 * when set (the Paperclip-managed config dir), otherwise the default
 * `~/.claude/projects`. Both are included when distinct.
 */
export function resolveTranscriptDirs(env: NodeJS.ProcessEnv = process.env): string[] {
  const dirs = new Set<string>();
  const configDir = env.CLAUDE_CONFIG_DIR?.trim();
  if (configDir) {
    dirs.add(path.resolve(configDir, "projects"));
  }
  dirs.add(path.resolve(env.HOME ?? os.homedir(), ".claude", "projects"));
  return [...dirs];
}

export function defaultTranscriptScrubOptions(): TranscriptScrubOptions {
  const base = path.resolve(resolvePaperclipInstanceRoot(), "data", "transcript-redaction");
  return {
    quarantineDir: path.join(base, "quarantine"),
    auditLog: path.join(base, "audit.ndjson"),
  };
}

async function walkJsonl(dir: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => null);
  if (!entries) return out;
  for (const entry of entries) {
    const name = entry.name;
    const full = path.join(dir, name);
    if (entry.isDirectory()) {
      out.push(...(await walkJsonl(full)));
    } else if (entry.isFile() && name.endsWith(".jsonl")) {
      out.push(full);
    }
  }
  return out;
}

/**
 * Scrub a single transcript file in place. Returns whether it changed. On a hit
 * the original is quarantined and an audit record is appended (unless dryRun).
 */
export async function scrubTranscriptFile(
  absPath: string,
  opts: TranscriptScrubOptions,
): Promise<TranscriptScrubFileResult> {
  let raw: Buffer;
  try {
    raw = await fs.readFile(absPath);
  } catch {
    return { file: absPath, changed: false };
  }

  const text = raw.toString("utf8");
  if (!SECRET_HINT_RE.test(text)) {
    return { file: absPath, changed: false };
  }

  const redacted = redactSecrets(text);
  if (redacted === text) {
    return { file: absPath, changed: false };
  }

  const newBytes = Buffer.from(redacted, "utf8");
  const result: TranscriptScrubFileResult = {
    file: absPath,
    changed: true,
    originalSha256: sha256(raw),
    redactedSha256: sha256(newBytes),
    originalBytes: raw.byteLength,
    redactedBytes: newBytes.byteLength,
  };

  if (!opts.dryRun) {
    // Quarantine the original (flattened name keeps the audit trail readable).
    await fs.mkdir(opts.quarantineDir, { recursive: true });
    const stamp = sha256(Buffer.from(absPath)).slice(0, 12);
    const quarantineName = `${path.basename(absPath)}.${stamp}.orig`;
    await fs.writeFile(path.join(opts.quarantineDir, quarantineName), raw);

    // Atomic in-place rewrite.
    const tmp = `${absPath}.redact-tmp`;
    await fs.writeFile(tmp, newBytes);
    await fs.rename(tmp, absPath);

    await fs.mkdir(path.dirname(opts.auditLog), { recursive: true });
    await fs.appendFile(
      opts.auditLog,
      JSON.stringify({
        ts: new Date().toISOString(),
        file: absPath,
        quarantine: quarantineName,
        originalSha256: result.originalSha256,
        redactedSha256: result.redactedSha256,
        originalBytes: result.originalBytes,
        redactedBytes: result.redactedBytes,
      }) + "\n",
    );
  }

  return result;
}

/** Scrub every `*.jsonl` under the given transcript roots. */
export async function scrubTranscriptDirs(
  dirs: string[],
  opts: TranscriptScrubOptions,
): Promise<TranscriptScrubSummary> {
  let processedFiles = 0;
  let redactedFiles = 0;
  for (const dir of dirs) {
    const files = await walkJsonl(dir);
    for (const file of files) {
      processedFiles++;
      const res = await scrubTranscriptFile(file, opts);
      if (res.changed) redactedFiles++;
    }
  }
  return { processedFiles, redactedFiles, dryRun: opts.dryRun === true };
}

export interface TranscriptRedactionSweeperHandle {
  stop(): void;
  sweepNow(): Promise<TranscriptScrubSummary>;
}

/**
 * Start the scrub-on-write guard: an immediate sweep plus a periodic sweep of
 * the Claude transcript roots. Gated by PAPERCLIP_TRANSCRIPT_REDACTION
 * (default on); set to "false"/"0" to disable. Best-effort — failures are
 * logged, never thrown.
 */
export function startTranscriptRedactionSweeper(options?: {
  dirs?: string[];
  scrubOptions?: TranscriptScrubOptions;
  intervalMs?: number;
  env?: NodeJS.ProcessEnv;
}): TranscriptRedactionSweeperHandle {
  const env = options?.env ?? process.env;
  const flag = (env.PAPERCLIP_TRANSCRIPT_REDACTION ?? "true").toLowerCase();
  const enabled = flag !== "false" && flag !== "0" && flag !== "off";

  const dirs = options?.dirs ?? resolveTranscriptDirs(env);
  const scrubOptions = options?.scrubOptions ?? defaultTranscriptScrubOptions();
  const intervalMs = options?.intervalMs ?? 30_000;

  const sweepNow = async (): Promise<TranscriptScrubSummary> => {
    try {
      const summary = await scrubTranscriptDirs(dirs, scrubOptions);
      if (summary.redactedFiles > 0) {
        logger.warn(
          { ...summary, dirs },
          "transcript redaction scrubbed secrets from Claude transcripts",
        );
      }
      return summary;
    } catch (err) {
      logger.error({ err, dirs }, "transcript redaction sweep failed");
      return { processedFiles: 0, redactedFiles: 0, dryRun: false };
    }
  };

  if (!enabled) {
    logger.info("transcript redaction sweeper disabled via PAPERCLIP_TRANSCRIPT_REDACTION");
    return { stop: () => {}, sweepNow };
  }

  void sweepNow();
  const timer = setInterval(() => void sweepNow(), intervalMs);
  // Don't keep the event loop alive for this background guard.
  timer.unref?.();
  logger.info({ dirs, intervalMs }, "transcript redaction sweeper started");

  return {
    stop: () => clearInterval(timer),
    sweepNow,
  };
}
