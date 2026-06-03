import { afterEach, beforeEach, describe, expect, it } from "vitest";
import os from "node:os";
import path from "node:path";
import { promises as fs } from "node:fs";
import {
  resolveTranscriptDirs,
  scrubTranscriptDirs,
  scrubTranscriptFile,
} from "./transcript-redaction.js";

let tmpRoot: string;

beforeEach(async () => {
  tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), "transcript-redact-"));
});

afterEach(async () => {
  await fs.rm(tmpRoot, { recursive: true, force: true });
});

function opts() {
  return {
    quarantineDir: path.join(tmpRoot, "quarantine"),
    auditLog: path.join(tmpRoot, "audit.ndjson"),
  };
}

describe("scrubTranscriptFile", () => {
  it("redacts an inline git remote PAT inside a jsonl line and keeps valid JSON", async () => {
    const pat = "ghp_" + "z".repeat(40);
    const file = path.join(tmpRoot, "session.jsonl");
    const line = {
      type: "tool_result",
      content: `origin\thttps://x-access-token:${pat}@github.com/axelweichert/paperclip.git (fetch)`,
    };
    await fs.writeFile(file, JSON.stringify(line) + "\n");

    const res = await scrubTranscriptFile(file, opts());
    expect(res.changed).toBe(true);

    const after = await fs.readFile(file, "utf8");
    expect(after).not.toContain(pat);
    expect(after).toMatch(/\*\*\*REDACTED:/);
    // Still parseable JSON per line.
    const parsed = JSON.parse(after.trim());
    expect(parsed.type).toBe("tool_result");
  });

  it("redacts env-var dumps (GITHUB_TOKEN / CLOUDFLARE_API_TOKEN / cfu_)", async () => {
    const file = path.join(tmpRoot, "env.jsonl");
    const dump = "GITHUB_TOKEN=ghp_" + "a".repeat(40) + " CLOUDFLARE_API_TOKEN=cfu_v1-aa-bb-cc-dd-ee";
    await fs.writeFile(file, JSON.stringify({ type: "stdout", text: dump }) + "\n");

    const res = await scrubTranscriptFile(file, opts());
    expect(res.changed).toBe(true);
    const after = await fs.readFile(file, "utf8");
    expect(after).not.toContain("ghp_a");
    expect(after).not.toContain("cfu_v1-aa-bb-cc-dd-ee");
  });

  it("quarantines the original and writes an audit record on a hit", async () => {
    const file = path.join(tmpRoot, "s.jsonl");
    await fs.writeFile(file, JSON.stringify({ text: "GH_X=ghp_" + "q".repeat(40) }) + "\n");

    await scrubTranscriptFile(file, opts());

    const quarantined = await fs.readdir(opts().quarantineDir);
    expect(quarantined.length).toBe(1);
    const audit = await fs.readFile(opts().auditLog, "utf8");
    const record = JSON.parse(audit.trim());
    expect(record.file).toBe(file);
    expect(record.originalSha256).toBeTruthy();
    expect(record.redactedSha256).not.toBe(record.originalSha256);
  });

  it("scrubs a naked high-entropy token with no prefix or label (WEI-222 F1)", async () => {
    // No ghp_/cfu_/TOKEN= marker — only redactSecrets()' HIGH_ENTROPY_RE would
    // catch it. The pre-check must still let it through to the filter.
    const token = "aB3dE7fG9hJ2kL5mN8pQ1rS4tU6vW0xYz7cD1eF4gH";
    expect(token.length).toBeGreaterThanOrEqual(40);
    const file = path.join(tmpRoot, "naked.jsonl");
    const line = JSON.stringify({ type: "tool_result", content: `value=${token}` }) + "\n";
    await fs.writeFile(file, line);

    const res = await scrubTranscriptFile(file, opts());
    expect(res.changed).toBe(true);
    const after = await fs.readFile(file, "utf8");
    expect(after).not.toContain(token);
    expect(after).toMatch(/\*\*\*REDACTED:high_entropy/);
  });

  it("does not touch a clean transcript file", async () => {
    const file = path.join(tmpRoot, "clean.jsonl");
    const content = JSON.stringify({ type: "user", text: "hello world, no secrets here" }) + "\n";
    await fs.writeFile(file, content);

    const res = await scrubTranscriptFile(file, opts());
    expect(res.changed).toBe(false);
    expect(await fs.readFile(file, "utf8")).toBe(content);
  });

  it("dry-run reports a hit without modifying the file or quarantine", async () => {
    const file = path.join(tmpRoot, "dry.jsonl");
    const original = JSON.stringify({ text: "GH_X=ghp_" + "d".repeat(40) }) + "\n";
    await fs.writeFile(file, original);

    const res = await scrubTranscriptFile(file, { ...opts(), dryRun: true });
    expect(res.changed).toBe(true);
    expect(await fs.readFile(file, "utf8")).toBe(original);
    await expect(fs.readdir(opts().quarantineDir)).rejects.toThrow();
  });
});

describe("scrubTranscriptDirs", () => {
  it("walks nested projects subdirs and counts redactions", async () => {
    const sub = path.join(tmpRoot, "projects", "-home-paperclip-dev");
    await fs.mkdir(sub, { recursive: true });
    await fs.writeFile(path.join(sub, "a.jsonl"), JSON.stringify({ text: "GH=ghp_" + "x".repeat(40) }) + "\n");
    await fs.writeFile(path.join(sub, "b.jsonl"), JSON.stringify({ text: "nothing secret" }) + "\n");

    const summary = await scrubTranscriptDirs([path.join(tmpRoot, "projects")], opts());
    expect(summary.processedFiles).toBe(2);
    expect(summary.redactedFiles).toBe(1);
  });

  it("skips files unchanged since the last sweep via the mtime/size cache (WEI-222 F2)", async () => {
    const dir = path.join(tmpRoot, "projects");
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(path.join(dir, "clean.jsonl"), JSON.stringify({ text: "nothing here" }) + "\n");

    const cache = new Map();
    const first = await scrubTranscriptDirs([dir], opts(), { cache });
    expect(first.processedFiles).toBe(1);
    expect(first.skippedFiles).toBe(0);

    // Same cache, file untouched -> the second sweep reads nothing.
    const second = await scrubTranscriptDirs([dir], opts(), { cache });
    expect(second.processedFiles).toBe(0);
    expect(second.skippedFiles).toBe(1);
  });

  it("skips transcripts modified within the recent-write window (WEI-222 F3)", async () => {
    const dir = path.join(tmpRoot, "projects");
    await fs.mkdir(dir, { recursive: true });
    const file = path.join(dir, "live.jsonl");
    await fs.writeFile(file, JSON.stringify({ text: "GH=ghp_" + "x".repeat(40) }) + "\n");
    const st = await fs.stat(file);

    // Clock pinned just after the file's mtime -> inside the 5s active-writer
    // window, so the live transcript is left alone.
    const skipped = await scrubTranscriptDirs([dir], opts(), {
      skipRecentMs: 5_000,
      now: () => st.mtimeMs + 1_000,
    });
    expect(skipped.processedFiles).toBe(0);
    expect(skipped.skippedFiles).toBe(1);
    expect(await fs.readFile(file, "utf8")).toContain("ghp_x");

    // Clock advanced past the window -> the (now-quiescent) file is scrubbed.
    const scrubbed = await scrubTranscriptDirs([dir], opts(), {
      skipRecentMs: 5_000,
      now: () => st.mtimeMs + 10_000,
    });
    expect(scrubbed.processedFiles).toBe(1);
    expect(scrubbed.redactedFiles).toBe(1);
    expect(await fs.readFile(file, "utf8")).not.toContain("ghp_x");
  });
});

describe("resolveTranscriptDirs", () => {
  it("includes CLAUDE_CONFIG_DIR/projects and ~/.claude/projects", () => {
    const dirs = resolveTranscriptDirs({ CLAUDE_CONFIG_DIR: "/cfg", HOME: "/home/u" } as NodeJS.ProcessEnv);
    expect(dirs).toContain(path.resolve("/cfg", "projects"));
    expect(dirs).toContain(path.resolve("/home/u", ".claude", "projects"));
  });
});
