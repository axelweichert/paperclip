import { describe, expect, it } from "vitest";
import { redactSecrets } from "./secret-redaction.js";

describe("redactSecrets — GitHub tokens", () => {
  const cases: Array<[string, string]> = [
    ["ghp_", "ghp_d0lJ" + "x".repeat(36)],
    ["github_pat", "github_pat_11ABCDEFG0" + "y".repeat(50) + "_" + "z".repeat(30)],
    ["gho", "gho_" + "a".repeat(36)],
    ["ghu", "ghu_" + "b".repeat(36)],
    ["ghs", "ghs_" + "c".repeat(36)],
    ["ghr", "ghr_" + "d".repeat(36)],
  ];

  for (const [label, token] of cases) {
    it(`redacts ${label} tokens to a marker`, () => {
      const text = `before ${token} after`;
      const out = redactSecrets(text);
      expect(out).not.toContain(token);
      expect(out).toMatch(/\*\*\*REDACTED:/);
    });
  }

  it("redacts the prefix tag in the marker", () => {
    const out = redactSecrets("X ghp_" + "Q".repeat(40) + " Y");
    expect(out).toContain("***REDACTED:ghp***");
  });

  it("redacts multiple tokens in one line", () => {
    const t1 = "ghp_" + "1".repeat(40);
    const t2 = "ghs_" + "2".repeat(40);
    const out = redactSecrets(`${t1} ${t2}`);
    expect(out).not.toContain(t1);
    expect(out).not.toContain(t2);
  });
});

describe("redactSecrets — Cloudflare Access tokens", () => {
  it("redacts client_secret hex when adjacent to label", () => {
    const hex = "0".repeat(32) + "ab".repeat(16);
    const text = `client_secret=${hex}`;
    const out = redactSecrets(text);
    expect(out).not.toContain(hex);
    expect(out).toContain("***REDACTED:cf_access***");
  });

  it("redacts CF-Access-Client-Secret header value", () => {
    const hex = "f".repeat(64);
    const text = `CF-Access-Client-Secret: ${hex}`;
    const out = redactSecrets(text);
    expect(out).not.toContain(hex);
  });

  it("does NOT redact a bare 64-hex string with no adjacent label", () => {
    // SHA-256 digest, no marker — high-entropy branch may still hit, see test below
    const hex = "0123456789abcdef".repeat(4);
    const out = redactSecrets(`digest ${hex} end`);
    // CF marker should not have fired (no client_secret label).
    // High-entropy fallback covers hex-only strings of length 64 because they are alnum.
    expect(out).toContain("***REDACTED:high_entropy***");
    expect(out).not.toContain("cf_access");
  });
});

describe("redactSecrets — Cloudflare API tokens (cfu_)", () => {
  it("redacts a cfu_ API token", () => {
    const token = "cfu_" + "Ab3xYz9".repeat(6); // hyphen/underscore-class, >8 chars
    const out = redactSecrets(`token ${token} end`);
    expect(out).not.toContain(token);
    expect(out).toContain("***REDACTED:cf_api***");
  });

  it("redacts a cfu_ token containing hyphens (escapes the high-entropy pass)", () => {
    const token = "cfu_v1-0-aaaa-bbbb-cccc-dddd";
    const out = redactSecrets(`CLOUDFLARE_API_TOKEN=${token}`);
    expect(out).not.toContain(token);
    expect(out).toMatch(/\*\*\*REDACTED:/);
  });
});

describe("redactSecrets — inline URL credentials", () => {
  it("redacts x-access-token:<PAT>@github.com from git remote output", () => {
    const pat = "ghp_" + "r".repeat(40);
    const text = `https://x-access-token:${pat}@github.com/axelweichert/paperclip.git`;
    const out = redactSecrets(text);
    expect(out).not.toContain(pat);
    expect(out).toContain("x-access-token:");
    expect(out).toContain("@github.com");
    expect(out).toMatch(/\*\*\*REDACTED:/);
  });

  it("redacts a SHORT, low-entropy URL password the entropy pass would miss", () => {
    const text = "postgres://app:hunter2@db.internal:5432/main";
    const out = redactSecrets(text);
    expect(out).not.toContain("hunter2");
    expect(out).toContain("postgres://app:***REDACTED:url_credential***@");
  });

  it("is idempotent on an already-redacted URL credential", () => {
    const once = redactSecrets("https://u:s3cr3tpw@host/x");
    const twice = redactSecrets(once);
    expect(twice).toBe(once);
  });
});

describe("redactSecrets — labeled env-var secrets", () => {
  it("redacts GITHUB_TOKEN=<value> env dumps", () => {
    const text = "GITHUB_TOKEN=ghp_" + "q".repeat(40);
    const out = redactSecrets(text);
    expect(out).not.toContain("ghp_q");
    expect(out).toContain("GITHUB_TOKEN=");
    expect(out).toMatch(/\*\*\*REDACTED:/);
  });

  it("redacts a token whose KEY has a suffix (TOKEN not at the end)", () => {
    const text = "GITHUB_TOKEN_AXELWEICHERTVB=abc-def-ghi-jkl-mno-pqr";
    const out = redactSecrets(text);
    expect(out).not.toContain("abc-def-ghi-jkl-mno-pqr");
    expect(out).toContain("GITHUB_TOKEN_AXELWEICHERTVB=");
    expect(out).toContain("***REDACTED:env_secret***");
  });

  it("redacts CLOUDFLARE_API_TOKEN values", () => {
    const text = 'CLOUDFLARE_API_TOKEN: "some-cf-api-token-value-1234"';
    const out = redactSecrets(text);
    expect(out).not.toContain("some-cf-api-token-value-1234");
    expect(out).toMatch(/\*\*\*REDACTED:/);
  });

  it("leaves a benign non-secret KEY=value alone", () => {
    const text = "LOG_LEVEL=debug";
    expect(redactSecrets(text)).toBe(text);
  });
});

describe("redactSecrets — generic high-entropy", () => {
  it("redacts a >=40 char [A-Za-z0-9_] string", () => {
    const blob = "AbcDef0123_GhiJkl4567MnoPqr8901StuVwxYz2";
    expect(blob.length).toBeGreaterThanOrEqual(40);
    const out = redactSecrets(`x ${blob} y`);
    expect(out).not.toContain(blob);
    expect(out).toContain("***REDACTED:high_entropy***");
  });

  it("leaves a 39-char alnum string alone", () => {
    const blob = "A".repeat(39);
    const out = redactSecrets(`x ${blob} y`);
    expect(out).toContain(blob);
  });

  it("leaves a long all-digit string alone (looks like an ID)", () => {
    const blob = "1".repeat(60);
    const out = redactSecrets(blob);
    expect(out).toBe(blob);
  });

  it("leaves a long single-character run alone", () => {
    const blob = "a".repeat(60);
    const out = redactSecrets(blob);
    expect(out).toBe(blob);
  });

  it("property: any >=40 char alnum run with >=10 distinct chars and <=90% digits is redacted", () => {
    const alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
    // Deterministic PRNG so the test is repeatable.
    let seed = 1337;
    const rand = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
    for (let trial = 0; trial < 100; trial++) {
      const len = 40 + Math.floor(rand() * 40);
      let s = "";
      const used = new Set<string>();
      while (s.length < len) {
        const c = alphabet[Math.floor(rand() * alphabet.length)]!;
        s += c;
        used.add(c);
      }
      // Reject draws that the redactor would consider low-entropy.
      if (used.size < 10) continue;
      const digitFrac = (s.match(/\d/g)?.length ?? 0) / s.length;
      if (digitFrac > 0.9) continue;

      const out = redactSecrets(`pre ${s} post`);
      expect(out).not.toContain(s);
    }
  });
});

describe("redactSecrets — leaves benign text alone", () => {
  it("returns short strings unchanged", () => {
    expect(redactSecrets("hello world")).toBe("hello world");
  });

  it("returns empty input unchanged", () => {
    expect(redactSecrets("")).toBe("");
  });

  it("preserves redaction markers on second pass", () => {
    const once = redactSecrets("ghp_" + "z".repeat(40));
    const twice = redactSecrets(once);
    expect(twice).toBe(once);
  });
});
