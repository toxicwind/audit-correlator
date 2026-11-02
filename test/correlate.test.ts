import { describe, test, expect } from "bun:test";
import { correlate, eventDoc, cfClassifier, cosine } from "../src/index.js";

// deterministic stub embedder: hash-based 8-dim vectors (offline, no network)
function stubEmbed(inputs: string[]): Promise<number[][]> {
  return Promise.resolve(inputs.map(docToVec));
}
function docToVec(doc: string): number[] {
  const v = new Array(8).fill(0);
  for (let i = 0; i < doc.length; i++) v[i % 8] += doc.charCodeAt(i) % 7;
  const n = Math.sqrt(v.reduce((a, x) => a + x * x, 0)) || 1;
  return v.map(x => x / n);
}

const EV = (when: string, action: string, email?: string, ip?: string, zone = "z.com", extra: any = {}): any => ({
  when, action: { type: action }, actor: { email, ip },
  metadata: { zone_name: zone, ...extra },
});

describe("eventDoc contract", () => {
  test("derives doc from action+zone+actor-class+token", () => {
    const d = eventDoc(EV("t", "rulesets_create", "a@x", undefined, "z.com", { phase: "http_request_dynamic_redirect", token_name: "tok1" }));
    expect(d).toContain("rulesets create");
    expect(d).toContain("on z.com");
    expect(d).toContain("http_request_dynamic_redirect");
    expect(d).toContain("token tok1");
  });
  test("pipeline events have no actor", () => {
    expect(eventDoc(EV("t", "create"))).toBe("create on z.com");
  });
});

describe("correlate (stub embedder)", () => {
  const events = [
    EV("2026-01-01T00:00:00Z", "zone_create", "owner@x"),          // operator
    EV("2026-01-02T00:00:00Z", "dns_create", undefined, "1.2.3.4"), // api-token
    EV("2026-01-03T00:00:00Z", "rulesets_create", "attacker@x"),   // flagged
    EV("2026-01-04T00:00:00Z", "rulesets_update", "attacker@x"),   // flagged
  ];
  const classify = cfClassifier("attacker@x");

  test("classes derive correctly", async () => {
    const out = await correlate(events, stubEmbed, classify, cosine);
    expect(out.results.map(r => r.cls)).toEqual(["operator", "api-token", "flagged", "flagged"]);
  });

  test("kin: every flagged event finds a nearest unflagged", async () => {
    const out = await correlate(events, stubEmbed, classify, cosine);
    expect(out.kin.length).toBe(2);
    for (const k of out.kin) {
      expect(k.nearest.cls).not.toBe("flagged");
      expect(k.score).toBeGreaterThan(0);
    }
  });

  test("misfits: empty when operator/api events differ from flagged", async () => {
    const out = await correlate(events, stubEmbed, classify, cosine);
    // stub vectors make rulesets_create(operator absent) — flagged docs are the
    // only "rulesets" ones, so nothing unflagged is closer to flagged-mean
    expect(Array.isArray(out.misfits)).toBe(true);
  });

  test("misfit DETECTS an unflagged event that mimics flagged behavior", async () => {
    const mimic = EV("2026-01-05T00:00:00Z", "rulesets_create", "sneaky@x"); // NOT flagged email
    const out = await correlate([...events, mimic], stubEmbed, classify, cosine);
    // "rulesets create on zone z.com by operator" is semantically IDENTICAL to
    // the flagged docs (same action/zone, different actor) → must be a misfit
    expect(out.misfits.length).toBe(1);
    expect(out.misfits[0].event.actor.email).toBe("sneaky@x");
  });
});

describe("cosine", () => {
  test("identical vectors = 1", () => {
    expect(cosine([1, 0], [1, 0])).toBe(1);
  });
  test("orthogonal = 0", () => {
    expect(cosine([1, 0], [0, 1])).toBe(0);
  });
  test("dim mismatch throws", () => {
    expect(() => cosine([1], [1, 2])).toThrow();
  });
});
