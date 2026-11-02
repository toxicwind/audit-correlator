/**
 * audit-correlator/src/correlate.ts — semantic audit-log behavior correlation.
 *
 * Embeds audit events (bge-m3 via @forge/hf) and correlates ACTOR BEHAVIOR:
 *  - fingerprint(events, flag): mean behavioral vector per actor class
 *  - kin(events, flag): for each flagged event, nearest UNFLAGGED event
 *  - misfits(events, flag): unflagged events semantically closest to the
 *    flagged class — the "behaves like the attacker but wasn't caught" set
 *
 * Event doc contract: "<action> <phase> on zone <z> by <derived actor class>
 * token <name>" — actor classes are DERIVED (operator/attacker/api-token/
 * pipeline), raw emails never embedded (privacy + tokenization noise).
 */
import type { EmbedOptions } from "./types.js";

export type AuditEvent = Record<string, any>;

export interface CorrelationResult {
  event: AuditEvent;
  doc: string;
  cls: string;
  scores: Record<string, number>;
}

/** Derive the actor class for one audit event. Override per source system. */
export type ActorClassifier = (e: AuditEvent) => string;

/** Default CF-shaped classifier; parameterize your flagged actor. */
export function cfClassifier(flaggedEmail: string): ActorClassifier {
  return (e: AuditEvent) => {
    const email = e.actor?.email;
    if (email === flaggedEmail) return "flagged";
    if (email) return "operator";
    if (e.actor?.ip) return "api-token";
    return "pipeline";
  };
}

/** Build the semantic document for one event. */
export function eventDoc(e: AuditEvent): string {
  const action = String(e.action?.type ?? e.action ?? "unknown").replace(/_/g, " ");
  const zone = e.metadata?.zone_name ?? e.metadata?.zone_tag ?? "";
  const phase = e.metadata?.phase ?? "";
  const token = e.metadata?.token_name ?? "";
  const repo = e.metadata?.repo ?? e.repo ?? "";
  const target = zone || repo;
  return [action, phase, target ? `on ${target}` : "", token ? `token ${token}` : ""]
    .filter(Boolean).join(" ").trim() || "unlabeled event";
}

function mean(vecs: number[][]): number[] {
  if (!vecs.length) return [];
  const dim = vecs[0].length;
  const m = new Array(dim).fill(0);
  for (const v of vecs) for (let i = 0; i < dim; i++) m[i] += v[i];
  const n = vecs.length;
  return m.map(x => x / n);
}

export interface CorrelateOutput {
  results: CorrelationResult[];
  misfits: CorrelationResult[];
  kin: Array<{ flagged: CorrelationResult; nearest: CorrelationResult; score: number }>;
}

/** Full correlation pass. embed = the embedMany fn (injected; forge hf client). */
export async function correlate(
  events: AuditEvent[],
  embed: (inputs: string[]) => Promise<number[][]>,
  classify: ActorClassifier,
  cosine: (a: number[], b: number[]) => number,
): Promise<CorrelateOutput> {
  const docs = events.map(eventDoc);
  const uniqDocs = [...new Set(docs)];
  const uniqVecs = await embed(uniqDocs);
  const index = new Map(uniqDocs.map((d, i) => [d, uniqVecs[i]] as const));
  const vecs = docs.map(d => index.get(d)!);

  const classes = events.map(classify);
  const byClass = new Map<string, number[][]>();
  classes.forEach((c, i) => {
    const a = byClass.get(c) ?? []; a.push(vecs[i]); byClass.set(c, a);
  });

  const flaggedCls = "flagged";
  const flaggedMean = mean(byClass.get(flaggedCls) ?? []);
  const otherMeans = new Map<string, number[]>();
  for (const [c, vecs_] of byClass) {
    if (c !== flaggedCls) otherMeans.set(c, mean(vecs_));
  }

  const results: CorrelationResult[] = events.map((e, i) => {
    const scores: Record<string, number> = {};
    if (flaggedMean.length) scores.flagged = cosine(vecs[i], flaggedMean);
    for (const [c, m] of otherMeans) scores[c] = cosine(vecs[i], m);
    return { event: e, doc: docs[i], cls: classes[i], scores };
  });

  // misfits: unflagged events whose nearest class mean is flagged
  const misfits = results.filter(r =>
    r.cls !== flaggedCls &&
    Object.entries(r.scores).every(([c, s]) => c === "flagged" || r.scores.flagged > s),
  );

  // kin: for each flagged event, nearest unflagged event
  const flaggedIdx = results.map((r, i) => r.cls === flaggedCls ? i : -1).filter(i => i >= 0);
  const kin = flaggedIdx.map(i => {
    let best = -1, bestScore = -2;
    for (let j = 0; j < results.length; j++) {
      if (classes[j] === flaggedCls) continue;
      const s = cosine(vecs[i], vecs[j]);
      if (s > bestScore) { bestScore = s; best = j; }
    }
    return best >= 0 ? { flagged: results[i], nearest: results[best], score: bestScore } : null;
  }).filter(Boolean) as Array<{ flagged: CorrelationResult; nearest: CorrelationResult; score: number }>;

  return { results, misfits, kin };
}
