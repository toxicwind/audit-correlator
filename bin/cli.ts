#!/usr/bin/env bun
// audit-correlator CLI — embed/correlate/misfit over any audit-log JSON array.
// JSON to stdout; exit 2 when misfits found (pipeline-friendly).
import { correlate, embedAuto, cosine, cfClassifier } from "../src/index.js";

const args = process.argv.slice(2);
const cmd = args[0];
const file = args[1];
const flagIdx = args.indexOf("--flag");
const flag = flagIdx >= 0 ? args[flagIdx + 1] : undefined;

if (!cmd || !file) {
  console.error("usage: audit-correlator <embed|correlate|misfit> <events.json> [--flag email:attacker@x]");
  process.exit(1);
}
const events = JSON.parse(await Bun.file(file).text());
if (!Array.isArray(events) || !events.length) { console.error("no events"); process.exit(1); }

// flag: email:<addr> | ip:<addr> — default CF classifier
let classify = cfClassifier("__none__");
if (flag?.startsWith("email:")) classify = cfClassifier(flag.slice(6));

if (cmd === "embed") {
  const { eventDoc } = await import("../src/index.js");
  const docs = events.map(eventDoc);
  const uniq = [...new Set(docs)];
  const vecs = await embedAuto(uniq);
  console.log(JSON.stringify({ events: events.length, uniqueDocs: uniq.length, dim: vecs[0].length }));
} else if (cmd === "correlate" || cmd === "misfit") {
  const out = await correlate(events, embedAuto, classify, cosine);
  if (cmd === "misfit") {
    console.log(JSON.stringify({ misfits: out.misfits.length, items: out.misfits.map(m => ({ when: m.event.when, action: m.event.action?.type, doc: m.doc, scores: m.scores })) }, null, 2));
    process.exit(out.misfits.length ? 2 : 0);
  }
  const summary = {
    events: events.length,
    classes: Object.entries(events.reduce((a: any, e) => { const c = classify(e); a[c] = (a[c] || 0) + 1; return a; }, {} as Record<string, number>)),
    misfits: out.misfits.length,
    kin: out.kin.map(k => ({ when: k.flagged.event.when, action: k.flagged.event.action?.type, nearest: { when: k.nearest.event.when, cls: k.nearest.cls, action: k.nearest.event.action?.type }, score: +k.score.toFixed(3) })),
  };
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.error(`unknown command ${cmd}`); process.exit(1);
}
