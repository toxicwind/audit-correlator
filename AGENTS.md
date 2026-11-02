# audit-correlator — agents.md (SDK contract)

> Semantic audit-log BEHAVIOR correlation on bge-m3. Read before extending.
> Product repo: `pens/geode/products/audit-correlator` (`toxicwind/audit-correlator`).

## What it is

Keyword filters on audit logs miss behavioral anomalies. This engine embeds
every event into the bge-m3 space and correlates ACTOR BEHAVIOR: who behaves
like whom, regardless of event-type overlap.

First proof (2026-11-02, CF hijack): the attacker (noo056272@gmail.com,
account OWNER) acted with the SAME event types as the operator
(rulesets_create/update, token_roll/revoke). Only the embedding space
separated behavior: 18/18 attacker events nearest-kin to api-token-lane
actions (0.72–0.94 cosine), zero labeled training needed. 69 misfits surfaced
(unflagged events behaving like the flagged class).

## Library API

```ts
import { correlate, eventDoc, cfClassifier, embedAuto, cosine } from "@geode/audit-correlator";

const out = await correlate(
  events,                    // AuditEvent[] — raw audit-log JSON rows
  embedAuto,                 // (inputs: string[]) => Promise<number[][]>
  cfClassifier("attacker@x"),// flags by email; classes: flagged|operator|api-token|pipeline
  cosine,
);
// out.results  — every event + its cosine scores to each class mean
// out.misfits  — UNFLAGGED events whose nearest class mean is "flagged"
// out.kin      — for each flagged event: its nearest unflagged event + score
```

## Event-doc contract (the semantic payload)

`eventDoc(e)` → `"<action words> <phase> on <target> token <name>"`
- action: snake_case split to words (`rulesets_create` → `rulesets create`)
- target: `metadata.zone_name` || `metadata.zone_tag` || `metadata.repo`
- Actor classes are DERIVED in the classifier — raw emails are NEVER in the
  doc (privacy + tokenization noise).

## Embedder adapter

`embedAuto` = forge bge-m3 (cloud, free/unlimited) → local bge-server fallback.
Both 1024-dim; callers treat interchangeably. Swap in any embedder with the
same `(inputs: string[]) => Promise<number[][]>` shape.

## CLI (JSON to stdout, pipeline-friendly)

```bash
audit-correlator embed    data.json                      # count + dim
audit-correlator correlate data.json --flag email:a@x    # classes + kin + misfit count
audit-correlator misfit   data.json --flag email:a@x     # misfit items; exit 2 if any
```

## Tests

`bun test` — 9 pass. Stub embedder (deterministic hash vectors, offline) for
the misfit-detection logic; the misfit DETECTION test (sneaky@x mimicking
flagged behavior) is the regression that matters. Live bge-m3 proof is in the
pinned dataset run: `data/cf-audit-2026-18mo.json` (1300 events, 18 flagged).

## Rules

- NEVER put raw emails/ips in event docs (derived classes only).
- Class means with zero members → skip that score (never divide by zero).
- Misfit = nearest-mean-is-flagged AND strictly greater than ALL other classes.
- New audit-log source? Write a new classifier (don't bend cfClassifier) +
  extend `eventDoc` target extraction — keep the doc shape stable so old
  embeddings stay comparable.
