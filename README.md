# audit-correlator — semantic audit-log correlation engine (bge-m3)

Embeds every event of ANY structured audit log (Cloudflare, GitHub, pitchfork,
estate logs) into the bge-m3 space and correlates actor BEHAVIOR — not
keywords. Finds: (1) events semantically kin to a flagged actor but not
flagged (misfits), (2) the behavioral fingerprint (mean vector) per actor
class, (3) nearest-kin chains across actors (attacker mimicking operator).

## Why

Keyword filters on audit logs miss behavioral anomalies: the femboy.pp.ua
hijacker (noo056272@gmail.com, CF account OWNER) acted with the SAME event
types as the operator (rulesets_create/update, token_roll/revoke) — only the
embedding space separated the BEHAVIOR. 18/18 attacker events scored nearest-kin
to api-token-lane actions (0.72–0.80 cosine), distinct from operator's own
0.74–0.79 — a separable fingerprint with zero labeled training.

## Usage

```bash
audit-correlator embed <audit.json>    # events JSONL/JSON array -> embeddings
audit-correlator correlate <audit.json> [--flag actor=email:x]  # fingerprint + kin
audit-correlator misfit <audit.json> --flag actor=email:x  # unflagged-but-kin
```

Event doc contract (the semantic payload per event): `action phase on zone Z
by ACTOR-CLASS token T` — actor-class is derived, never raw email (privacy).

## API

```ts
import { correlate, misfits, fingerprint } from '@geode/audit-correlator';
```

## Data

First dataset: `/tmp/cf-audit-complete.json` (1300 CF events, 18mo window,
18 attacker) — copied to `data/` for regression.
