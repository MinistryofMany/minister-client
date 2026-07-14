# @ministryofmany/identity

Pure Semaphore v4 identity layer: one backed-up 32-byte device seed yields a
distinct, unlinkable `Identity` per context (`deriveIdentity(seed, contextId)`),
plus a PBKDF2 + AES-GCM seed vault, a BIP-39 mnemonic backup, and the
per-device commitment lifecycle/revocation contract the membership layer
consumes. No Semaphore v3 or RLN in the dependency closure.

## Ministry anon handoff (`minister-link`)

For RPs whose device seed comes from Ministry (anon-identity master spec
sections 8.4 and 9) instead of local generation:

```ts
import {
  extractMinisterAppSecret,
  deriveDeviceSeedFromMinister,
  deriveIdentity,
} from "@ministryofmany/identity";

// On the OIDC callback LANDING page, before any other script touches the URL:
const appSecret = extractMinisterAppSecret(); // reads + SCRUBS #minister_anon=v1.<b64url>
if (appSecret === null) {
  // fail-closed: login worked, no anonymous identity arrived -
  // show your "connect your anonymous identity" state, never invent a secret.
} else {
  const deviceSeed = await deriveDeviceSeedFromMinister(appSecret, rpMixSecret);
  const identity = await deriveIdentity(deviceSeed, contextId); // existing chain, unchanged
}
```

Integration rules (spec 9.3): run the extract-and-scrub before any analytics or
third-party JS; **no client-side redirect anywhere in the callback chain** (a
`location.assign`, meta refresh, or router navigation destroys the fragment -
only server-side 3xx hops preserve it); never send the per-app secret or the
device seed to any server; cache at most the mixed device seed, never the raw
per-app secret.

### `rpMixSecret` is identity-determining - do not lose it, do not rotate it

`device_seed = HKDF-SHA-256(ikm = per_app_secret, salt = rp_mix_secret,
info = "minister/anon/rp-mix/v1", L = 32)`. The mix secret is the HKDF salt,
so **losing or regenerating it silently forks every user's identity in your
app** - every commitment, membership, and nullifier orphans, every prior post
becomes unownable, and no error fires anywhere (spec invariant I9). Discipline:

- Provision **once** at launch: >= 32 CSPRNG bytes (suggested env var
  `ANON_RP_MIX_SECRET`), served to your signed-in page by your own server -
  never baked into a public bundle.
- Back it up immediately with the same durability as your database.
- **Immutable post-launch.** Exclude it from every secret-rotation runbook;
  there is no legitimate rotation, only the fork.
- Write your recovery story (where the backup lives, who restores it) before
  the integration ships.

Ministry never holds this value - that separation is the point: a compromise
exfiltrating seeds from ministry.id still cannot reproduce your app's
identities without your mix secret.
