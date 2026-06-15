# @minister/client

OIDC relying-party SDK for **Minister** — an OpenID Connect identity provider
that lets users authenticate _and_ disclose W3C verifiable-credential "badges"
(email-domain, age-over-N, residency, connected accounts, and more).

Use this in your app to:

- Run the authorization-code flow with PKCE (S256) against Minister.
- Verify the returned `id_token` (signature, issuer, audience, nonce).
- Extract and **signature-verify** the disclosed badges against Minister's
  public keys, with holder-binding enforced.

Three ways to integrate: run the full flow yourself (`createMinisterClient`), verify tokens/badges on a backend (`createMinisterVerifier`), or plug into Auth.js (`@minister/client/auth-js`).

ESM-only. Runs on Node 20+, Deno, and edge runtimes (Vercel Edge, Cloudflare
Workers) — it uses the Web Crypto API and `fetch`, not `node:crypto`.

## Install

```sh
pnpm add @minister/client
```

`jose` and `zod` are runtime dependencies and are installed automatically.

## Quick start

Create one client and reuse it. `issuer` is Minister's origin.

```ts
import { createMinisterClient } from "@minister/client";

export const minister = createMinisterClient({
  issuer: "https://ministry.id",
  clientId: process.env.MINISTER_CLIENT_ID!,
  clientSecret: process.env.MINISTER_CLIENT_SECRET, // omit for public/PKCE-only clients
  redirectUri: "https://yourapp.example/auth/minister/callback",
});
```

### 1. Start — build the authorization URL and persist flow state

```ts
import type { OidcFlowState } from "@minister/client";

export async function startLogin() {
  const { verifier, challenge } = await minister.generatePkce();
  const state = minister.randomToken();
  const nonce = minister.randomToken();

  // Ask for the badges your app needs. `openid` is required; the SDK does
  // not add it for you. `badgeScope("age-over-21")` === "badge:age-over-21".
  const url = await minister.getAuthorizationUrl({
    scopes: [
      "openid",
      "profile",
      minister.badgeScope("age-over-21"),
      minister.badgeScope("email-domain"),
    ],
    state,
    nonce,
    codeChallenge: challenge,
  });

  // YOU own persistence. Store this keyed by `state`; the SDK stores nothing.
  const flow: OidcFlowState = {
    state,
    nonce,
    codeVerifier: verifier,
    expiresAt: Date.now() + 10 * 60_000, // 10 minutes
  };
  await saveFlow(state, flow); // your storage: signed cookie, KV, DB row, ...

  return url; // redirect the user here (302)
}
```

> **You own the flow state, and you must consume it atomically by `state`.**
> On callback, look the record up by the returned `state`, **delete it in the
> same operation** (delete-on-read), and reject if it is missing or expired.
> This makes each `state`/`nonce` usable at most once, which is what defends
> the flow against CSRF and replay. The SDK deliberately stores nothing.

### 2. Callback — exchange the code for verified claims + badges

```ts
export async function handleCallback(req: Request) {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) throw new Error("missing code/state");

  // Atomic consume: fetch AND delete by state in one step.
  const flow = await takeFlow(state);
  if (!flow || flow.expiresAt < Date.now()) {
    throw new Error("unknown or expired login flow");
  }

  const { claims, badges, rejected } = await minister.exchangeCode({
    code,
    codeVerifier: flow.codeVerifier,
    expectedNonce: flow.nonce,
  });

  // `claims.sub` is a pairwise pseudonymous id — stable for this user at
  // YOUR client, and different from what other RPs see.
  // `badges` are already signature-verified and holder-bound.
  const isAdult = badges.some((b) => b.type === "age-over-21");

  // `rejected` holds any disclosed badges that failed verification (bad
  // signature, expired, wrong issuer, ...). Login still succeeds; log/alert
  // on these if a partner may be misconfigured.

  await upsertUser({
    ministerSub: claims.sub,
    name: claims.name,
    avatar: claims.picture,
    isAdult,
  });

  // ... set your own session ...
}
```

`exchangeCode` throws `MinisterTokenError` if the token exchange fails or the
`id_token` signature / issuer / audience / nonce / expiry checks fail — map
that to a `401`. A disclosed badge that fails verification is **not** fatal:
it is dropped from `badges` and surfaced in `rejected`, and login proceeds.

### Verifying a badge received out of band

Badges can also reach you outside the OIDC flow (e.g. a Minister share link).
Verify any Minister VC JWT against Minister's public keys:

```ts
import { VcVerificationError } from "@minister/client";

try {
  const badge = await minister.verifyMinisterBadge(vcJwt);
  // badge.type    -> the badge slug, e.g. "email-domain"
  // badge.claims  -> schema-validated claims, e.g. { domain: "example.com" }
  // badge.subject -> the holder's stable Minister DID (== credentialSubject.id);
  //                  NOT the id_token `sub` (that is a per-RP pairwise value)
  // badge.raw     -> the original JWT, for storage/forwarding
} catch (err) {
  if (err instanceof VcVerificationError) {
    // invalid signature, wrong issuer, bad envelope, or holder-binding mismatch
  }
  throw err;
}
```

Optionally validate the claim shape against the known badge vocabulary:

```ts
import { getBadgeClaimSchema } from "@minister/client";

const schema = getBadgeClaimSchema("email-domain");
const parsed = schema?.safeParse(badge.claims);
```

## Verify on your backend (without running the flow)

If your app uses an OIDC library (or another service runs the flow) and you
just need to verify a Minister `id_token` and its badges, use the verifier —
no flow state, no redirect handling:

```ts
import { createMinisterVerifier } from "@minister/client";

const minister = createMinisterVerifier({
  issuer: "https://ministry.id",
  clientId: "your-client-id", // enables the id_token `aud` check (recommended)
});

const claims = await minister.verifyIdToken(idToken); // throws MinisterTokenError on a bad token
// claims: { sub, name?, picture?, raw }

const { badges, rejected } = await minister.verifyBadges(idToken);
// badges:   [{ type: "age-over-21", claims: { threshold: 21 }, subject, raw }, ...]
// rejected: [{ raw, error }]  (badges that failed verification; never throws per-badge)
```

`verifyBadges` accepts either a raw `id_token` string (it verifies the wrapper
first) or an already-verified payload object (it trusts the wrapper and only
verifies the badge VCs). The verifier caches Minister's JWKS after the first
fetch. Pass `jwks` to inject a key in tests.

## With Auth.js (next-auth)

`@minister/client/auth-js` gives you a provider config and a badge helper you
hand to Auth.js through its documented extension points. We do **not** modify,
fork, or pin Auth.js — `@auth/core` is a types-only optional peer.

```ts
import NextAuth from "next-auth";
import { ministerProvider, ministerBadgesFromProfile } from "@minister/client/auth-js";
import { badgeScopes } from "@minister/client/badges";

export const { handlers, auth } = NextAuth({
  providers: [
    ministerProvider({
      clientId: process.env.MINISTER_CLIENT_ID!,
      clientSecret: process.env.MINISTER_CLIENT_SECRET, // omit for public clients
      issuer: process.env.MINISTER_ISSUER!,
      scopes: ["openid", "profile", ...badgeScopes(["age-over-18"])],
    }),
  ],
  callbacks: {
    async jwt({ token, profile }) {
      if (profile) {
        const { badges } = await ministerBadgesFromProfile(profile, {
          issuer: process.env.MINISTER_ISSUER!,
        });
        token.ministerBadges = badges;
      }
      return token;
    },
  },
});
```

`ministerProvider` returns a standard OIDC provider config; Auth.js verifies the
`id_token`, and `ministerBadgesFromProfile` verifies the nested badge VCs inside
your own callback.

### Subpath imports

- `@minister/client` — the main entry: flow client, verifier, errors, types, and the badge vocabulary.
- `@minister/client/badges` — the badge vocabulary alone (slugs, scopes, Zod claim schemas, `badgeScope`/`badgeScopes`/`badgeTypeOf`). Dependency-light; no jose pulled in. Useful for building scope lists or parsing claims in a UI.
- `@minister/client/auth-js` — the Auth.js helpers only (`ministerProvider`, `ministerBadgesFromProfile`).

## What "verified" means here

- **id_token:** EdDSA signature against Minister's JWKS, plus `iss` ==
  configured issuer, `aud` == your `clientId`, and `nonce` == the value you
  persisted at start, with `exp`/`iat` present and `exp` not in the past.
- **Each badge:** EdDSA signature against Minister's public keys, `iss` ==
  `did:web:<minister-host>`, JWT `typ` == `vc+jwt`, a present and unexpired
  `exp`, a well-formed `vc` envelope, and `credentialSubject.id` == the VC's
  own `sub` (holder binding). A badge whose signature, issuer, type, expiry,
  structure, or subject binding is wrong is rejected (dropped into `rejected`,
  never thrown from `verifyBadges`).

> **Issuer-domain coupling (all badges rejected?).** The expected badge issuer
> is derived as `did:web:<host-of-your-configured-issuer>`. Minister signs badge
> VCs with `did:web:<MINISTER_ISSUER_DOMAIN>`. If the Minister deployment's
> `MINISTER_ISSUER_DOMAIN` host does not equal the OIDC issuer host, **every
> badge fails verification** and lands in `rejected` with an issuer mismatch
> (login and `id_token` verification are unaffected). If you see all badges
> rejected, check that Minister's `MINISTER_ISSUER_DOMAIN` host matches its
> OIDC issuer host.

## API

| Export | Purpose |
| --- | --- |
| `createMinisterClient(config)` | Build a flow client bound to one Minister + RP. |
| `client.getAuthorizationUrl(args)` | Discover the authorize endpoint and build the redirect URL. |
| `client.exchangeCode(args)` | Token exchange + verify id_token + verify badges. Returns `{ claims, badges, rejected }`. |
| `client.verifyMinisterBadge(vcJwt, opts?)` | Verify a single VC badge; `type` is a slug string (e.g. `"email-domain"`). |
| `client.generatePkce()` | PKCE S256 `{ verifier, challenge }`. |
| `client.randomToken(bytes?)` | URL-safe random `state` / `nonce`. |
| `client.badgeScope(slug)` | `"badge:<slug>"` helper. |
| `createMinisterVerifier(config)` | Configure-once verifier: `verifyIdToken`, `verifyBadges`, `verifyBadge`. |
| `verifyMinisterIdToken`, `verifyMinisterBadges`, `verifyMinisterBadge` | The standalone verification functions. |
| `badgeScope`, `badgeScopes`, `badgeTypeOf`, `knownBadgeTypes`, `getBadgeClaimSchema` | Badge vocabulary helpers. |
| `MinisterTokenError` | Thrown when an `id_token` itself fails verification. |
| `OidcFlowState`, `MinisterClaims`, `VerifiedBadge`, `BadgesResult`, `RejectedBadge`, ... | Public types. |
| `VcVerificationError`, `OidcError`, `MinisterTokenError` | Error classes. |

### Testing without the network

`exchangeCode` and `verifyMinisterBadge` accept injectable key sources so your
tests never hit Minister: pass `idTokenKey` / `badgeKey` (to `exchangeCode`) or
`{ key }` (to `verifyMinisterBadge`) — a `KeyLike`, a `Uint8Array`, or a `jose`
key-resolver function. The default is a remote JWKS fetched from Minister.

## License

MIT OR Apache-2.0
