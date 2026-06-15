# @minister/client

OIDC relying-party SDK for **Minister** — an OpenID Connect identity provider
that lets users authenticate _and_ disclose W3C verifiable-credential "badges"
(email-domain, age-over-N, residency, connected accounts, and more).

Use this in your app to:

- Run the authorization-code flow with PKCE (S256) against Minister.
- Verify the returned `id_token` (signature, issuer, audience, nonce).
- Extract and **signature-verify** the disclosed badges against Minister's
  public keys, with holder-binding enforced.

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

  const { claims, badges } = await minister.exchangeCode({
    code,
    codeVerifier: flow.codeVerifier,
    expectedNonce: flow.nonce,
  });

  // `claims.sub` is a pairwise pseudonymous id — stable for this user at
  // YOUR client, and different from what other RPs see.
  // `badges` are already signature-verified and holder-bound.
  const isAdult = badges.some(
    (b) => b.type.includes("MinisterAgeOver21Credential"),
  );

  await upsertUser({
    ministerSub: claims.sub,
    name: claims.name,
    avatar: claims.picture,
    isAdult,
  });

  // ... set your own session ...
}
```

`exchangeCode` throws if the token exchange fails, the `id_token` signature /
issuer / audience / nonce checks fail, or any disclosed badge fails
verification. Map a throw to a `401`.

### Verifying a badge received out of band

Badges can also reach you outside the OIDC flow (e.g. a Minister share link).
Verify any Minister VC JWT against Minister's public keys:

```ts
import { VcVerificationError } from "@minister/client";

try {
  const badge = await minister.verifyMinisterBadge(vcJwt);
  // badge.type    -> e.g. ["VerifiableCredential", "MinisterEmailDomainCredential"]
  // badge.claims  -> e.g. { domain: "example.com" }
  // badge.sub     -> the holder's subject DID (== credentialSubject.id)
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

## What "verified" means here

- **id_token:** EdDSA signature against Minister's JWKS, plus `iss` ==
  configured issuer, `aud` == your `clientId`, and `nonce` == the value you
  persisted at start.
- **Each badge:** EdDSA signature against Minister's public keys, `iss` ==
  `did:web:<minister-host>`, JWT `typ` == `vc+jwt`, a well-formed `vc`
  envelope, and `credentialSubject.id === sub` (holder binding). A badge whose
  signature, issuer, type, structure, or subject binding is wrong is rejected.

## API

| Export | Purpose |
| --- | --- |
| `createMinisterClient(config)` | Build a client bound to one Minister + RP. |
| `client.getAuthorizationUrl(args)` | Discover the authorize endpoint and build the redirect URL. |
| `client.exchangeCode(args)` | Token exchange + verify id_token + verify badges. |
| `client.verifyMinisterBadge(vcJwt, opts?)` | Verify a single VC badge. |
| `client.generatePkce()` | PKCE S256 `{ verifier, challenge }`. |
| `client.randomToken(bytes?)` | URL-safe random `state` / `nonce`. |
| `client.badgeScope(slug)` | `"badge:<slug>"` helper. |
| `getBadgeClaimSchema(slug)`, `knownBadgeTypes()` | Badge vocabulary (Zod schemas + slugs). |
| `OidcFlowState`, `MinisterClaims`, `VerifiedBadge`, ... | Public types. |
| `VcVerificationError`, `OidcError` | Error classes. |

### Testing without the network

`exchangeCode` and `verifyMinisterBadge` accept injectable key sources so your
tests never hit Minister: pass `idTokenKey` / `badgeKey` (to `exchangeCode`) or
`{ key }` (to `verifyMinisterBadge`) — a `KeyLike`, a `Uint8Array`, or a `jose`
key-resolver function. The default is a remote JWKS fetched from Minister.

## License

MIT OR Apache-2.0
