// did:web identifier for a domain. Per the W3C did:web spec the DID
// document is served at https://<domain>/.well-known/did.json. Mirrors
// `@ministryofmany/vc`'s `buildDid` so the VC `iss` this SDK expects matches
// exactly what Minister stamps when issuing.
export function buildDid(domain: string): string {
  return `did:web:${domain}`;
}

// Derive the issuer DID from a Minister origin (the OIDC `issuer`).
// Minister signs VCs with `iss = did:web:<host>` where <host> is the
// origin's host (including a non-default port, encoded per did:web as
// `host%3Aport`). e.g. "https://ministry.id" -> "did:web:ministry.id".
//
// Explicit + total: a path-bearing issuer is REJECTED rather than silently
// dropped. Minister's did:web is host-only, so an issuer with a path would
// make the derived DID diverge and every badge fail closed with no signal —
// fail loud at config time instead. `issuer` is trusted RP config (set once),
// so throwing here surfaces a misconfiguration, never attacker input.
export function didFromIssuer(issuer: string): string {
  const url = new URL(issuer);
  if (url.pathname !== "" && url.pathname !== "/") {
    throw new Error(
      `Minister issuer must be an origin with no path (got path "${url.pathname}" in "${issuer}")`,
    );
  }
  if (url.search !== "" || url.hash !== "") {
    throw new Error(`Minister issuer must be an origin with no query or fragment: "${issuer}"`);
  }
  // did:web encodes a port by percent-encoding the colon.
  const host = url.port ? `${url.hostname}%3A${url.port}` : url.hostname;
  return buildDid(host);
}

// Build the per-RP PAIRWISE subject DID Minister stamps into a disclosed
// badge: `did:web:<host>:u:<sub>`, where <host> is the issuer host and <sub>
// is the id_token pairwise subject. The wrapper uses this to bind a badge to
// the login (badge `subject` must equal the value this returns for the
// id_token `sub`).
export function buildPairwiseSubjectDid(issuer: string, sub: string): string {
  return `${didFromIssuer(issuer)}:u:${sub}`;
}

// Parse a pairwise subject DID back into { issuerDid, sub }, or null when it
// does not match the `did:web:<...>:u:<sub>` shape. Explicit `:u:` handling —
// <sub> must be a single, non-empty, colon-free trailing segment — so this is
// total and never silently mis-splits a path-bearing DID.
export function parsePairwiseSubjectDid(
  subject: string,
): { issuerDid: string; sub: string } | null {
  const marker = ":u:";
  const idx = subject.lastIndexOf(marker);
  if (idx <= 0) return null;
  const issuerDid = subject.slice(0, idx);
  const sub = subject.slice(idx + marker.length);
  if (!issuerDid.startsWith("did:web:") || sub.length === 0 || sub.includes(":")) return null;
  return { issuerDid, sub };
}
