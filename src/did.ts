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
export function didFromIssuer(issuer: string): string {
  const url = new URL(issuer);
  // did:web encodes a port by percent-encoding the colon.
  const host = url.port ? `${url.hostname}%3A${url.port}` : url.hostname;
  return buildDid(host);
}
