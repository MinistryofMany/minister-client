// Thrown when a verifiable-credential badge fails verification — bad
// signature, wrong issuer, malformed envelope, or a subject-binding
// mismatch. Mirrors `@minister/vc`'s `VcVerificationError`.
export class VcVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VcVerificationError";
  }
}

// Thrown when the OIDC flow fails — discovery, token exchange, or
// id_token verification (signature / iss / aud / nonce).
export class OidcError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OidcError";
  }
}
