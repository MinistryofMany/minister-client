// Thrown when a verifiable-credential badge fails verification — bad
// signature, wrong issuer, malformed envelope, or a subject-binding
// mismatch. Mirrors `@minister/vc`'s `VcVerificationError`.
// Its message may include VC-derived text; do not reflect it to untrusted output.
export class VcVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VcVerificationError";
  }
}

// Thrown when the OIDC flow fails for a non-token reason - missing client
// config, discovery, the token-exchange request, or a malformed token
// response. id_token verification failures throw MinisterTokenError;
// individual bad badges are reported in BadgesResult.rejected, not thrown.
export class OidcError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OidcError";
  }
}

// Thrown when an id_token itself fails verification - signature, issuer,
// audience, expiry, or nonce. The token is the trust root, so this is a
// hard failure (distinct from an individual bad badge, which is reported
// in BadgesResult.rejected rather than thrown).
// Its message may include token-derived text; do not reflect it to untrusted output.
export class MinisterTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MinisterTokenError";
  }
}
