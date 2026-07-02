import type { JWTPayload } from "jose";
import { verifyMinisterBadge } from "./verify-badge";
import { verifyIdTokenPayload } from "./verify-id-token";
import { buildPairwiseSubjectDid } from "./did";
import { MinisterTokenError, VcVerificationError } from "./errors";
import type { KeyInput, BadgesResult } from "./types";

export interface VerifyBadgesOptions {
  issuer: string;
  // Required when a raw id_token STRING is passed (the wrapper is verified,
  // and its `aud` must be enforced fail-closed). Unused on the already-verified
  // payload path.
  clientId?: string;
  key?: KeyInput;
}

// Verify the `minister_badges` carried by a token AND bind each one to the
// login.
//
// - Given a raw id_token STRING, the wrapper is verified first (throws
//   MinisterTokenError if it fails, including a missing clientId/audience),
//   then its badges are read.
// - Given an already-verified PAYLOAD object (e.g. Auth.js's profile, or a
//   prior verifyIdToken result), the wrapper is trusted and only the badges are
//   verified.
//
// Holder binding: each badge's pairwise subject MUST equal
// `did:web:<host>:u:<id_token sub>`. Minister re-mints each disclosed badge
// under the same pairwise pseudonym it stamps as the id_token `sub`, so a badge
// whose subject does not bind to THIS login (a borrowed/mismatched credential,
// or one carrying a stale subject) is pushed to `rejected` rather than trusted.
//
// Individual bad badges never throw — they are returned in `rejected`.
export async function verifyMinisterBadges(
  tokenOrPayload: string | JWTPayload,
  options: VerifyBadgesOptions,
): Promise<BadgesResult> {
  let payload: JWTPayload;
  if (typeof tokenOrPayload === "string") {
    // Fail closed: verifying the wrapper string requires an expected audience.
    if (!options.clientId) {
      throw new MinisterTokenError("clientId is required to verify a raw id_token string");
    }
    payload = await verifyIdTokenPayload(tokenOrPayload, {
      issuer: options.issuer,
      clientId: options.clientId,
      key: options.key,
    });
  } else {
    payload = tokenOrPayload;
  }

  const raw = (payload as Record<string, unknown>)["minister_badges"];
  if (raw === undefined || raw === null) return { badges: [], rejected: [] };
  if (!Array.isArray(raw)) {
    return { badges: [], rejected: [{ raw: String(raw), error: new VcVerificationError("minister_badges is not an array") }] };
  }

  // The login the badges must bind to. Without a usable subject we cannot bind,
  // so every badge is rejected (fail closed) rather than trusted unbound.
  const idTokenSub = (payload as Record<string, unknown>)["sub"];
  const canBind = typeof idTokenSub === "string" && idTokenSub.length > 0;
  const expectedSubject = canBind
    ? buildPairwiseSubjectDid(options.issuer, idTokenSub as string)
    : undefined;

  const result: BadgesResult = { badges: [], rejected: [] };
  for (const entry of raw) {
    if (typeof entry !== "string") {
      result.rejected.push({ raw: String(entry), error: new VcVerificationError("badge entry is not a JWT string") });
      continue;
    }
    try {
      const badge = await verifyMinisterBadge(entry, { issuer: options.issuer, key: options.key });
      if (!expectedSubject) {
        throw new VcVerificationError(
          "cannot bind badge: id_token has no usable `sub`",
        );
      }
      if (badge.subject !== expectedSubject) {
        // Signed by Minister, but its subject does not bind to THIS login —
        // a borrowed/mismatched credential. Do not count it.
        throw new VcVerificationError(
          "badge subject is not bound to the id_token sub (borrowed or mismatched credential)",
        );
      }
      result.badges.push(badge);
    } catch (cause) {
      result.rejected.push({
        raw: entry,
        error: cause instanceof VcVerificationError ? cause : new VcVerificationError(String(cause)),
      });
    }
  }
  return result;
}
