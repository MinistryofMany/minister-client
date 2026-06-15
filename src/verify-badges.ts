import type { JWTPayload } from "jose";
import { verifyMinisterBadge } from "./verify-badge";
import { verifyIdTokenPayload } from "./verify-id-token";
import { VcVerificationError } from "./errors";
import type { KeyInput, BadgesResult } from "./types";

export interface VerifyBadgesOptions {
  issuer: string;
  // Needed only when a raw id_token string is passed (to verify the wrapper).
  clientId?: string;
  key?: KeyInput;
}

// Verify the `minister_badges` carried by a token.
//
// - Given a raw id_token STRING, the wrapper is verified first (throws
//   MinisterTokenError if it fails), then its badges are read.
// - Given an already-verified PAYLOAD object (e.g. Auth.js's profile, or
//   a prior verifyIdToken result), the wrapper is trusted and only the
//   badges are verified.
//
// Individual bad badges never throw — they are returned in `rejected`.
export async function verifyMinisterBadges(
  tokenOrPayload: string | JWTPayload,
  options: VerifyBadgesOptions,
): Promise<BadgesResult> {
  // For the string path, the whole `options` object is forwarded to the
  // id_token verifier, so its `clientId` (audience) and `key` are honored
  // when verifying the wrapper. Do not narrow this to `{ issuer }` - that
  // would silently drop audience enforcement on the string path.
  const payload =
    typeof tokenOrPayload === "string"
      ? await verifyIdTokenPayload(tokenOrPayload, options)
      : tokenOrPayload;

  const raw = (payload as Record<string, unknown>)["minister_badges"];
  if (raw === undefined || raw === null) return { badges: [], rejected: [] };
  if (!Array.isArray(raw)) {
    return { badges: [], rejected: [{ raw: String(raw), error: new VcVerificationError("minister_badges is not an array") }] };
  }

  const result: BadgesResult = { badges: [], rejected: [] };
  for (const entry of raw) {
    if (typeof entry !== "string") {
      result.rejected.push({ raw: String(entry), error: new VcVerificationError("badge entry is not a JWT string") });
      continue;
    }
    try {
      result.badges.push(await verifyMinisterBadge(entry, { issuer: options.issuer, key: options.key }));
    } catch (cause) {
      result.rejected.push({
        raw: entry,
        error: cause instanceof VcVerificationError ? cause : new VcVerificationError(String(cause)),
      });
    }
  }
  return result;
}
