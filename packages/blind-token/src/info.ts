import type { ActionInfo } from "./types.js";

// Build the public-metadata bytes for an action. EXACTLY `<infoPrefix>:<actionKey>`
// UTF-8 - byte-identical to FreedInk's versionInfo()
// (src/lib/server/vote-token.ts:103-105 and src/lib/client/vote-token.ts:231-233,
// both `new TextEncoder().encode(`freedink-vote:${versionId}`)`).
//
// So buildInfo({ infoPrefix: 'freedink-vote', actionKey: versionId }) ===
// new TextEncoder().encode(`freedink-vote:${versionId}`). The colon separator is
// the single literal byte between the namespace and the action key; binding the
// token to these bytes is what prevents cross-action replay (a token for actionKey
// A only verifies under A).
//
// NOTE on Signet (verified, Signet/src/crypto.rs:47): the deployed Signet service
// hard-codes the `freedink-vote:` prefix and signs over `freedink-vote:<version_id>`.
// For a RemoteSigner against that Signet, info.infoPrefix MUST be 'freedink-vote'
// and the RemoteSigner sends version_id = actionKey, so Signet reconstructs the
// same bytes this builder produces. See RemoteSigner for the coupling guard.
export function buildInfo(info: ActionInfo): Uint8Array {
  return new TextEncoder().encode(`${info.infoPrefix}:${info.actionKey}`);
}
