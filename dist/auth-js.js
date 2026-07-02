import {
  verifyMinisterBadges
} from "./chunk-65H325O6.js";
import "./chunk-OY24DUVT.js";

// src/auth-js.ts
function ministerProvider(options) {
  const scopes = options.scopes ?? ["openid", "profile"];
  return {
    id: "minister",
    name: "Minister",
    type: "oidc",
    issuer: options.issuer,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: { params: { scope: scopes.join(" ") } },
    checks: ["pkce", "state", "nonce"]
  };
}
function ministerBadgesFromProfile(profile, options) {
  return verifyMinisterBadges(profile, { issuer: options.issuer, key: options.key });
}
export {
  ministerBadgesFromProfile,
  ministerProvider
};
//# sourceMappingURL=auth-js.js.map