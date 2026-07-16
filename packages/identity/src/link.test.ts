import { describe, expect, it } from "vitest";
import { deriveIdentity } from "./derive.js";
import {
  APP_SECRET_BYTES,
  MINISTER_ANON_PARAM,
  decideAnonAction,
  extractMinisterAppSecret,
  type MinisterLinkHistory,
  type MinisterLinkLocation,
} from "./link.js";

// The frozen deforum/epoch-1 branch (root "Ministry of Many"). Reused here as a
// realistic 32-byte per-app secret to carry in the fragment.
const DEFORUM_BRANCH_HEX = "99c3d5190c131b9cb9527bd634465a9bdc426efc5cdd945fa99eab01eebb4d66";

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fakeLocation(hash: string, pathname = "/auth/callback", search = "?ok=1"): MinisterLinkLocation {
  return { pathname, search, hash };
}
function recordingHistory(): { urls: Array<string | null | undefined>; history: MinisterLinkHistory } {
  const urls: Array<string | null | undefined> = [];
  return {
    urls,
    history: {
      replaceState: (_data, _unused, url) => {
        urls.push(url);
      },
    },
  };
}

const BRANCH = fromHex(DEFORUM_BRANCH_HEX);
const VALID_FRAGMENT_VALUE = `v1.${b64url(BRANCH)}`;

describe("extractMinisterAppSecret: parse + scrub", () => {
  it("extracts a valid fragment and scrubs it from the URL (path + search preserved)", () => {
    const { urls, history } = recordingHistory();
    const secret = extractMinisterAppSecret({
      location: fakeLocation(`#${MINISTER_ANON_PARAM}=${VALID_FRAGMENT_VALUE}`),
      history,
    });
    expect(b64url(BRANCH)).toHaveLength(43);
    expect(toHex(secret as Uint8Array)).toBe(DEFORUM_BRANCH_HEX);
    expect((secret as Uint8Array).byteLength).toBe(APP_SECRET_BYTES);
    expect(urls).toEqual(["/auth/callback?ok=1"]);
  });

  it("scrubs ONLY the minister_anon param, preserving other fragment params", () => {
    const { urls, history } = recordingHistory();
    const secret = extractMinisterAppSecret({
      location: fakeLocation(`#a=1&${MINISTER_ANON_PARAM}=${VALID_FRAGMENT_VALUE}&b=2`),
      history,
    });
    expect(secret).not.toBeNull();
    expect(urls).toEqual(["/auth/callback?ok=1#a=1&b=2"]);
  });

  it("preserves an existing history.state through the scrub (does not clobber router state)", () => {
    const routerState = { key: "route-1", nav: 42 };
    const datas: unknown[] = [];
    const urls: Array<string | null | undefined> = [];
    const history: MinisterLinkHistory = {
      state: routerState,
      replaceState: (data, _unused, url) => {
        datas.push(data);
        urls.push(url);
      },
    };
    const secret = extractMinisterAppSecret({
      location: fakeLocation(`#${MINISTER_ANON_PARAM}=${VALID_FRAGMENT_VALUE}`),
      history,
    });
    expect(secret).not.toBeNull();
    expect(urls).toEqual(["/auth/callback?ok=1"]);
    expect(datas).toEqual([routerState]);
  });

  it("scrub: false leaves the URL untouched but still returns the secret", () => {
    const { urls, history } = recordingHistory();
    const secret = extractMinisterAppSecret({
      location: fakeLocation(`#${MINISTER_ANON_PARAM}=${VALID_FRAGMENT_VALUE}`),
      history,
      scrub: false,
    });
    expect(secret).not.toBeNull();
    expect(urls).toEqual([]);
  });

  it("returns null without touching history when the fragment is absent", () => {
    const { urls, history } = recordingHistory();
    expect(extractMinisterAppSecret({ location: fakeLocation(""), history })).toBeNull();
    expect(extractMinisterAppSecret({ location: fakeLocation("#"), history })).toBeNull();
    expect(extractMinisterAppSecret({ location: fakeLocation("#state=xyz&code=abc"), history })).toBeNull();
    expect(urls).toEqual([]);
  });

  it("fail-closed on an unknown version - null, but the value is still scrubbed", () => {
    const { urls, history } = recordingHistory();
    const secret = extractMinisterAppSecret({
      location: fakeLocation(`#${MINISTER_ANON_PARAM}=v2.${b64url(BRANCH)}`),
      history,
    });
    expect(secret).toBeNull();
    expect(urls).toEqual(["/auth/callback?ok=1"]);
  });

  it("fail-closed on malformed values - null, still scrubbed", () => {
    const cases = [
      "v1.",
      `v1.${b64url(BRANCH).slice(0, 42)}`,
      `v1.${b64url(BRANCH)}A`,
      `v1.${"!".repeat(43)}`,
      "v1",
      b64url(BRANCH),
      `v1.${b64url(BRANCH).slice(0, 40)}+A=`,
    ];
    for (const value of cases) {
      const { urls, history } = recordingHistory();
      const secret = extractMinisterAppSecret({
        location: fakeLocation(`#${MINISTER_ANON_PARAM}=${value}`),
        history,
      });
      expect(secret, `value: ${value}`).toBeNull();
      expect(urls, `value: ${value}`).toEqual(["/auth/callback?ok=1"]);
    }
  });

  it("returns null fail-closed when no location exists (SSR)", () => {
    expect(extractMinisterAppSecret()).toBeNull();
  });

  it("throws loudly if a scrub is required but history.replaceState is unavailable", () => {
    expect(() =>
      extractMinisterAppSecret({
        location: fakeLocation(`#${MINISTER_ANON_PARAM}=${VALID_FRAGMENT_VALUE}`),
      }),
    ).toThrow(/cannot scrub/);
  });

  it("full chain: fragment -> extract -> deriveIdentity is deterministic", async () => {
    const { history } = recordingHistory();
    const secret = extractMinisterAppSecret({
      location: fakeLocation(`#${MINISTER_ANON_PARAM}=${VALID_FRAGMENT_VALUE}`),
      history,
    });
    expect(secret).not.toBeNull();
    const a = await deriveIdentity(secret as Uint8Array, { kind: "subforum", id: "alpha" });
    const b = await deriveIdentity(secret as Uint8Array, { kind: "subforum", id: "alpha" });
    expect(a.commitment).toBe(b.commitment);
    expect(a.commitment).toMatch(/^[0-9]+$/);
  });
});

describe("decideAnonAction", () => {
  const branch = BRANCH;

  it("no branch delivered -> none, whatever the epochs", () => {
    expect(decideAnonAction({ branch: null, tokenEpoch: 1, storedEpoch: undefined })).toEqual({ action: "none" });
    expect(decideAnonAction({ branch: null, tokenEpoch: 5, storedEpoch: 3 })).toEqual({ action: "none" });
  });

  it("branch but no authenticated token epoch -> none (fail closed)", () => {
    expect(decideAnonAction({ branch, tokenEpoch: undefined, storedEpoch: undefined })).toEqual({ action: "none" });
    expect(decideAnonAction({ branch, tokenEpoch: undefined, storedEpoch: 2 })).toEqual({ action: "none" });
  });

  it("first identity (nothing stored) -> adopt at the token epoch", () => {
    expect(decideAnonAction({ branch, tokenEpoch: 1, storedEpoch: undefined })).toEqual({
      action: "adopt",
      branch,
      epoch: 1,
    });
    expect(decideAnonAction({ branch, tokenEpoch: 7, storedEpoch: undefined })).toEqual({
      action: "adopt",
      branch,
      epoch: 7,
    });
  });

  it("token epoch strictly advances -> rekey", () => {
    expect(decideAnonAction({ branch, tokenEpoch: 2, storedEpoch: 1 })).toEqual({
      action: "rekey",
      branch,
      epoch: 2,
    });
  });

  it("token epoch equal or stale -> none (never clobber; W1/C1)", () => {
    expect(decideAnonAction({ branch, tokenEpoch: 3, storedEpoch: 3 })).toEqual({ action: "none" });
    expect(decideAnonAction({ branch, tokenEpoch: 2, storedEpoch: 5 })).toEqual({ action: "none" });
  });
});
