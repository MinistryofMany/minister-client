import { hkdfSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { DEVICE_SEED_BYTES, deriveIdentity } from "./derive.js";
import {
  APP_SECRET_BYTES,
  MINISTER_ANON_PARAM,
  RP_MIX_SECRET_MIN_BYTES,
  deriveDeviceSeedFromMinister,
  extractMinisterAppSecret,
  type MinisterLinkHistory,
  type MinisterLinkLocation,
} from "./minister-link.js";

// ---------------------------------------------------------------------------
// Golden vectors from the anon-identity master spec (sections 8.1 and 9.2).
// Every hex constant below was independently re-derived with node:crypto
// hkdfSync before being pinned here; the suite also re-checks them at runtime.
// ---------------------------------------------------------------------------

/** Spec 8.1 root seed: hex "4d696e6973747279206f66204d616e79" = "Ministry of Many". */
const SPEC_ROOT_SEED_HEX = "4d696e6973747279206f66204d616e79";

/** Spec 8.1 per_app_secret golden vectors. */
const PER_APP_SECRET_HEX = {
  deforum: "a6a39187454acc287e62b9eaeabecef8c67bf08500fc53bd5e00912ab0f71a5e",
  freedink: "8f25c90c8c1c9717e16c2e9bf90951f44e4897c1a6ada79af3ba57de2909e0b0",
} as const;

/** Spec 9.2: rp_mix_secret = utf8("example-rp-mix-secret-32-bytes!!") (32 bytes). */
const RP_MIX = new TextEncoder().encode("example-rp-mix-secret-32-bytes!!");

/** Spec 9.2 golden: device_seed for the deforum per_app_secret + RP_MIX. */
const DEVICE_SEED_DEFORUM_HEX =
  "09aa876834bad70b4c38e57dbecea98c69f127e240e4eb021ed6d822cab554d5";

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

/**
 * Ministry-side per-app derivation (spec 8.1), re-implemented here so the test
 * proves the pinned fixtures really are HKDF(seed, "minister/anon/hkdf/v1",
 * "minister/anon/v1:app:" + anonAppId) and not copy-paste artifacts.
 */
async function ministrySidePerAppSecret(seed: Uint8Array, anonAppId: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", seed as BufferSource, "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode("minister/anon/hkdf/v1") as BufferSource,
      info: new TextEncoder().encode(`minister/anon/v1:app:${anonAppId}`) as BufferSource,
    },
    key,
    256,
  );
  return new Uint8Array(bits);
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

const DEFORUM_SECRET = fromHex(PER_APP_SECRET_HEX.deforum);
const FREEDINK_SECRET = fromHex(PER_APP_SECRET_HEX.freedink);
const VALID_FRAGMENT_VALUE = `v1.${b64url(DEFORUM_SECRET)}`;

describe("spec golden vectors", () => {
  it("spec 8.1: the deforum and freedink per_app_secret vectors reproduce from the root seed", async () => {
    const seed = fromHex(SPEC_ROOT_SEED_HEX);
    expect(new TextDecoder().decode(seed)).toBe("Ministry of Many");
    expect(toHex(await ministrySidePerAppSecret(seed, "deforum"))).toBe(
      PER_APP_SECRET_HEX.deforum,
    );
    expect(toHex(await ministrySidePerAppSecret(seed, "freedink"))).toBe(
      PER_APP_SECRET_HEX.freedink,
    );
  });

  it("spec 9.2: deriveDeviceSeedFromMinister(deforum, example mix) matches the device_seed golden", async () => {
    const deviceSeed = await deriveDeviceSeedFromMinister(DEFORUM_SECRET, RP_MIX);
    expect(toHex(deviceSeed)).toBe(DEVICE_SEED_DEFORUM_HEX);
    expect(deviceSeed.byteLength).toBe(DEVICE_SEED_BYTES);
  });

  it("cross-checks both app vectors against an independent HKDF implementation (node:crypto)", async () => {
    for (const secret of [DEFORUM_SECRET, FREEDINK_SECRET]) {
      const expected = new Uint8Array(
        hkdfSync("sha256", secret, RP_MIX, new TextEncoder().encode("minister/anon/rp-mix/v1"), 32),
      );
      const actual = await deriveDeviceSeedFromMinister(secret, RP_MIX);
      expect(toHex(actual)).toBe(toHex(expected));
    }
  });

  it("full chain: fragment -> extract -> derive -> golden device seed -> existing deriveIdentity", async () => {
    expect(b64url(DEFORUM_SECRET)).toHaveLength(43);
    const { history } = recordingHistory();
    const secret = extractMinisterAppSecret({
      location: fakeLocation(`#${MINISTER_ANON_PARAM}=${VALID_FRAGMENT_VALUE}`),
      history,
    });
    expect(secret).not.toBeNull();
    expect(toHex(secret as Uint8Array)).toBe(PER_APP_SECRET_HEX.deforum);

    const deviceSeed = await deriveDeviceSeedFromMinister(secret as Uint8Array, RP_MIX);
    expect(toHex(deviceSeed)).toBe(DEVICE_SEED_DEFORUM_HEX);

    // The mixed seed feeds the EXISTING per-context chain unchanged.
    const a = await deriveIdentity(deviceSeed, "subforum:alpha");
    const b = await deriveIdentity(deviceSeed, "subforum:alpha");
    expect(a.commitment).toBe(b.commitment);
    expect(a.commitment).toMatch(/^[0-9]+$/);
  });
});

describe("deriveDeviceSeedFromMinister", () => {
  it("rp_mix_secret domain separation: a different mix secret forks the device seed", async () => {
    const otherMix = new TextEncoder().encode("another-rp-mix-secret-32-bytes!!");
    expect(otherMix.byteLength).toBe(32);
    const a = await deriveDeviceSeedFromMinister(DEFORUM_SECRET, RP_MIX);
    const b = await deriveDeviceSeedFromMinister(DEFORUM_SECRET, otherMix);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it("app-secret separation: different per-app secrets, same mix -> different device seeds", async () => {
    const a = await deriveDeviceSeedFromMinister(DEFORUM_SECRET, RP_MIX);
    const b = await deriveDeviceSeedFromMinister(FREEDINK_SECRET, RP_MIX);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it("is deterministic", async () => {
    const a = await deriveDeviceSeedFromMinister(DEFORUM_SECRET, RP_MIX);
    const b = await deriveDeviceSeedFromMinister(DEFORUM_SECRET, RP_MIX);
    expect(toHex(a)).toBe(toHex(b));
  });

  it("rejects a wrong-length appSecret", async () => {
    await expect(deriveDeviceSeedFromMinister(new Uint8Array(16), RP_MIX)).rejects.toThrow(
      new RegExp(`${APP_SECRET_BYTES} bytes`),
    );
    await expect(deriveDeviceSeedFromMinister(new Uint8Array(33), RP_MIX)).rejects.toThrow(
      new RegExp(`${APP_SECRET_BYTES} bytes`),
    );
  });

  it("rejects a too-short rpMixSecret", async () => {
    await expect(
      deriveDeviceSeedFromMinister(DEFORUM_SECRET, new Uint8Array(RP_MIX_SECRET_MIN_BYTES - 1)),
    ).rejects.toThrow(/at least 32 bytes/);
  });
});

describe("extractMinisterAppSecret: parse + scrub", () => {
  it("extracts a valid fragment and scrubs it from the URL (path + search preserved)", () => {
    const { urls, history } = recordingHistory();
    const secret = extractMinisterAppSecret({
      location: fakeLocation(`#${MINISTER_ANON_PARAM}=${VALID_FRAGMENT_VALUE}`),
      history,
    });
    expect(toHex(secret as Uint8Array)).toBe(PER_APP_SECRET_HEX.deforum);
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
    expect(
      extractMinisterAppSecret({ location: fakeLocation("#state=xyz&code=abc"), history }),
    ).toBeNull();
    expect(urls).toEqual([]);
  });

  it("fail-closed on an unknown version - null, but the value is still scrubbed", () => {
    const { urls, history } = recordingHistory();
    const secret = extractMinisterAppSecret({
      location: fakeLocation(`#${MINISTER_ANON_PARAM}=v2.${b64url(DEFORUM_SECRET)}`),
      history,
    });
    expect(secret).toBeNull();
    expect(urls).toEqual(["/auth/callback?ok=1"]);
  });

  it("fail-closed on malformed values - null, still scrubbed", () => {
    const cases = [
      "v1.", // empty payload
      `v1.${b64url(DEFORUM_SECRET).slice(0, 42)}`, // 42 chars (31.5 bytes)
      `v1.${b64url(DEFORUM_SECRET)}A`, // 44 chars (33 bytes)
      `v1.${"!".repeat(43)}`, // non-base64url chars
      "v1", // no dot
      b64url(DEFORUM_SECRET), // no version prefix
      `v1.${b64url(DEFORUM_SECRET).slice(0, 40)}+A=`, // base64, not base64url
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
    // Node test env: globalThis.location is undefined.
    expect(extractMinisterAppSecret()).toBeNull();
  });

  it("throws loudly if a scrub is required but history.replaceState is unavailable", () => {
    // Node test env: globalThis.history is undefined, and no opts.history given.
    expect(() =>
      extractMinisterAppSecret({
        location: fakeLocation(`#${MINISTER_ANON_PARAM}=${VALID_FRAGMENT_VALUE}`),
      }),
    ).toThrow(/cannot scrub/);
  });
});
