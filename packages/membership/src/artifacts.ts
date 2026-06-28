// Client-side, injectable prover-artifact loading.
//
// FreedInk fetches same-origin and integrity-pins by SHA-256, refusing unpinned
// bytes (verified loadArtifacts/fetchAndVerify). Discreetly passes Uint8Array
// artifacts directly. Hard-coding either into the package would couple it to one
// app's lockfile, so the artifact source is a seam the app implements (or uses a
// shipped helper).

/**
 * Resolves the prover artifacts for a tree depth. For Semaphore, `depth` selects
 * the per-depth circuit (verified buildProof picks artifacts by depth). For RLN
 * there is one fixed circuit, so the depth is ignored (always 20).
 *
 * Returns verified bytes ready to feed the prover. The IMPLEMENTATION owns where
 * the bytes come from and whether they are integrity-checked - the package never
 * fetches from a hard-coded URL.
 */
export interface ArtifactSource {
  load(depth: number): Promise<{ wasm: Uint8Array; zkey: Uint8Array }>;
}

/** Per-depth SHA-256 pin. */
export interface ArtifactPin {
  wasm: { sha256: string };
  zkey: { sha256: string };
}

function toHex(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("WebCrypto (globalThis.crypto.subtle) is not available for artifact pinning.");
  }
  return toHex(await subtle.digest("SHA-256", bytes as unknown as BufferSource));
}

/**
 * Same-origin fetch + SHA-256 verify against a caller-supplied pin map. This is
 * FreedInk's fetchAndVerify behavior lifted and made data-driven: the pin map is
 * INJECTED by the app (FreedInk keeps its snark-artifacts.lock.json; Deforum
 * ships its own), not vendored into the package. Fails loudly on mismatch and
 * never falls back to a live CDN (verified: refusing unpinned bytes is the point).
 *
 * The URL template defaults to FreedInk's vendored layout
 * `<baseUrl>/<depth>/semaphore-<depth>.{wasm,zkey}` and can be overridden.
 */
export function hashPinnedArtifactSource(opts: {
  baseUrl: string;
  pins: Record<string, ArtifactPin>;
  fetchImpl?: typeof fetch;
  urlFor?: (baseUrl: string, depth: number) => { wasm: string; zkey: string };
}): ArtifactSource {
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  const urlFor =
    opts.urlFor ??
    ((base: string, depth: number) => ({
      wasm: `${base}/${depth}/semaphore-${depth}.wasm`,
      zkey: `${base}/${depth}/semaphore-${depth}.zkey`,
    }));

  async function fetchAndVerify(url: string, expectedSha256: string): Promise<Uint8Array> {
    const res = await fetchImpl(url, { cache: "force-cache" });
    if (!res.ok) {
      throw new Error(
        `[membership] failed to fetch artifact ${url}: ${res.status} ${res.statusText}`,
      );
    }
    const bytes = new Uint8Array(await res.arrayBuffer());
    const digest = await sha256Hex(bytes);
    if (digest !== expectedSha256) {
      throw new Error(
        `[membership] artifact integrity check failed for ${url}: ` +
          `expected sha256 ${expectedSha256}, got ${digest}`,
      );
    }
    return bytes;
  }

  return {
    async load(depth: number) {
      const pin = opts.pins[String(depth)];
      if (!pin) {
        throw new Error(
          `[membership] no pinned hashes for depth ${depth}; vendor and pin this depth.`,
        );
      }
      const urls = urlFor(opts.baseUrl, depth);
      const [wasm, zkey] = await Promise.all([
        fetchAndVerify(urls.wasm, pin.wasm.sha256),
        fetchAndVerify(urls.zkey, pin.zkey.sha256),
      ]);
      return { wasm, zkey };
    },
  };
}

/**
 * Returns pre-loaded Uint8Arrays for a depth (Discreetly's browser passthrough,
 * and the simplest Node test source). The app owns the bytes; this just adapts
 * them to the `ArtifactSource` contract.
 */
export function staticArtifactSource(
  byDepth: (depth: number) => { wasm: Uint8Array; zkey: Uint8Array },
): ArtifactSource {
  return {
    async load(depth: number) {
      return byDepth(depth);
    },
  };
}
