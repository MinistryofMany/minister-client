import type { Signer } from "./signer.js";
import { createLocalSigner } from "./local-signer.js";
import type { LocalSignerOpts } from "./local-signer.js";
import { createRemoteSigner } from "./remote-signer.js";
import type { RemoteSignerConfig } from "./remote-signer.js";

// Selection mirror of FreedInk's getVoteSigner(): RemoteSigner when a remote
// config is given, else LocalSigner. The app decides (e.g. from SIGNET_URL) and
// passes one config. FreedInk reads the env + resolves PEMs in its config layer
// and hands the resolved kind here; the package never reads env or the filesystem.
export function createSigner(
  opts:
    | { kind: "local"; local: LocalSignerOpts }
    | { kind: "remote"; remote: RemoteSignerConfig },
): Signer {
  if (opts.kind === "remote") return createRemoteSigner(opts.remote);
  return createLocalSigner(opts.local);
}
