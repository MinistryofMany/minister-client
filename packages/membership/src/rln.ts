// @ministryofmany/membership/rln - the RLN engine on its own subpath.
//
// The RLN engine transitively imports @ministryofmany/rln (rlnjs + Semaphore v3
// + the depth-20 circuit), which is an OPTIONAL peer of this package. Keeping the
// engine off the package root means a semaphore-only consumer's import graph
// never touches that island; an RLN consumer installs @ministryofmany/rln and
// imports the engine statically from here (or lazily via the root's
// engineFor("rln") / loadRlnEngine()).

export { rlnEngine } from "./engines/rln.js";
