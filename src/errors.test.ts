// src/errors.test.ts
import { describe, expect, it } from "vitest";
import { MinisterTokenError, VcVerificationError } from "./errors";

describe("errors", () => {
  it("MinisterTokenError carries its name", () => {
    const e = new MinisterTokenError("bad aud");
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe("MinisterTokenError");
    expect(e.message).toBe("bad aud");
  });
  it("VcVerificationError still exists", () => {
    expect(new VcVerificationError("x").name).toBe("VcVerificationError");
  });
});
