import { describe, it, expect } from "vitest";
import { schedule, type ScheduleVote } from "./schedule.js";
import type { StoredVote } from "../types.js";

const config = { slots: ["mon", "tue", "wed"] };

function votes(sels: string[][]): StoredVote<ScheduleVote>[] {
  return sels.map((selected, i) => ({ nullifier: String(i + 1), vote: { selected } }));
}

describe("schedule validateVote", () => {
  it("accepts a subset and normalizes to config order + dedupes", () => {
    const r = schedule.validateVote(config, { selected: ["wed", "mon", "mon"] });
    expect(r).toMatchObject({ ok: true });
    if (r.ok) expect(r.vote.selected).toEqual(["mon", "wed"]);
  });
  it("accepts the empty selection by default", () => {
    expect(schedule.validateVote(config, { selected: [] })).toMatchObject({ ok: true });
  });
  it("rejects an unknown slot", () => {
    expect(schedule.validateVote(config, { selected: ["fri"] })).toMatchObject({
      ok: false,
      code: "invalid-vote",
    });
  });
  it("enforces min/max selections", () => {
    const cfg = { slots: ["mon", "tue", "wed"], minSelections: 1, maxSelections: 2 };
    expect(schedule.validateVote(cfg, { selected: [] })).toMatchObject({ ok: false });
    expect(schedule.validateVote(cfg, { selected: ["mon", "tue", "wed"] })).toMatchObject({
      ok: false,
    });
    expect(schedule.validateVote(cfg, { selected: ["mon", "tue"] })).toMatchObject({ ok: true });
  });
});

describe("schedule tally + heatmap view", () => {
  it("counts per slot and surfaces the best slot(s)", () => {
    const t = schedule.tally(config, votes([["mon", "tue"], ["mon"], ["tue", "wed"]]));
    expect(t.counts).toEqual({ mon: 2, tue: 2, wed: 1 });
    const view = schedule.resultView(config, t);
    expect(view.kind).toBe("schedule");
    expect(view.slots).toEqual([
      { slot: "mon", count: 2 },
      { slot: "tue", count: 2 },
      { slot: "wed", count: 1 },
    ]);
    expect(view.best).toEqual(["mon", "tue"]);
  });
  it("best is empty when no one selected anything", () => {
    const view = schedule.resultView(config, schedule.tally(config, votes([[], []])));
    expect(view.best).toEqual([]);
  });
});

describe("schedule resolve", () => {
  it("resolve matches tally", () => {
    const v = votes([["mon"], ["wed"]]);
    const r = schedule.resolve(config, v);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.tally).toEqual(schedule.tally(config, v));
  });
});
