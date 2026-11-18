import { describe, expect, it } from "vitest";
import { clone, fakeTokens, integrity, npmInstall } from "./__fixtures__/builders.js";
import { esbuildLikeScenario, shaiHulud2Scenario, wormScenario } from "./__fixtures__/scenarios.js";
import { verdictCacheKey } from "./cache-key.js";
import { InvalidPackageIdentityError } from "./errors.js";
import { RULES } from "./rules/index.js";
import type { Rule } from "./rules/types.js";
import {
  allowsInstall,
  errorVerdict,
  judge,
  judgeWith,
  kindFromFindings,
  RULESET_VERSION,
} from "./verdict.js";

const ruleIds = (v: ReturnType<typeof judge>) => [...new Set(v.findings.map((f) => f.ruleId))].sort();

describe("scenarios", () => {
  it("judges the worm MALICIOUS with R1, R2, R3, R6, and R10", () => {
    const v = judge(wormScenario());
    expect(v.kind).toBe("MALICIOUS");
    expect(ruleIds(v)).toEqual(["R1", "R10", "R2", "R3", "R6"]);
  });

  it("judges the esbuild-like package SAFE with no findings", () => {
    const v = judge(esbuildLikeScenario());
    expect(v).toEqual({ kind: "SAFE", rulesetVersion: RULESET_VERSION, findings: [], omittedFindings: 0 });
    expect(allowsInstall(v)).toBe(true);
  });

  it("judges the Shai-Hulud 2.0 lookalike MALICIOUS with R4, R5, and R9", () => {
    const v = judge(shaiHulud2Scenario());
    expect(v.kind).toBe("MALICIOUS");
    expect(ruleIds(v)).toEqual(expect.arrayContaining(["R4", "R5", "R9"]));
  });

  it("never shows a honeytoken in full", () => {
    const text = JSON.stringify(judge(wormScenario()));
    expect(text).not.toContain(fakeTokens.npm());
    expect(text).not.toContain(fakeTokens.github());
  });

  it("every rule fires in at least one scenario or unit case", () => {
    const seen = new Set(
      [wormScenario(), shaiHulud2Scenario()].flatMap((s) => judge(s).findings.map((f) => f.ruleId)),
    );
    for (const id of ["R7", "R8", "R13"]) seen.add(id as never); // covered in rules.test.ts
    expect([...seen].sort()).toEqual(RULES.map((r) => r.id).sort());
  });
});

describe("fail closed", () => {
  it("returns ERROR for invalid input", () => {
    expect(judge({}).kind).toBe("ERROR");
    expect(judge(null).kind).toBe("ERROR");
  });

  it("returns ERROR when there are no exec events", () => {
    expect(judge(npmInstall(() => {}).build({ events: [] })).kind).toBe("ERROR");
    const noExec = npmInstall(() => {}).build();
    expect(judge({ ...noExec, events: noExec.events.filter((e) => e.type !== "exec") }).kind).toBe("ERROR");
  });

  it("returns ERROR when truncated with no events", () => {
    const v = judge(npmInstall(() => {}).build({ events: [], eventsTruncated: true }));
    expect(v.kind).toBe("ERROR");
  });

  it("returns ERROR when a rule produces empty or unknown evidence", () => {
    const empty: Rule = {
      id: "R1",
      title: "broken",
      evaluate: () => [{ severity: "Low", explanation: "x", evidence: [] }],
    };
    const unknown: Rule = {
      id: "R1",
      title: "broken",
      evaluate: () => [{ severity: "Low", explanation: "x", evidence: [99999] }],
    };
    expect(judgeWith(esbuildLikeScenario(), [empty]).kind).toBe("ERROR");
    expect(judgeWith(esbuildLikeScenario(), [unknown]).kind).toBe("ERROR");
  });

  it("returns ERROR, not an exception, when a rule throws", () => {
    const boom: Rule = {
      id: "R1",
      title: "broken",
      evaluate: () => {
        throw new RangeError("boom");
      },
    };
    const v = judgeWith(esbuildLikeScenario(), [boom]);
    expect(v.kind).toBe("ERROR");
    expect(v.kind === "ERROR" && v.reason).toContain("RangeError");
  });

  it("only SAFE allows an install", () => {
    expect(allowsInstall(errorVerdict("x"))).toBe(false);
    expect(allowsInstall(judge(wormScenario()))).toBe(false);
  });

  it("escapes the reason it's given", () => {
    const v = errorVerdict("bad\u001b[2Jthing");
    expect(v.kind === "ERROR" && v.reason).not.toContain("\u001b");
  });
});

describe("caps", () => {
  it("caps findings at 25 per rule but keeps the verdict from all of them", () => {
    const input = npmInstall((t) => {
      t.exec(201, 100, "/bin/sh", ["sh"]);
      for (let i = 0; i < 30; i++) t.dns(`host-${i}.invalid`);
      t.exit(201, 0, 100);
    }).build();
    const v = judge(input);
    expect(v.kind).toBe("SUSPICIOUS");
    expect(v.findings.filter((f) => f.ruleId === "R3")).toHaveLength(25);
    expect(v.omittedFindings).toBe(5);
  });

  it("caps evidence at 20 per finding", () => {
    const v = judge(shaiHulud2Scenario());
    for (const f of v.findings) expect(f.evidence.length).toBeLessThanOrEqual(20);
  });
});

describe("kindFromFindings", () => {
  it("uses the highest severity", () => {
    expect(kindFromFindings([])).toBe("SAFE");
    expect(kindFromFindings([{ severity: "Medium" }, { severity: "Low" }])).toBe("SAFE");
    expect(kindFromFindings([{ severity: "High" }])).toBe("SUSPICIOUS");
    expect(kindFromFindings([{ severity: "High" }, { severity: "Critical" }])).toBe("MALICIOUS");
  });
});

describe("verdictCacheKey", () => {
  const id = { name: "@scope/pkg", version: "1.0.0", integrity: integrity() };

  it("builds a key from all four parts", () => {
    expect(verdictCacheKey(id, "1.0.0")).toBe(
      `verdict:v1:%40scope%2Fpkg:1.0.0:${encodeURIComponent(integrity())}:1.0.0`,
    );
  });

  it("changes when the integrity or ruleset changes", () => {
    expect(verdictCacheKey(id, "1.0.0")).not.toBe(
      verdictCacheKey({ ...id, integrity: integrity("B") }, "1.0.0"),
    );
    expect(verdictCacheKey(id, "1.0.0")).not.toBe(verdictCacheKey(id, "1.0.1"));
  });

  it("can't be confused by separators inside parts", () => {
    expect(verdictCacheKey({ ...id, name: "a:b", version: "c" }, "1")).not.toBe(
      verdictCacheKey({ ...id, name: "a", version: "b:c" }, "1"),
    );
  });

  it.each([
    [{ ...id, name: "" }, "1"],
    [{ ...id, name: "x".repeat(215) }, "1"],
    [{ ...id, version: "" }, "1"],
    [{ ...id, integrity: "sha1-abc" }, "1"],
    [{ ...id, integrity: `sha512-${"A".repeat(86)}=` }, "1"],
    [{ ...id, integrity: `${integrity()} sha384-x` }, "1"],
    [{ ...id, name: "\ud800" }, "1"],
    [id, ""],
  ])("rejects %j", (identity, ruleset) => {
    expect(() => verdictCacheKey(identity, ruleset)).toThrow(InvalidPackageIdentityError);
  });
});

describe("determinism", () => {
  it("gives the same verdict for a deep copy", () => {
    const input = wormScenario();
    expect(judge(clone(input))).toEqual(judge(input));
  });
});
