import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { simulateSessionPolicyCall } from "../src/session-simulator.js";
import type { SessionPolicyRule } from "../src/types.js";

const SAMPLE_RULES: SessionPolicyRule[] = [
  {
    smartAccount: "CACCOUNT111",
    contextRuleId: 1,
    targetContract: "CTOKEN111",
    allowedFns: ["transfer", "approve"],
    validUntilLedger: 5000,
  },
];

describe("simulateSessionPolicyCall", () => {
  it("allows an allowlisted function on the matching CallContract target before expiry", () => {
    const res = simulateSessionPolicyCall(SAMPLE_RULES, {
      targetContract: "CTOKEN111",
      fnName: "transfer",
      currentLedger: 4500,
      contextRuleType: "CallContract",
    });
    assert.equal(res.allowed, true);
    assert.equal(res.matchedRuleId, 1);
  });

  it("blocks a function not present in allowedFns", () => {
    const res = simulateSessionPolicyCall(SAMPLE_RULES, {
      targetContract: "CTOKEN111",
      fnName: "burn",
      currentLedger: 4500,
      contextRuleType: "CallContract",
    });
    assert.equal(res.allowed, false);
    assert.match(res.reason ?? "", /SessionError\(4\)/);
  });

  it("blocks calls when no rule exists for the target contract", () => {
    const res = simulateSessionPolicyCall(SAMPLE_RULES, {
      targetContract: "CUNKNOWN999",
      fnName: "transfer",
      currentLedger: 4500,
      contextRuleType: "CallContract",
    });
    assert.equal(res.allowed, false);
    assert.match(res.reason ?? "", /SessionError\(1\)/);
  });

  it("blocks calls when the session rule has expired", () => {
    const res = simulateSessionPolicyCall(SAMPLE_RULES, {
      targetContract: "CTOKEN111",
      fnName: "transfer",
      currentLedger: 5001,
      contextRuleType: "CallContract",
    });
    assert.equal(res.allowed, false);
    assert.match(res.reason ?? "", /expired/i);
  });

  it("blocks non-CallContract context types", () => {
    const res = simulateSessionPolicyCall(SAMPLE_RULES, {
      targetContract: "CTOKEN111",
      fnName: "transfer",
      currentLedger: 4500,
      contextRuleType: "Default",
    });
    assert.equal(res.allowed, false);
    assert.match(res.reason ?? "", /SessionError\(2\)/);
  });
});
