import { rpc, Transaction } from "@stellar/stellar-sdk";
import type {
  SessionPolicyRule,
  SessionSimulationResult,
  SimulatedContractCall,
} from "./types.js";

/**
 * Pure client-side pre-validation of a contract call against a set of
 * `session-policy` rules without submitting a transaction to the network.
 */
export function simulateSessionPolicyCall(
  rules: SessionPolicyRule[],
  call: SimulatedContractCall
): SessionSimulationResult {
  if (call.contextRuleType !== "CallContract") {
    return {
      allowed: false,
      reason: "SessionError(2): Only CallContract context rules are permitted by session-policy",
    };
  }

  const matchingRules = rules.filter(
    (rule) => rule.targetContract === call.targetContract
  );

  if (matchingRules.length === 0) {
    return {
      allowed: false,
      reason: `SessionError(1): No session-policy rule installed for target ${call.targetContract}`,
    };
  }

  for (const rule of matchingRules) {
    if (
      rule.validUntilLedger !== undefined &&
      call.currentLedger > rule.validUntilLedger
    ) {
      continue;
    }
    if (rule.allowedFns.length === 0) {
      continue;
    }
    if (rule.allowedFns.includes(call.fnName)) {
      return {
        allowed: true,
        matchedRuleId: rule.contextRuleId,
      };
    }
  }

  const allExpired = matchingRules.every(
    (r) => r.validUntilLedger !== undefined && call.currentLedger > r.validUntilLedger
  );
  if (allExpired) {
    return {
      allowed: false,
      reason: "ContextRule expired: currentLedger exceeds validUntilLedger",
    };
  }

  return {
    allowed: false,
    reason: `SessionError(4): Method '${call.fnName}' is not in allowed_fns`,
  };
}

/**
 * Pre-validates a built Soroban `Transaction` via RPC `simulateTransaction`
 * combined with local session-policy rule evaluation.
 */
export async function simulateTransactionWithSessionPolicy(
  server: rpc.Server,
  tx: Transaction,
  rules: SessionPolicyRule[],
  call: SimulatedContractCall
): Promise<SessionSimulationResult & { rpcSimulated?: boolean }> {
  const localCheck = simulateSessionPolicyCall(rules, call);
  if (!localCheck.allowed) {
    return { ...localCheck, rpcSimulated: false };
  }

  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) {
    return {
      allowed: false,
      reason: `RPC simulation rejected transaction: ${sim.error}`,
      rpcSimulated: true,
    };
  }

  return {
    ...localCheck,
    rpcSimulated: true,
  };
}
