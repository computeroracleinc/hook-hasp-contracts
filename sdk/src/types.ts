export type SignerType =
  | { kind: "Delegated"; address: string }
  | { kind: "External"; verifier: string; keyData: Uint8Array };

export type ContextRuleType =
  | { kind: "Default" }
  | { kind: "CallContract"; contractAddress: string }
  | { kind: "CreateContract"; wasmHash: Uint8Array };

export interface ContextRule {
  id: number;
  contextType: ContextRuleType;
  name: string;
  signers: SignerType[];
  policies: string[];
  validUntil?: number;
}

export interface DeployedContractRecord {
  address: string;
  wasmHash: Uint8Array;
}

export interface SessionPolicyRule {
  smartAccount: string;
  contextRuleId: number;
  allowedFns: string[];
  targetContract: string;
  validUntilLedger?: number;
}

export interface SimulatedContractCall {
  targetContract: string;
  fnName: string;
  currentLedger: number;
  contextRuleType: ContextRuleType["kind"];
}

export interface SessionSimulationResult {
  allowed: boolean;
  reason?: string;
  matchedRuleId?: number;
}
