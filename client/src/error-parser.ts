/**
 * JSON-RPC Soroban contract error response parser for user-facing dApp feedback.
 */

export interface ParsedSorobanError {
  code?: number;
  contract?: string;
  message: string;
  raw: string;
}

export const SOROBAN_ERROR_DICTIONARY: Record<number, string> = {
  // SessionPolicy (policies/session-policy)
  1: "Session policy is not installed for this smart account rule.",
  2: "Session policy only supports CallContract context rules.",
  3: "Session policy allowed_fns list is empty or exceeds the maximum.",
  4: "This contract method is not permitted by the active session policy.",
  5: "Session policy is already installed for this context rule.",

  // Spending limit / Multi-token spending limit
  101: "Spending limit exceeded for this asset.",
  102: "Spending limit period has not been initialized.",
  103: "Oracle price is stale or unavailable for this asset.",
  104: "Token decimals or price conversion overflowed.",

  // SmartAccountError (stellar-accounts 3000+)
  3000: "Context rule not found on this smart account.",
  3001: "Signer is not authorized for this context rule.",
  3002: "Context rule has expired.",
  3119: "Invalid WebAuthn public key length (expected >= 65 bytes).",

  // LatchSmartAccountError (latch-smart-account 4000+)
  4000: "No deployed satellite contract found at the requested index.",
  4001: "Deployed contract counter reached maximum capacity (u32::MAX).",
};

const CONTRACT_ERROR_REGEX = /Error\(Contract,\s*#(\d+)\)/i;

/**
 * Parses a raw Soroban JSON-RPC error string or object into a user-friendly message.
 */
export function parseSorobanRpcError(errorInput: unknown): ParsedSorobanError {
  const raw =
    typeof errorInput === "string"
      ? errorInput
      : errorInput instanceof Error
        ? errorInput.message
        : JSON.stringify(errorInput);

  const match = raw.match(CONTRACT_ERROR_REGEX);
  if (match) {
    const code = Number(match[1]);
    const translated =
      SOROBAN_ERROR_DICTIONARY[code] ??
      `Contract execution failed with error code #${code}.`;
    return { code, message: translated, raw };
  }

  if (/tx_insufficient_fee/i.test(raw)) {
    return { message: "Transaction fee is too low for current network congestion.", raw };
  }
  if (/tx_bad_seq/i.test(raw)) {
    return { message: "Account sequence number is out of date. Please retry.", raw };
  }

  return {
    message: "Transaction failed during Soroban simulation or submission.",
    raw,
  };
}
