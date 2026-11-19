import { Address, Contract, nativeToScVal, rpc, scValToNative, TransactionBuilder, xdr } from "@stellar/stellar-sdk";

/**
 * Helper to encode `SessionAccountParams` for `session-policy` installation.
 */
export function encodeSessionPolicyParams(allowedFns: string[]): xdr.ScVal {
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: nativeToScVal("allowed_fns", { type: "symbol" }),
      val: xdr.ScVal.scvVec(
        allowedFns.map((fn) => nativeToScVal(fn, { type: "symbol" }))
      ),
    }),
  ]);
}

/**
 * Helper to encode `RecipientAllowlistParams` for `recipient-allowlist-policy`.
 */
export function encodeRecipientAllowlistParams(allowedRecipients: string[]): xdr.ScVal {
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: nativeToScVal("allowed_recipients", { type: "symbol" }),
      val: xdr.ScVal.scvVec(
        allowedRecipients.map((addr) => new Address(addr).toScVal())
      ),
    }),
  ]);
}

/**
 * Typed client for `session-policy`.
 */
export class SessionPolicyClient {
  public readonly contract: Contract;
  public readonly server: rpc.Server;
  public readonly networkPassphrase: string;

  constructor(contractId: string, rpcUrl: string, networkPassphrase: string) {
    this.contract = new Contract(contractId);
    this.server = new rpc.Server(rpcUrl);
    this.networkPassphrase = networkPassphrase;
  }

  /**
   * Reads `get_allowed_fns(context_rule_id, smart_account)` from `session-policy`.
   */
  async getAllowedFns(
    sourcePublicKey: string,
    contextRuleId: number,
    smartAccount: string
  ): Promise<string[]> {
    const account = await this.server.getAccount(sourcePublicKey);
    const tx = new TransactionBuilder(account, {
      fee: "100",
      networkPassphrase: this.networkPassphrase,
    })
      .addOperation(
        this.contract.call(
          "get_allowed_fns",
          nativeToScVal(contextRuleId, { type: "u32" }),
          new Address(smartAccount).toScVal()
        )
      )
      .setTimeout(30)
      .build();

    const sim = await this.server.simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim) || !sim.result) {
      throw new Error(`SessionPolicy simulation failed: ${JSON.stringify(sim)}`);
    }
    return scValToNative(sim.result.retval) as string[];
  }
}
