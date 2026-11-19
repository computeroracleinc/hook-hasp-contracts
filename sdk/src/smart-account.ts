import {
  Address,
  Contract,
  nativeToScVal,
  rpc,
  scValToNative,
  TransactionBuilder,
  xdr,
} from "@stellar/stellar-sdk";
import type { ContextRuleType, DeployedContractRecord, SignerType } from "./types.js";

export interface SmartAccountClientOptions {
  contractId: string;
  rpcUrl: string;
  networkPassphrase: string;
}

function encodeSigner(signer: SignerType): xdr.ScVal {
  if (signer.kind === "Delegated") {
    return xdr.ScVal.scvVec([
      nativeToScVal("Delegated", { type: "symbol" }),
      new Address(signer.address).toScVal(),
    ]);
  }
  return xdr.ScVal.scvVec([
    nativeToScVal("External", { type: "symbol" }),
    new Address(signer.verifier).toScVal(),
    nativeToScVal(Buffer.from(signer.keyData), { type: "bytes" }),
  ]);
}

function encodeContextRuleType(ruleType: ContextRuleType): xdr.ScVal {
  if (ruleType.kind === "Default") {
    return xdr.ScVal.scvVec([nativeToScVal("Default", { type: "symbol" })]);
  }
  if (ruleType.kind === "CallContract") {
    return xdr.ScVal.scvVec([
      nativeToScVal("CallContract", { type: "symbol" }),
      new Address(ruleType.contractAddress).toScVal(),
    ]);
  }
  return xdr.ScVal.scvVec([
    nativeToScVal("CreateContract", { type: "symbol" }),
    nativeToScVal(Buffer.from(ruleType.wasmHash), { type: "bytes" }),
  ]);
}

/**
 * Typed client bindings for `LatchSmartAccount`.
 */
export class LatchSmartAccountClient {
  public readonly contract: Contract;
  public readonly server: rpc.Server;
  public readonly networkPassphrase: string;

  constructor(options: SmartAccountClientOptions) {
    this.contract = new Contract(options.contractId);
    this.server = new rpc.Server(options.rpcUrl);
    this.networkPassphrase = options.networkPassphrase;
  }

  /**
   * Builds a `batch_add_signer` operation for an existing context rule.
   */
  buildBatchAddSignerOp(contextRuleId: number, signers: SignerType[]): xdr.Operation {
    return this.contract.call(
      "batch_add_signer",
      nativeToScVal(contextRuleId, { type: "u32" }),
      xdr.ScVal.scvVec(signers.map(encodeSigner))
    );
  }

  /**
   * Builds an `add_context_rule` operation on the smart account.
   */
  buildAddContextRuleOp(
    contextType: ContextRuleType,
    name: string,
    validUntil: number | undefined,
    signers: SignerType[],
    policies: Map<string, xdr.ScVal>
  ): xdr.Operation {
    const validUntilVal =
      validUntil === undefined
        ? xdr.ScVal.scvVoid()
        : nativeToScVal(validUntil, { type: "u32" });
    const policyEntries = Array.from(policies.entries()).map(
      ([addr, val]) =>
        new xdr.ScMapEntry({
          key: new Address(addr).toScVal(),
          val,
        })
    );
    return this.contract.call(
      "add_context_rule",
      encodeContextRuleType(contextType),
      nativeToScVal(name, { type: "string" }),
      validUntilVal,
      xdr.ScVal.scvVec(signers.map(encodeSigner)),
      xdr.ScVal.scvMap(policyEntries)
    );
  }

  /**
   * Builds a `deploy_contract` operation to deploy a satellite contract from the account.
   */
  buildDeployContractOp(
    wasmHash: Uint8Array,
    salt: Uint8Array,
    constructorArgs: xdr.ScVal[] = []
  ): xdr.Operation {
    return this.contract.call(
      "deploy_contract",
      nativeToScVal(Buffer.from(wasmHash), { type: "bytes" }),
      nativeToScVal(Buffer.from(salt), { type: "bytes" }),
      xdr.ScVal.scvVec(constructorArgs)
    );
  }

  /**
   * Queries `get_deployed_contract_count` via Soroban RPC simulation.
   */
  async getDeployedContractCount(sourcePublicKey: string): Promise<number> {
    const account = await this.server.getAccount(sourcePublicKey);
    const tx = new TransactionBuilder(account, {
      fee: "100",
      networkPassphrase: this.networkPassphrase,
    })
      .addOperation(this.contract.call("get_deployed_contract_count"))
      .setTimeout(30)
      .build();

    const sim = await this.server.simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim) || !sim.result) {
      throw new Error(`Simulation failed: ${JSON.stringify(sim)}`);
    }
    return Number(scValToNative(sim.result.retval));
  }

  /**
   * Queries `get_deployed_contract(index)` via Soroban RPC simulation.
   */
  async getDeployedContract(
    sourcePublicKey: string,
    index: number
  ): Promise<DeployedContractRecord> {
    const account = await this.server.getAccount(sourcePublicKey);
    const tx = new TransactionBuilder(account, {
      fee: "100",
      networkPassphrase: this.networkPassphrase,
    })
      .addOperation(
        this.contract.call(
          "get_deployed_contract",
          nativeToScVal(index, { type: "u32" })
        )
      )
      .setTimeout(30)
      .build();

    const sim = await this.server.simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim) || !sim.result) {
      throw new Error(`Simulation failed: ${JSON.stringify(sim)}`);
    }
    const decoded = scValToNative(sim.result.retval) as {
      address: string;
      wasm_hash: Uint8Array;
    };
    return {
      address: decoded.address,
      wasmHash: decoded.wasm_hash,
    };
  }
}
