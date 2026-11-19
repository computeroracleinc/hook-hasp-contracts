import {
  Contract,
  Keypair,
  Networks,
  TransactionBuilder,
  nativeToScVal,
  rpc,
} from "@stellar/stellar-sdk";
import {
  LatchSmartAccountClient,
  encodeSessionPolicyParams,
} from "../src/index.js";

/**
 * Sample script demonstrating deploying a LatchSmartAccount via factory-contract
 * and executing a session-policy-scoped transaction on Stellar Testnet.
 *
 * Required env vars:
 *   TESTNET_SECRET_KEY   - Funded Stellar Testnet secret key (S...)
 *   FACTORY_CONTRACT_ID  - Deployed factory-contract ID (C...)
 *   SESSION_POLICY_ID    - Deployed session-policy contract ID (C...)
 *   TARGET_CONTRACT_ID   - Target dApp contract ID (C...)
 */
async function main() {
  const secret = process.env.TESTNET_SECRET_KEY;
  const factoryId = process.env.FACTORY_CONTRACT_ID;
  const sessionPolicyId = process.env.SESSION_POLICY_ID;
  const targetContractId = process.env.TARGET_CONTRACT_ID;

  if (!secret || !factoryId || !sessionPolicyId || !targetContractId) {
    throw new Error(
      "Missing required env vars: TESTNET_SECRET_KEY, FACTORY_CONTRACT_ID, SESSION_POLICY_ID, TARGET_CONTRACT_ID"
    );
  }

  const rpcUrl = "https://soroban-testnet.stellar.org";
  const server = new rpc.Server(rpcUrl);
  const signer = Keypair.fromSecret(secret);
  const sourceAccount = await server.getAccount(signer.publicKey());

  // 1. Deploy smart account via factory-contract
  const factory = new Contract(factoryId);
  const salt = new Uint8Array(32).fill(7);
  const deployTx = new TransactionBuilder(sourceAccount, {
    fee: "100000",
    networkPassphrase: Networks.TESTNET,
  })
    .addOperation(
      factory.call(
        "deploy",
        nativeToScVal(Buffer.from(salt), { type: "bytes" }),
        nativeToScVal([], { type: "vec" }),
        nativeToScVal([], { type: "map" })
      )
    )
    .setTimeout(60)
    .build();

  const preparedDeploy = await server.prepareTransaction(deployTx);
  preparedDeploy.sign(signer);
  const deployResp = await server.sendTransaction(preparedDeploy);
  console.log("Submitted factory deploy tx:", deployResp.hash);

  // 2. Configure a session rule on the deployed smart account
  const smartAccountId = process.env.SMART_ACCOUNT_ID ?? factoryId;
  const accountClient = new LatchSmartAccountClient({
    contractId: smartAccountId,
    rpcUrl,
    networkPassphrase: Networks.TESTNET,
  });

  const sessionKey = Keypair.random();
  const policyMap = new Map();
  policyMap.set(sessionPolicyId, encodeSessionPolicyParams(["transfer", "swap"]));

  const refreshedAccount = await server.getAccount(signer.publicKey());
  const ruleTx = new TransactionBuilder(refreshedAccount, {
    fee: "100000",
    networkPassphrase: Networks.TESTNET,
  })
    .addOperation(
      accountClient.buildAddContextRuleOp(
        { kind: "CallContract", contractAddress: targetContractId },
        "dapp-session",
        undefined,
        [{ kind: "Delegated", address: sessionKey.publicKey() }],
        policyMap
      )
    )
    .setTimeout(60)
    .build();

  const preparedRule = await server.prepareTransaction(ruleTx);
  preparedRule.sign(signer);
  const ruleResp = await server.sendTransaction(preparedRule);
  console.log("Submitted add_context_rule tx:", ruleResp.hash);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
