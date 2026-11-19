#!/usr/bin/env node
/**
 * CLI tool to inspect and decode `latch-smart-account` on-chain storage entries.
 *
 * Usage:
 *   node scripts/inspect-account.mjs --contract <C...> [--rpc <url>] [--max-rules 16]
 */
import { Address, Contract, rpc, scValToNative, xdr } from "@stellar/stellar-sdk";

function parseArgs(argv) {
  const args = {
    rpc: "https://soroban-testnet.stellar.org",
    maxRules: 16,
    contract: "",
  };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--contract" && argv[i + 1]) args.contract = argv[++i];
    else if (argv[i] === "--rpc" && argv[i + 1]) args.rpc = argv[++i];
    else if (argv[i] === "--max-rules" && argv[i + 1]) args.maxRules = Number(argv[++i]);
  }
  if (!args.contract) {
    console.error("Usage: inspect-account.mjs --contract <CONTRACT_ID> [--rpc <URL>] [--max-rules <N>]");
    process.exit(1);
  }
  return args;
}

function decodeStorageKey(scVal) {
  try {
    return scValToNative(scVal);
  } catch {
    return scVal.toXDR("base64");
  }
}

async function main() {
  const { contract, rpc: rpcUrl, maxRules } = parseArgs(process.argv);
  const server = new rpc.Server(rpcUrl);
  const contractAddr = new Address(contract);

  // 1. Fetch contract instance entry (contains instance storage + WASM hash)
  const instanceKey = xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: contractAddr.toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
    })
  );

  // 2. Probe LatchSmartAccountStorageKey::DeployedContractCount & ContextRule entries
  const keys = [instanceKey];
  for (let i = 0; i < maxRules; i++) {
    keys.push(
      xdr.LedgerKey.contractData(
        new xdr.LedgerKeyContractData({
          contract: contractAddr.toScAddress(),
          key: xdr.ScVal.scvVec([
            xdr.ScVal.scvSymbol("DeployedContract"),
            xdr.ScVal.scvU32(i),
          ]),
          durability: xdr.ContractDataDurability.persistent(),
        })
      )
    );
  }

  const response = await server.getLedgerEntries(...keys);
  console.log(`\n=== LatchSmartAccount Inspection: ${contract} ===`);
  console.log(`RPC: ${rpcUrl}`);
  console.log(`Latest Ledger: ${response.latestLedger}\n`);

  for (const entry of response.entries ?? []) {
    const ledgerData = entry.val.contractData();
    const keyDecoded = decodeStorageKey(ledgerData.key());
    const valDecoded = decodeStorageKey(ledgerData.val());

    if (ledgerData.key().switch().name === "scvLedgerKeyContractInstance") {
      const instance = ledgerData.val().instance();
      const exec = instance.executable();
      console.log("[Instance Metadata]");
      console.log(`  Executable: ${exec.switch().name}`);
      if (exec.switch().name === "contractExecutableWasm") {
        console.log(`  WASM Hash:  ${Buffer.from(exec.wasmHash()).toString("hex")}`);
      }
      const storage = instance.storage() ?? [];
      console.log(`  Instance Storage Entries (${storage.length}):`);
      for (const item of storage) {
        console.log(`    - ${JSON.stringify(decodeStorageKey(item.key()))}: ${JSON.stringify(decodeStorageKey(item.val()))}`);
      }
    } else {
      console.log(`[Persistent Entry] ${JSON.stringify(keyDecoded)} => ${JSON.stringify(valDecoded)}`);
    }
  }
}

main().catch((err) => {
  console.error("Inspection failed:", err);
  process.exit(1);
});
