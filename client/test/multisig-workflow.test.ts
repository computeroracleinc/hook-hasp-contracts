import assert from "node:assert/strict";
import { describe, it } from "node:test";
import crypto from "node:crypto";
import { Keypair } from "@stellar/stellar-sdk";
import { parseSorobanRpcError } from "../src/error-parser.js";

interface DetachedSignaturePacket {
  signerPublicKey: string;
  signatureBase64: string;
}

/**
 * Simulates disconnected multi-sig approval collection:
 *   Client A signs payload -> transmits signature packet ->
 *   Client B signs payload -> coordinator aggregates & verifies threshold.
 */
function collectAndVerifyMultisig(
  payloadHash: Buffer,
  packets: DetachedSignaturePacket[],
  threshold: number
): { approved: boolean; validSigners: string[] } {
  const validSigners = new Set<string>();

  for (const pkt of packets) {
    const kp = Keypair.fromPublicKey(pkt.signerPublicKey);
    const sig = Buffer.from(pkt.signatureBase64, "base64");
    if (kp.verify(payloadHash, sig)) {
      validSigners.add(pkt.signerPublicKey);
    }
  }

  return {
    approved: validSigners.size >= threshold,
    validSigners: Array.from(validSigners),
  };
}

describe("Multi-sig approval workflow across disconnected clients", () => {
  it("completes 2-of-2 approval when Client A and Client B sign independently", () => {
    const payloadHash = crypto.createHash("sha256").update("soroban-auth-payload-v1").digest();

    // Disconnected Client A
    const clientA = Keypair.random();
    const packetA: DetachedSignaturePacket = {
      signerPublicKey: clientA.publicKey(),
      signatureBase64: clientA.sign(payloadHash).toString("base64"),
    };

    // Disconnected Client B
    const clientB = Keypair.random();
    const packetB: DetachedSignaturePacket = {
      signerPublicKey: clientB.publicKey(),
      signatureBase64: clientB.sign(payloadHash).toString("base64"),
    };

    const result = collectAndVerifyMultisig(payloadHash, [packetA, packetB], 2);
    assert.equal(result.approved, true);
    assert.deepEqual(result.validSigners, [clientA.publicKey(), clientB.publicKey()]);
  });

  it("rejects execution when threshold is not met or duplicate signer is replayed", () => {
    const payloadHash = crypto.createHash("sha256").update("soroban-auth-payload-v1").digest();
    const clientA = Keypair.random();
    const packetA: DetachedSignaturePacket = {
      signerPublicKey: clientA.publicKey(),
      signatureBase64: clientA.sign(payloadHash).toString("base64"),
    };

    const result = collectAndVerifyMultisig(payloadHash, [packetA, packetA], 2);
    assert.equal(result.approved, false);
    assert.equal(result.validSigners.length, 1);
  });

  it("translates Soroban JSON-RPC error 101 to human-readable message", () => {
    const parsed = parseSorobanRpcError("HostError: Error(Contract, #101)");
    assert.equal(parsed.code, 101);
    assert.equal(parsed.message, "Spending limit exceeded for this asset.");
  });
});
