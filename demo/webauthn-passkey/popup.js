const output = document.getElementById("output");
const registerBtn = document.getElementById("registerBtn");
const signBtn = document.getElementById("signBtn");

let credentialId = null;

function toHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Registers a secp256r1 (ES256 / -7) WebAuthn passkey compatible with `webauthn-verifier`.
 */
registerBtn.addEventListener("click", async () => {
  try {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));

    const cred = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: "Latch Smart Account" },
        user: {
          id: userId,
          name: "latch-user@example.com",
          displayName: "Latch User",
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "required",
        },
      },
    });

    credentialId = cred.rawId;
    signBtn.disabled = false;
    output.textContent = JSON.stringify(
      {
        status: "registered",
        credentialIdHex: toHex(credentialId),
        note: "Extract 65-byte uncompressed P-256 key + credentialId for webauthn-verifier key_data.",
      },
      null,
      2
    );
  } catch (err) {
    output.textContent = `Registration error: ${err.message}`;
  }
});

/**
 * Signs a 32-byte Soroban auth payload hash and formats the WebAuthnSigData fields
 * (`authenticator_data`, `client_data`, `signature`) for Soroban submission.
 */
signBtn.addEventListener("click", async () => {
  try {
    const sorobanAuthHash = crypto.getRandomValues(new Uint8Array(32));
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: sorobanAuthHash,
        allowCredentials: [{ id: credentialId, type: "public-key" }],
        userVerification: "required",
      },
    });

    const resp = assertion.response;
    output.textContent = JSON.stringify(
      {
        status: "signed",
        authHashHex: toHex(sorobanAuthHash),
        authenticatorDataHex: toHex(resp.authenticatorData),
        clientDataJSON: new TextDecoder().decode(resp.clientDataJSON),
        derSignatureHex: toHex(resp.signature),
      },
      null,
      2
    );
  } catch (err) {
    output.textContent = `Signing error: ${err.message}`;
  }
});
