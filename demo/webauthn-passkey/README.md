# WebAuthn Passkey Browser Extension Demo

Minimal Chrome/Chromium Manifest V3 extension demonstrating WebAuthn P-256 (`alg: -7`) passkey registration and Soroban auth payload hash signing for `latch-verifiers/webauthn-verifier`.

## Loading in Chrome

1. Open `chrome://extensions/` and enable **Developer mode**.
2. Click **Load unpacked** and select `demo/webauthn-passkey/`.
3. Click the extension icon to register a passkey and sign a sample 32-byte Soroban auth hash.
