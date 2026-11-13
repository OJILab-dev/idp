// The test vectors of WebAuthn Level 3 §16 that fall inside this verifier's scope: attestation "none" or packed self
// attestation, one of the three COSE algorithms, user verification set, and no cross-origin client data. §16.3 is
// the one registration and §16.6 the one authentication with the UV flag set; §16.2 registers without UV, so it
// shows the user-verification requirement. All use the RP ID example.org and the origin https://example.org (§16).
import { describe, expect, it } from "vitest";
import { base64urlEncode } from "@idp/base64url";
import { verifyAuthentication, verifyRegistration, WebAuthnVerificationError } from "../src/index.js";

function hex(encoded: string): Uint8Array {
  return Uint8Array.from(encoded.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

const rp = { rpId: "example.org", origin: "https://example.org" };

// §16.2 ES256 Credential with No Attestation, registration.
const NONE_ES256 = {
  challenge: "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130",
  credentialId: "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4",
  clientDataJSON:
    "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d",
  attestationObject:
    "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220",
};

// §16.3 ES256 Credential with Self Attestation, registration.
const PACKED_SELF_ES256 = {
  challenge: "7869c2b772d4b58eba9378cf8f29e26cf935aa77df0da89fa99c0bdc0a76f7e5",
  credentialId: "455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58c",
  clientDataJSON:
    "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2265476e4374334c55745936366b336a506a796e6962506b31716e666644616966715a774c33417032392d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205539685458764b453255526b4d6e625f307859485667227d",
  attestationObject:
    "a363666d74667061636b65646761747453746d74a263616c672663736967584630440220067a20754ab925005dbf378097c92120031581c73228d1fb4f5b881bcd7da98302207fc7b147558c7c0eba3af18bd9d121fa3d3a26d17fe3f220272178f473b6006d68617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000df850e09db6afbdfab51697791506cfc0020455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58ca5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2",
  credentialPublicKey:
    "a5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2",
};

// §16.6 ES256 Credential with very long credential ID: the credential public key from its registration (whose
// authenticator data has BE set) and the authentication.
const LONG_ID_ES256 = {
  credentialPublicKey:
    "a50102032620012158203b8176b7504489cc593046d7988abb7905a742de6ac2cdc748a873c663e90cb12258201436d5edc9a75f23999eef9d5950a5c2455514ee1014084720f841a06b828a11",
  challenge: "ef1deba56dce48f674a447ccf63b9599258ce87648e5c396f2ef0ca1da460e3b",
  authenticatorData: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50d00000000",
  clientDataJSON:
    "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22377833727057334f53505a307045664d396a75566d53574d36485a4935634f573875384d6f647047446a73222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d",
  signature:
    "304502203ecef83fb12a0cae7841055f9f87103a99fd14b424194bbf06c4623d3ee6e3fd022100d2ace346db262b1374a6b70faa51f518a42ddca13a4125ce6f5052a75bac9fb6",
};

describe("WebAuthn Level 3 §16 test vectors", () => {
  it("verifies the §16.3 registration with packed self attestation", async () => {
    const verified = await verifyRegistration(
      {
        credentialId: base64urlEncode(hex(PACKED_SELF_ES256.credentialId)),
        clientDataJSON: hex(PACKED_SELF_ES256.clientDataJSON),
        attestationObject: hex(PACKED_SELF_ES256.attestationObject),
      },
      { challenge: base64urlEncode(hex(PACKED_SELF_ES256.challenge)), rp },
    );
    expect(verified).toEqual({
      credentialId: base64urlEncode(hex(PACKED_SELF_ES256.credentialId)),
      publicKey: hex(PACKED_SELF_ES256.credentialPublicKey),
      signCount: 0,
      backupEligible: true,
      backupState: true,
    });
  });

  it("rejects the §16.2 registration, whose authenticator data lacks the UV flag", async () => {
    const registration = verifyRegistration(
      {
        credentialId: base64urlEncode(hex(NONE_ES256.credentialId)),
        clientDataJSON: hex(NONE_ES256.clientDataJSON),
        attestationObject: hex(NONE_ES256.attestationObject),
      },
      { challenge: base64urlEncode(hex(NONE_ES256.challenge)), rp },
    );
    await expect(registration).rejects.toThrow(WebAuthnVerificationError);
    await expect(registration).rejects.toThrow(/user verification/);
  });

  it("verifies the §16.6 authentication", async () => {
    const verified = await verifyAuthentication(
      {
        credentialId: "unused: the caller looks the credential up",
        clientDataJSON: hex(LONG_ID_ES256.clientDataJSON),
        authenticatorData: hex(LONG_ID_ES256.authenticatorData),
        signature: hex(LONG_ID_ES256.signature),
        userHandle: undefined,
      },
      {
        challenge: base64urlEncode(hex(LONG_ID_ES256.challenge)),
        rp,
        credential: { publicKey: hex(LONG_ID_ES256.credentialPublicKey), signCount: 0, backupEligible: true, userHandle: new Uint8Array(16) },
        userHandleRequired: false,
      },
    );
    expect(verified).toEqual({ signCount: 0, backupState: false });
  });
});
