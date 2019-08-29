//import * as crypto from "crypto"
jest.mock("crypto", () => ({ randomBytes: (l: number) => Buffer.alloc(l) }))

import { PublicKeyCreateCredentialOptions } from "../publicKeyCreateCredentialOptions"
import { AttestationConveyance } from "../../types/attestationConveyance";
import { PubKeyCredType } from "../../types/pubKeyCredType";

describe('PublicKeyCreateCredentialOptions', () => {
  const rp = { name: "Jest Unit Test", id: "test.example.com" }
  const user = { id: "1", displayName: "Unit Test", name: "test.jest@example.com" }
  beforeAll(() => {

  })


  it("should return valid pubkey credential create options", () => {
    const pbcco = new PublicKeyCreateCredentialOptions(
      rp,
      user,
      AttestationConveyance.DIRECT,
      [{
        type: PubKeyCredType.PUBLIC_KEY, alg: -7
      }]
    )

    expect(pbcco).toHaveProperty("rp", rp);
    expect(pbcco).toHaveProperty("user", user);
    expect(pbcco).toHaveProperty("attestation", "direct");
    expect(pbcco).toHaveProperty("challenge", Buffer.from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "base64"));
    
    expect(pbcco).toHaveProperty("pubKeyCredParams", [{ type: "public-key", alg: -7 }])

    expect(pbcco.timeout).toBeUndefined();
    expect(pbcco.authenticatorSelection).toBeUndefined();
    expect(pbcco.excludeCredentials).toBeUndefined();

  })

  it("should return valid pubkey credential create options", () => {
    const pbcco = new PublicKeyCreateCredentialOptions(
      rp,
      user,
      AttestationConveyance.INDIRECT,
      [{
        type: PubKeyCredType.PUBLIC_KEY, alg: -7
      }]
    )

    expect(pbcco).toHaveProperty("attestation", "indirect");
  })

  it("should return valid pubkey credential create options", () => {
    const pbcco = new PublicKeyCreateCredentialOptions(
      rp,
      user,
      AttestationConveyance.DIRECT,
      [{
        type: PubKeyCredType.PUBLIC_KEY, alg: -7
      }],
      30000
    )

    expect(pbcco).toHaveProperty("timeout", 30000);
  })

  describe('toJSON', () => {
    it("should return valid pubkey credential create options", () => {
      const pbcco = new PublicKeyCreateCredentialOptions(
        rp,
        user,
        AttestationConveyance.DIRECT,
        [{
          type: PubKeyCredType.PUBLIC_KEY, alg: -7
        }]
      ).toJSON()
  
      expect(pbcco).toHaveProperty("challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
      expect(pbcco).toHaveProperty("rp", rp);
      expect(pbcco).toHaveProperty("user", user);
      expect(pbcco).toHaveProperty("attestation", "direct");
      
      expect(pbcco).toHaveProperty("pubKeyCredParams", [{ type: "public-key", alg: -7 }])
  
      expect(pbcco.timeout).toBeUndefined();
      expect(pbcco.authenticatorSelection).toBeUndefined();
      expect(pbcco.excludeCredentials).toBeUndefined();
    })
  });
});