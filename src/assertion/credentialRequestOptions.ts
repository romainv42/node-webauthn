import * as crypto from "crypto"

import { AllowCredential } from "../types/allowCredential"
import { AuthenticatorInfo } from "../types/authenticatorInfo"
import { AuthenticatorTransport } from "../types/authenticatorTransport";
import base64url from "base64url";

export class CredentialRequestOptions {
  challenge: Buffer
  allowCredentials: Array<AllowCredential>

  /**
   *
   */
  constructor(authenticators: Array<AuthenticatorInfo>, defaultTransports?: Array<AuthenticatorTransport>) {
    if (authenticators.length === 0) throw new Error("Unable to create credentialRequestOptions without authenticator")

    this.allowCredentials = authenticators.map(a => new AllowCredential(a.credId, defaultTransports))
    this.challenge = crypto.randomBytes(32)
  }

  toJSON() {
    return {
      ...this,
      challenge: base64url.encode(this.challenge)
    }
  }
}
