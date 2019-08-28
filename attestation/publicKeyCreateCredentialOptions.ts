

import base64url from "base64url";
import * as crypto from "crypto";

import { RelyingParty } from "../types/relyingParty";
import { CredCreateUserInformation } from "../types/userInformation";
import { AttestationConveyance } from "../types/attestationConveyance";
import { PubKeyCredParam } from "../types/pubKeyCredParam";
import { AuthenticatorSelectionCriteria } from "../types/authenticatorSelection";
import { PubKeyCredDescriptor } from "../types/pubKeyCredDescriptor";

// import 

export class PublicKeyCreateCredentialOptions {
  challenge: Buffer
  rp: RelyingParty
  user: CredCreateUserInformation
  attestation: AttestationConveyance
  pubKeyCredParams: Array<PubKeyCredParam>
  timeout?: number
  authenticatorSelection?: AuthenticatorSelectionCriteria
  excludeCredentials?: Array<PubKeyCredDescriptor>
  /**
   *
   */
  constructor(
    rp: RelyingParty,
    user: CredCreateUserInformation,
    attestation: AttestationConveyance,
    pubKeyCredParams: Array<PubKeyCredParam>,
    timeout?: number,
    authenticatorSelection?: AuthenticatorSelectionCriteria,
    excludeCredentials?: Array<PubKeyCredDescriptor>,
  ) {

    this.challenge = crypto.randomBytes(32)
    this.rp = rp
    this.user = user
    this.attestation = attestation
    this.pubKeyCredParams = pubKeyCredParams
    this.timeout = timeout
    this.authenticatorSelection = authenticatorSelection
    this.excludeCredentials = excludeCredentials
  }

  toJSON() : any {
    return {
      ...this,
      challenge: base64url(this.challenge)
    }
  }
}