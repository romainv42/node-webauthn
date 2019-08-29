import { PubKeyCredType } from "../types/pubKeyCredType";
import { Interface } from "readline";
import { AuthenticatorInfo, AuthenticatorFormat } from "../types/authenticatorInfo";
import base64url from "base64url";
import { AssertionCredentialData } from "../types/credentialData";
import { VerifyResponse } from "../types/verifyResponse";
import { hash, ASN1toPEM, verifySignature } from "../utils"
const U2F_USER_PRESENTED = 0x01;

class InnerWebAuthnResponse {
  authenticatorData: Buffer
  signature: Buffer
  // userHandle: any // TODO: Determine what is this
  clientDataJson: Buffer

  /**
   *
   */
  constructor(response: any) {
    if (!response.hasOwnProperty("authenticatorData") ||
      !response.hasOwnProperty("signature") ||
      !response.hasOwnProperty("clientDataJson")) {
      throw new Error("Unable to parse response")
    }

    this.authenticatorData = Buffer.isBuffer(response.authenticatorData) ? response.authenticatorData : base64url.decode(response.authenticatorData)
    this.signature = Buffer.isBuffer(response.signature) ? response.signature : base64url.decode(response.signature)
    this.clientDataJson = Buffer.isBuffer(response.clientDataJson) ? response.clientDataJson : base64url.decode(response.clientDataJson)
  }
}

export class AuthenticatorAssertionResponse {
  rawId: Buffer
  id: Buffer
  type: PubKeyCredType
  // getClientExtensionsResults: Array<any> // TODO: Determine what are these extensions
  response: InnerWebAuthnResponse

  /**
   *
   */
  constructor(response: any)  {
    if (!response.hasOwnProperty("rawId") ||
      !response.hasOwnProperty("id") ||
      !response.hasOwnProperty("response")) {
      throw new Error("Unable to parse response")
    }

    this.rawId = Buffer.isBuffer(response.rawId) ? response.rawId : base64url.decode(response.rawId)
    this.id = Buffer.isBuffer(response.id) ? response.id : base64url.decode(response.id)
    this.type = response.type
    this.response = new InnerWebAuthnResponse(response.response)
  }

  verify(authenticators: Array<AuthenticatorInfo>) : VerifyResponse {
    if (authenticators.length === 0) throw new Error("Enable to verify a signature without authenticator")

    const authenticator = authenticators.find(a => a.credId.equals(this.id))
    if (!authenticator) throw new Error("Authenticator not found")
    if (authenticator.fmt !== AuthenticatorFormat.FIDO_U2F) throw new Error("Not Supported: FIDO-U2F only")
    
    const authData = new AssertionCredentialData(this.response.authenticatorData)

    const result = new VerifyResponse()

    if (!(authData.flags & U2F_USER_PRESENTED)) throw new Error('User was NOT presented during authentication!')

    const clientDataHash = hash(this.response.clientDataJson)
    const signatureBase = Buffer.concat([
      authData.rpIdHash,
      Buffer.from([authData.flags]),
      Buffer.from([authData.counter]),
      clientDataHash
    ])

    const publicKey = ASN1toPEM(authenticator.publicKey) 
    result.verified = verifySignature(this.response.signature, signatureBase, publicKey) && authenticator.counter < authData.counter

    if (result.verified) {
      authenticator.counter = authData.counter
      result.authrInfo = authenticator
    }

    return result
  }
}