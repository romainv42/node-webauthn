import * as cbor from "cbor"
import base64url from "base64url";

import { AuthenticatorFormat } from "./authenticatorInfo"
import { AttestationCredentialData } from "./credentialData";

export interface AttestationStatement {
  alg: number
  sig: Buffer
  x5c?: Array<Buffer>
  ecdaaKeyId?: Buffer
}


export class AttestationObject {
  authData: AttestationCredentialData
  fmt: AuthenticatorFormat
  attStmt: AttestationStatement

  public authDataBuffer: Buffer
  /**
   *
   */
  constructor(data: Buffer | string) {
    const buffer = this.getBuffer(data)
    const res = cbor.decodeAllSync(buffer)[0]
    this.fmt = res.fmt
    this.attStmt = res.attStmt as AttestationStatement
    this.authDataBuffer = res.authData
    this.authData = new AttestationCredentialData(res.authData)
  }

  private getBuffer(data: Buffer | string): Buffer {
    if (Buffer.isBuffer(data)) {
      return data
    }
    return base64url.toBuffer(data)
  }
}
