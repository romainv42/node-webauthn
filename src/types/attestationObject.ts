import * as cbor from "cbor"
import base64url from "base64url";

import { AuthenticatorFormat } from "./authenticatorInfo"

interface AttestationStatement {
  alg: number
  sig: Buffer
  x5c?: Array<Buffer>
  ecdaaKeyId?: Buffer
}

class AttestationCredentialData {
  rpIdHash: Buffer
  flags: number
  counter: number
  aaguid: Buffer
  credId: Buffer
  COSEPublicKey: Buffer

  /**
   *
   */
  constructor(data: Buffer) {
    const array = [...data]
    this.rpIdHash = Buffer.from(array.splice(0, 32))
    this.flags = Buffer.from(array.splice(0, 1))[0]
    this.counter = Buffer.from(array.splice(0, 4)).readUInt32BE(0)
    this.aaguid = Buffer.from(array.splice(0, 16))
    const credIDLength = Buffer.from(array.splice(0, 2)).readUInt16BE(0)
    this.credId = Buffer.from(array.splice(0, credIDLength))
    this.COSEPublicKey = Buffer.from(array)
  }
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
