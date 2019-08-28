import base64url from "base64url";

export enum AuthenticatorFormat {
  FIDO_U2F = "fido-udf",
  PACKED = "packed"
}

export class AuthenticatorInfo {
  fmt: AuthenticatorFormat = AuthenticatorFormat.FIDO_U2F
  publicKey: Buffer
  counter: number
  credId: Buffer

  /**
   *
   */
  constructor(publicKey: Buffer, counter: number, credId: Buffer, fmt?: AuthenticatorFormat) {
    this.publicKey = publicKey
    this.counter = counter
    this.credId = credId
    if (fmt) {
      this.fmt = fmt
    }
  }

  toJSON(): any {
    return { 
      ...this,
      publicKey: base64url.encode(this.publicKey),
      credId: base64url.encode(this.credId),
    }
  }
}
