import { PubKeyCredType } from "./pubKeyCredType"
import { AuthenticatorTransport } from "./authenticatorTransport"

export class AllowCredential {
  type: PubKeyCredType = PubKeyCredType.PUBLIC_KEY
  id: Buffer
  transports: Array<AuthenticatorTransport>

  private defaultTransports = [
    AuthenticatorTransport.BLE,
    AuthenticatorTransport.NFC,
    AuthenticatorTransport.USB
  ]

  /**
   *
   */
  constructor(id: Buffer, transports?: Array<AuthenticatorTransport>, type?: PubKeyCredType) {
    this.id = id
    this.transports = transports || this.defaultTransports
    if ( type) this.type = type
  }
}