import { PubKeyCredType } from "./pubKeyCredType"
import { AuthenticatorTransport } from "./authenticatorTransport"

export class PubKeyCredDescriptor {
  type: PubKeyCredType = PubKeyCredType.PUBLIC_KEY
  id: Buffer
  transports?: Array<AuthenticatorTransport>

  /**
   *
   */
  constructor(id: Buffer, transports?: Array<AuthenticatorTransport>) {
    this.id = id
    this.transports = transports
  }
}