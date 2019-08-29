abstract class AbstractCredentialData {
  rpIdHash: Buffer
  flags: number
  counter: number

  protected rest?: number[]
  /**
   *
   */
  constructor(data: Buffer) {
    const array = [...data]
    this.rpIdHash = Buffer.from(array.splice(0, 32))
    this.flags = Buffer.from(array.splice(0, 1))[0]
    this.counter = Buffer.from(array.splice(0, 4)).readUInt32BE(0)

    if (array.length > 0) {
      this.rest = array
    }
  }
}


export class AttestationCredentialData extends AbstractCredentialData {
  aaguid: Buffer
  credId: Buffer
  COSEPublicKey: Buffer

  /**
   *
   */
  constructor(data: Buffer) {
    super(data)
    if (!this.rest) throw new Error("Inconsistent Attestion Credential Data")

    const array = this.rest
    this.rpIdHash = Buffer.from(array.splice(0, 32))
    this.flags = Buffer.from(array.splice(0, 1))[0]
    this.counter = Buffer.from(array.splice(0, 4)).readUInt32BE(0)
    this.aaguid = Buffer.from(array.splice(0, 16))
    const credIDLength = Buffer.from(array.splice(0, 2)).readUInt16BE(0)
    this.credId = Buffer.from(array.splice(0, credIDLength))
    this.COSEPublicKey = Buffer.from(array)
  }
}

export class AssertionCredentialData extends AbstractCredentialData {
}
