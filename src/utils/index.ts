import * as crypto from "crypto"
import * as cbor from "cbor"

export function ASN1toPEM(buffer: Buffer): string {
  if (!Buffer.isBuffer(buffer)) throw new Error("ASN1 should be a buffer")
  let type = "CERTIFICATE"
  if (buffer.length == 65 && buffer[0] == 0x04) {
    /*
        If needed, we encode rawpublic key to ASN structure, adding metadata:
        SEQUENCE {
          SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
             OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
          }
          BITSTRING <raw public key>
        }
        Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
    */

    buffer = Buffer.concat([
      Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
      buffer
    ]);

    type = "PUBLIC KEY";
  }
  //.replace(/.{1,64}/g, '$&\n')
  return `-----BEGIN ${type}-----\n${buffer.toString("base64").replace(/.{1,64}/g, '$&\n')}-----END ${type}-----\n`;
}

export function verifySignature (signature: Buffer, data: Buffer, publicKey: string) {
  return crypto.createVerify('SHA256')
      .update(data)
      .verify(publicKey, signature);
}

export function convertCOSEKey(pubKey: Buffer): Buffer {
  const coseStruct = cbor.decodeAllSync(pubKey)[0]
  const tag = Buffer.from([0x04]);
  const x = coseStruct.get(-2);
  const y = coseStruct.get(-3);

  return Buffer.concat([tag, x, y])
}