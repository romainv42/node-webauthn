import * as crypto from "crypto"
import * as cbor from "cbor"
import base64url from "base64url";
import { Certificate } from "@fidm/x509"
import * as iso from "i18n-iso-countries"

import { AuthenticatorInfo, AuthenticatorFormat } from "../types/authenticatorInfo"
import { AttestationObject } from "../types/attestationObject";

import { ASN1toPEM, verifySignature, convertCOSEKey, hash } from "../utils"
import { VerifyResponse } from "../types/verifyResponse";

const U2F_USER_PRESENTED = 0x01;

interface WebAuthnAttestationResponse {
  attestationObject: string
  clientDataJSON: string
}

export class AuthenticatorAttestionResponse {
  response: WebAuthnAttestationResponse

  /**
   *
   */
  constructor(response: WebAuthnAttestationResponse) {
    this.response = response
  }

  verify(): VerifyResponse {
    const attObj = new AttestationObject(this.response.attestationObject)

    const response = new VerifyResponse()

    if (!(attObj.authData.flags & U2F_USER_PRESENTED))
      throw new Error('User was NOT presented durring authentication!')

    if (!attObj.attStmt.x5c || attObj.attStmt.x5c.length === 0)
      throw new Error('Missing certificates x5C')

    const clientDataHash = hash(base64url.toBuffer(this.response.clientDataJSON))
    const publicKey = convertCOSEKey(attObj.authData.COSEPublicKey)
    const PEMCertificate = ASN1toPEM(attObj.attStmt.x5c![0])

    let signatureBase: Buffer;
    if (attObj.fmt === AuthenticatorFormat.FIDO_U2F) {
      signatureBase = Buffer.concat([
        Buffer.from([0x00]),
        attObj.authData.rpIdHash,
        clientDataHash,
        attObj.authData.credId,
        publicKey
      ])
    } else if (attObj.fmt === AuthenticatorFormat.PACKED && attObj.attStmt.x5c) {
      signatureBase = Buffer.concat([attObj.authDataBuffer, clientDataHash])
      const pem = Certificate.fromPEM(Buffer.from(PEMCertificate, "utf8"))
      const aaguidExt = pem.getExtension('1.3.6.1.4.1.45724.1.1.4')

      let aaguidCheck = true
      if (aaguidExt != null) {
        aaguidCheck = !aaguidExt.critical && aaguidExt.value.slice(2).equals(attObj.authData.aaguid)
      }

      if (!(pem.version === 3 &&
        aaguidCheck &&
        iso.isValid(pem.subject.countryName) &&
        pem.subject.organizationName &&
        pem.subject.organizationalUnitName === "Authenticator Attestation" &&
        pem.subject.commonName &&
        !pem.isCA
      )) {
        return response
      }
    } else {
      throw new Error('Unsupported attestation format! ' + attObj.fmt)
    }
    response.verified = verifySignature(attObj.attStmt.sig, signatureBase, PEMCertificate)
    if (response.verified) {
      response.authrInfo = new AuthenticatorInfo(publicKey, attObj.authData.counter, attObj.authData.credId, AuthenticatorFormat.FIDO_U2F)
    }
    return response
  }
}