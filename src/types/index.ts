import { AllowCredential } from "./allowCredential"
import { AttestationConveyance } from "./attestationConveyance"
import { AuthenticatorAttachment, AuthenticatorSelectionCriteria } from "./authenticatorSelection"
import { AuthenticatorInfo, AuthenticatorFormat } from "./authenticatorInfo"
import { AuthenticatorTransport } from "./authenticatorTransport"
import { AttestationCredentialData, AssertionCredentialData } from "./credentialData"
import { PubKeyCredDescriptor } from "./pubKeyCredDescriptor"
import { PubKeyCredParam } from "./pubKeyCredParam"
import { PubKeyCredType } from "./pubKeyCredType"
import { RelyingParty } from "./relyingParty"
import { CredCreateUserInformation } from "./userInformation"
import { VerifyResponse } from "./verifyResponse"

export namespace Types {
  AllowCredential
  AssertionCredentialData
  AttestationConveyance
  AttestationCredentialData
  AuthenticatorAttachment
  AuthenticatorFormat
  AuthenticatorInfo
  AuthenticatorSelectionCriteria
  AuthenticatorTransport
  PubKeyCredDescriptor
  PubKeyCredParam
  PubKeyCredType
  RelyingParty
  CredCreateUserInformation
  VerifyResponse
}