import { AuthenticatorInfo } from "./authenticatorInfo";

export class VerifyResponse {
  verified: boolean = false
  authrInfo?: AuthenticatorInfo
}