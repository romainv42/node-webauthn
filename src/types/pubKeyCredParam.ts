import { PubKeyCredType } from "./pubKeyCredType"

export class PubKeyCredParam {
  type: PubKeyCredType = PubKeyCredType.PUBLIC_KEY
  alg: number
  /**
   *
   */
  constructor(alg: number) {
    this.alg = alg
  }
}
