import { AuthenticatorInfo } from "../authenticatorInfo"

describe('AuthenticatorInfo', () => {
  const expected = {
    fmt: 'fido-udf',
    publicKey: 'YWFhYWFhYWFhYWFhYWFhYQ',
    counter: 1,
    credId: 'YWFhYWFhYWFhYWFhYWFhYQ'
  }

  it('should convert buffers to base64url', () => {
    const a = new AuthenticatorInfo(Buffer.allocUnsafe(16).fill('a'), 1, Buffer.allocUnsafe(16).fill('a'))
    expect(a.toJSON()).toStrictEqual(expected);
  })
})