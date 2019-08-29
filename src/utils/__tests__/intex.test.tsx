import { createBrotliCompress } from "zlib";

const { ASN1toPEM, convertCOSEKey, verifySignature } = require("../index")

describe("Utils", () => {
  describe("ASN1toPEM", () => {
    let mock = {
      pubkey: {
        buffer: Buffer.concat([Buffer.from([0x04]), Buffer.allocUnsafe(64).fill(11)]),
        base64: "BAsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws=",
        pem: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECwsLCwsLCwsLCwsLCwsLCwsLCwsL\nCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==\n-----END PUBLIC KEY-----\n"
      },
      certificate: {
        buffer: Buffer.allocUnsafe(128).fill(42),
        base64: "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=",
        pem: "-----BEGIN CERTIFICATE-----\nKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioq\nKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioq\nKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=\n-----END CERTIFICATE-----\n"
      }
    }

    it("should return Public Key PEM", () => {
      const result = ASN1toPEM(mock.pubkey.buffer)
      expect(result).toBe(mock.pubkey.pem)
    });

    it("should return Certificate PEM", () => {
      const result = ASN1toPEM(mock.certificate.buffer)
      expect(result).toBe(mock.certificate.pem)
    });

    it("should throw an error", () => {
      expect(() => {
        ASN1toPEM(mock.certificate.base64)
      }).toThrow()
    });
  })

  describe('convertCOSEKey', () => {
    const mock = [{
      key: Buffer.from("a601020278246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c235820aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf", "hex"),
      pubkey: Buffer.from("0465eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c", "hex")
    }, {
      key: Buffer.from("a52001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff22582020138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e010202623131", "hex"),
      pubkey: Buffer.from("04bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e", "hex")
    }];

    it.each(mock.map(o => [o.key, o.pubkey]))(
      "should return the pubkey",
      (input, expected) => {
        expect(convertCOSEKey(input).toString("hex")).toBe(expected.toString("hex"));
      }
    )
  });

  describe.skip('verifySignature', () => {
    const mock = {
      signature: Buffer.from("304502203dfb1637b0be72f407a44fd148e3b89f9d6c1a38da8dbb2002d320451002a0a60221008bef319b52855da22082d7bf7933f9aa06a13af446babc8402376c50b73061e1", "hex"),
      data: Buffer.from("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634500000024fa2b99dc9e3942578f924a30d23c411800408ab5f960861bd31690cd421b7b87b3ac08227601b49dea1a6fa870daeba5ce0a437e21705bb97849726a5ea38728e4a575946416a72b02ac01a9c31653b7cb0ba5010203262001215820f924f949080b6cf9c427dd74ef1061af59f0b6585a7f8aacdfd2ed5f0fc65345225820d72c2d71e8f057e1ff4276821191aebf8a217de153f81e51f18823672dc78168569c6c145a7fcd9a86409426aa8a129e6f5ea0b81fc097a4ccff51bb4f14b5d6", "hex"),
      pubkey: "-----BEGIN CERTIFICATE-----\nMIICvDCCAaSgAwIBAgIEA63wEjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ\ndWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw\nMDBaGA8yMDUwMDkwNDAwMDAwMFowbTELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1\nYmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEmMCQG\nA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgNjE3MzA4MzQwWTATBgcqhkjOPQIB\nBggqhkjOPQMBBwNCAAQZnoecFi233DnuSkKgRhalswn+ygkvdr4JSPltbpXK5Mxl\nzVSgWc+9x8mzGysdbBhEecLAYfQYqpVLWWosHPoXo2wwajAiBgkrBgEEAYLECgIE\nFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsr\nBgEEAYLlHAEBBAQSBBD6K5ncnjlCV4+SSjDSPEEYMAwGA1UdEwEB/wQCMAAwDQYJ\nKoZIhvcNAQELBQADggEBACjrs2f+0djw4onryp/22AdXxg6a5XyxcoybHDjKu72E\n2SN9qDGsIZSfDy38DDFr/bF1s25joiu7WA6tylKA0HmEDloeJXJiWjv7h2Az2/si\nqWnJOLic4XE1lAChJS2XAqkSk9VFGelg3SLOiifrBet+ebdQwAL+2QFrcR7JrXRQ\nG9kUy76O2VcSgbdPROsHfOYeywarhalyVSZ+6OOYK/Q/DLIaOC0jXrnkzm2ymMQF\nQlBAIysrYeEM1wxiFbwDt+lAcbcOEtHEf5ZlWi75nUzlWn8bSx/5FO4TbZ5hIEcU\niGRpiIBEMRZlOIm4ZIbZycn/vJOFRTVps0V0S4ygtDc=\n-----END CERTIFICATE-----\n",
      wrongKey: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZe2loSV3wrroKUN/4zhwGhCqo3Xh\nu1td4QjeQ5wIVR0eUu11cBFj9/nkDd+fNBs9ybqGCvfgynyn6e7NAITRnA==\n-----END PUBLIC KEY-----\n"
    }

    it('should succesfully verified signature', () => {
      expect(verifySignature(
        mock.signature,
        mock.data,
        mock.pubkey
      )).toBeTruthy();
    });

    it('should failed to verify wrong signature', () => {
      expect(verifySignature(
        mock.signature.slice(0, 50),
        mock.data,
        mock.pubkey
      )).toBeFalsy();
    });

    it('should failed to verify wrong data', () => {
      expect(verifySignature(
        mock.signature,
        mock.data.slice(0, 50),
        mock.pubkey
      )).toBeFalsy();
    });

    it('should failed to verify wrong key', () => {
      expect(verifySignature(
        mock.signature,
        mock.data,
        mock.wrongKey
      )).toBeFalsy();
    });
  });
})