export class RidtVerificationResult {
  signatureValid: boolean
  tokenValid: boolean
  publicKey: CryptoKey
  payload: string[]

  constructor(signatureValid: boolean, tokenValid: boolean, publicKey: CryptoKey, payload: string[]) {
    this.signatureValid = signatureValid;
    this.tokenValid = tokenValid;
    this.publicKey = publicKey;
    this.payload = payload;
  }

  // getter for the attributes

  getSignatureValid() {return this.signatureValid; }
  getTokenValid() {return this.tokenValid; }
  getPublicKey() {return this.publicKey; }
  getPayload() {return this.payload; }
}
