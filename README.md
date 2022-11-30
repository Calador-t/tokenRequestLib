# tokenRequestLib
Allowes to requst and verify a openID connect token.

### Install
```npm i @tobias_schn/experimental_tokenrequestlib@1.0.0```
### Import
import { HandleRidt, RidtVerificationResult } from '@tobias_schn/experimental_tokenrequestlib'

## Classes
HandleRidt
RidtVerificationResult

### HandleRidt
```static async generateTokenRequest(keyPair: CryptoKeyPair, iss: string, sub: string, aud: string, iat: number, nbf: number, exp: number, nonce: number, tokenClaims: string[], tokenNonce: string, tokenLifetime: number): Promise<string> ```
generate a JWT used to request an OpenIdToken

```static async requestRemoteIdToken(accessToken: string, requestToken: string, ridtEndpointUri: string): Promise<string>```
requests an IAT (Identity asertion token)

```static async verifyRemoteIdToken(ridt: string, issuer: string): Promise<RidtVerificationResult>```
verifyes the IAT signature and syntax and asures that the issuer is correct

### RidtVerificationResult
Contains inforamtion about the validity of an IAT and includes the payload
```constructor(signatureValid: boolean, tokenValid: boolean, publicKey: CryptoKey, payload: string[])```
