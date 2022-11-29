import * as jose from 'jose'
import { RidtVerificationResult } from "./ridtVerificationResult"
//import * as Timestamp from "../time/timestamp"

const IAT_DFLT = "now"
const NBF_DFLT = "now"
const EXP_DFLT = "2h"

export class HandleRidt {


  static httpGet(theUrl) {
  let xmlHttpReq = new XMLHttpRequest();
  xmlHttpReq.open("GET", theUrl, false);
  xmlHttpReq.send(null);
  return xmlHttpReq.responseText;
  }

  static parseJwt (token: string, token_index: number) {
    var base64Url = token.split('.')[token_index];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
  }


  static claimsStringToArray(claims){

  }
  /**
   * generate a JWT used to request an OpenIdToken
   * @Params
   * "keyPair" is the key used by the avvount that wants to authenticate
   * "tokenClaims" are the claims present in the openId Token
   * "tokenNonce" is the nonce in the openId token
   * "tokenLifetime" is how long the token should be valid in seconds
   * @usedWith
   * generateTokenRequest ganerates a request token with can be used with the function: requestRemoteIdToken from this lib
   */
  static async generateTokenRequest(keyPair: CryptoKeyPair, iss: string, sub: string, aud: string, iat: number, nbf: number, exp: number, nonce: number, tokenClaims: string[], tokenNonce: string, tokenLifetime: number): Promise<string> {

    let claimsString = ""
    for (let i = 0; i < tokenClaims.length; i++) {
      claimsString += tokenClaims[i]
      if (i != tokenClaims.length - 1) {
        claimsString += " "
      }
    }

    let publicKeyExp = await window.crypto.subtle.exportKey(
        "jwk",
        keyPair.publicKey,
    );

    const jwtBody =
    {
      "sub": sub,
      "nbf": nbf,
      "nonce": nonce,
      "token_claims": claimsString,
      "token_lifetime": tokenLifetime,
      "token_nonce": tokenNonce
    }

    return await new jose.SignJWT(jwtBody)
      .setProtectedHeader({ alg: 'ES256',  'type': 'JWT', 'jwk': { 'kty': 'EC', 'crv': 'P-256', 'x': publicKeyExp.x, 'y': publicKeyExp.y} })
      .setIssuedAt(iat)
      .setIssuer(iss)
      .setAudience(aud)
      .setExpirationTime(exp)
      .sign(keyPair.privateKey)
  }

  /**
   *
   *
   *
   */
  static async requestRemoteIdToken(accessToken: string, requestToken: string, ridtEndpointUri: string): Promise<string> {

    const header = new Headers();

    header.append('accept', 'application/json');
    header.append('Authorization',  'Bearer ' + accessToken)
    header.append('Content-Type', 'application/jwt')


    const message = {
      method: 'POST',
      headers: header,
      body: requestToken
    };

    const myRequest = new Request(ridtEndpointUri);

    var response = await fetch(myRequest, message)
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    var body = await response.text()

    return body
  }
  /**
   * @ensures:
   * - Signature fits to issuers key stored in key config (under: issuer + "/.well-known/openid-configuration")
   * - Issuer is the same as in the OpenId Token
   * @params:
   * - ridt: OpenID token
   * - issuer: Url of entity issuing the Token (e.g. http://example.com)
   */
  static async verifyRemoteIdToken(ridt: string, issuer: string): Promise<RidtVerificationResult> {

    console.log(ridt)
    var ridtHeader = HandleRidt.parseJwt(ridt, 0)
    var ridtKid = ridtHeader.kid

    var key = await HandleRidt.getRidtKey(issuer, ridtKid)

    var publicKey: CryptoKey = await HandleRidt.importJWK(key)
    var ridtBody = HandleRidt.parseJwt(ridt, 1)


    console.log("----------------")
    console.log(publicKey)

    var sigValid = true
    var tokenValid = true
    var res_payload = null

    try {
      const { payload, protectedHeader } = await jose.jwtVerify(ridt, publicKey, {
        issuer: ridtBody.iss
      })
      res_payload = payload

    } catch  (e) {
      console.log(e)
      if (e.constructor.name == "JWSSignatureVerificationFailed") {
        sigValid = false
      } else {
        tokenValid = false
      }
    }


    return new RidtVerificationResult(sigValid, tokenValid, publicKey, res_payload)


  }

  static async getRidtKey(issuer: string, ridtKid: number) {
    var ridtEndpoint = issuer + "/.well-known/openid-configuration"
    var openIdConfig = JSON.parse(HandleRidt.httpGet(ridtEndpoint))

    var keyUri = openIdConfig.jwks_uri
    var keyConfig = JSON.parse(HandleRidt.httpGet(keyUri))

    var keys = keyConfig.keys

    for( let key in Object.keys(keys)) {
      if(keys[key].kid == ridtKid) {
        return keys[key]
      }
    }
    throw new Error('Key specified in the OID Token not present in keys config of the releam');
  }

  /**
   * @Only imports RSA and EC keys from a OpenID Providers key config
   */
  static async importJWK(key): Promise<any> {

    switch(key.kty) {
      case "RSA":
        return await jose.importJWK(
          {
            kty: 'RSA',
            e: 'AQAB',
            n: key.n,
          },
          key.alg,
        )

      case "EC":
        return await jose.importJWK(
          {
            crv: 'P-256',
            kty: 'EC',
            x: key.x,
            y: key.y,
          },
          key.alg,
        )
      default:
        throw Error("Algorithm " + key.kry + " is not supported by the tokenRequestLib")
    }
  }
}
