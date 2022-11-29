import * as jose from 'jose'
import * as GenKey from "../crypto/genKey.js"
import * as GenNonce from "../crypto/genNonce.js"
import * as Timestamp from "../time/timestamp.js"

const IAT_DFLT =  "now"
const NBF_DFLT = "now"
const EXP_DFLT = "2h"


function nowSeconds() {
  Math.floor(new Date().getTime() / 1000)
}

function handleTokenLife(tokenLife, key, deflt) {
  if(key in tokenLife && typeof(tokenLife[key]) !== 'undefined' && tokenLife[key]) {
    return tokenLife[key]
  } else {
    return deflt
  }
}

function genClaims(need_claims, otherClaims) {
    var claims = ""
    if (need_claims[0]) { claims += "sub" + " " }
    if (need_claims[1]) { claims += "name" + " " }
    if (need_claims[2]) { claims += "family_namen" + " " }
    if (need_claims[3]) { claims += "middle_name" + " " }
    if (need_claims[4]) { claims += "nickname" + " " }
    if (need_claims[5]) { claims += "given_name" + " " }
    if (need_claims[6]) { claims += "profile" + " " }
    if (need_claims[7]) { claims += "family_name" + " " }
    if (need_claims[8]) { claims += "middle_name" + " " }
    if (need_claims[9]) { claims += "nickname" + " " }
    if (need_claims[10]) { claims += "profile" + " " }
    if (need_claims[11]) { claims += "picture" + " " }
    if (need_claims[12]) { claims += "website" + " " }
    if (need_claims[13]) { claims += "email" + " " }
    if (need_claims[14]) { claims += "email_verified" + " " }
    if (need_claims[15]) { claims += "gender" + " " }
    if (need_claims[16]) { claims += "birthdate" + " " }
    if (need_claims[17]) { claims += "zoneinfo" + " " }
    if (need_claims[18]) { claims += "locale" + " " }
    if (need_claims[19]) { claims += "phone_number" + " " }
    if (need_claims[20]) { claims += "phone_number_verified" + " " }
    if (need_claims[21]) { claims += "address" + " " }
    if (need_claims[22]) { claims += "updated_at" + " " }

    if (otherClaims != "undefined" && typeof otherClaims != "undefined"){
        claims += otherClaims
    }
    return claims
}


function validateKeyData(keyData) {

  if(Array.isArray(keyData) && keyData.length == 3 &&
      typeof keyData[0] != "undefined" && typeof keyData[1] != "undefined" && typeof keyData[2] != "undefined") {
      return keyData
  } else {
    return undefined

  }
}

async function makeKeyPair(keyData) {

  keyData = validateKeyData(keyData)

  if(typeof keyData == "undefined") {
    return await GenKey.generateEs256KeyPair();
  } else {
    const kPrivate = await GenKey.generateRsa256KeyPairFromJwk({
      "crv": "P-256",
      "d": keyData[0],
      "ext": true,
      "key_ops": ["sign"],
      "kty": "EC",
      "x": keyData[1],
      "y": keyData[2]
    }, "sign")

    const jkPub  = await GenKey.generateRsa256KeyPairFromJwk({
      "crv": "P-256",
      "ext": true,
      "key_ops": ["verify"],
      "kty": "EC",
      "x": keyData[1],
      "y": keyData[2]
    }, "verify")

    return {"privateKey": kPrivate, "publicKey": jkPub }
  }
}

export async function genJwt(keyData, issuer, audience, subject, tokenLifeTime, tokenLife, claims_array, otherClaims, tokenNonce) {

  let keyPair = await makeKeyPair(keyData)

  let publicKeyExp = await GenKey.exportPublicKeyJwk(keyPair);
  const privateKeyExp = await GenKey.exportPrivateKeyJwk(keyPair);


  const nonce = GenNonce.generateNonce()
  if ( tokenNonce == "undefined" || typeof tokenNonce == "undefined" || tokenNonce == "" ) {
    tokenNonce = GenNonce.generateNonce()
  }

  const claims = genClaims(claims_array, otherClaims)

  const iat = Timestamp.convertRelativeTimeToTimestamp(
                            handleTokenLife(tokenLife, "iat", IAT_DFLT))
  const nbf = Timestamp.convertRelativeTimeToTimestamp(
                            handleTokenLife(tokenLife, "nbf", NBF_DFLT))
  const exp = Timestamp.convertRelativeTimeToTimestamp(
                            handleTokenLife(tokenLife, "exp", EXP_DFLT))

  const jwtBody =
  {
    "sub": subject,
    "nbf": nbf,
    "nonce": nonce,
    "token_claims": claims,
    "token_lifetime": tokenLifeTime,
    "token_nonce": tokenNonce
  }

  return await new jose.SignJWT(jwtBody)
    .setProtectedHeader({ alg: 'ES256',  'type': 'JWT', 'jwk': { 'kty': 'EC', 'crv': 'P-256', 'x': publicKeyExp.x, 'y': publicKeyExp.y} })
    .setIssuedAt(iat)
    .setIssuer(issuer)
    .setAudience(audience)
    .setExpirationTime(exp)
    .sign(keyPair.privateKey)
}
