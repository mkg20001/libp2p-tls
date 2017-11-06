'use strict'

const protobuf = require("protons")

exports.MAGIC_MAX = 10000000000 //until tls1.3 - needed to determine which client is going to be the server
exports.packet = protobuf('message Packet { required int64 magic = 1; required bool fin = 2; }').Packet

const crypto = require("libp2p-crypto")
const Id = require("peer-id")

const forge = require("node-forge")
const pki = forge.pki
const pemToJwk = require('pem-jwk').pem2jwk
const jwkToPem = require('pem-jwk').jwk2pem

/**
 * Get a random integer between `min` and `max`.
 *
 * @param {number} min - min number
 * @param {number} max - max number
 * @return {number} a random integer
 */
function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1) + min);
}
exports.getRandomInt = getRandomInt

/**
  * Converts a libp2p-crypto RsaPrivateKey into a PEM encoded public/private key pair
  *
  * @param {RsaPrivateKey} key - libp2p-crypto private key
  * @return {Object{public, private}} object containing the pem encoded keys
  */
function libp2pToPem(key) {
  return {
    private: jwkToPem(key._key),
    public: jwkToPem(key._publicKey)
  }
}
exports.libp2pToPem = libp2pToPem

/**
  * Converts a DER encoded certificate buffer into a forge encoded certificate
  *
  * @param {Buffer} cert - DER certificate buffer
  * @return {forge.Certificate} forge encoded certificate
  */
function loadDERForge(crt) {
  const bytes = forge.util.createBuffer(crt)
  const asn1 = forge.asn1.fromDer(bytes)
  return pki.certificateFromAsn1(asn1)
}
exports.loadDERForge = loadDERForge

/**
  * Get a peer-id from a forge encoded certificate
  *
  * @param {forge.Certificate} cert - Certificate as returned by `loadDERForge`
  * @param {cb(err, (PeerId) id)} cb - Callback that gets called with either the id or the error
  * @return {undefined}
  */
function getPeerId(cert, cb) {
  try {
    if (!cert.verify(cert)) throw new Error("Certificate invalid!")
    const _id = cert.subject.getField("CN").value
    const _key = pemToJwk(pki.publicKeyToPem(cert.publicKey))
    const key = new crypto.keys.supportedKeys.rsa.RsaPublicKey(_key)
    Id.createFromPubKey(key.bytes, (err, id) => {
      if (err) return cb(err)
      if (id.toB58String() != _id) return cb(new Error("ID is not matching"))
      return cb(null, id)
    })
  } catch(e) {
    cb(e)
  }
}
exports.getPeerId = getPeerId

// Determines which algorithm to use.  Note:  f(a, b) = f(b, a)
exports.theBest = (order, p1, p2) => {
  let first
  let second

  if (order < 0) {
    first = p2
    second = p1
  } else if (order > 0) {
    first = p1
    second = p2
  } else {
    return p1[0]
  }

  for (let firstCandidate of first) {
    for (let secondCandidate of second) {
      if (firstCandidate === secondCandidate) {
        return firstCandidate
      }
    }
  }

  throw new Error('No algorithms in common!')
}
