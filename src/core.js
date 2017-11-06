'use strict'

const {
  libp2pToPem,
  loadDERForge,
  getPeerId,
  packet,
  getRandomInt,
  MAGIC_MAX
} = require("./support")

const forge = require("node-forge")
const pki = forge.pki

/**
 * Get a libp2p-tls compatible x509 certificate
 *
 * @param {PeerId} id - PeerId of the peer
 * @return {Object{key, cert}} PEM-encoded private key and PEM-encoded x509 certificate
 */
function selfSignedCert(id) {
  const key = libp2pToPem(id._privKey)
  const keys = {
    privateKey: pki.privateKeyFromPem(key.private),
    publicKey: pki.publicKeyFromPem(key.public),
  }
  const cert = pki.createCertificate()

  cert.publicKey = keys.publicKey
  cert.serialNumber = '01'
  cert.validity.notBefore = new Date()
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

  const attrs = [{
    name: 'commonName',
    value: id.toB58String()
  }, {
    name: 'countryName',
    value: 'US'
  }, {
    shortName: 'ST',
    value: 'Virginia'
  }, {
    name: 'localityName',
    value: 'Blacksburg'
  }, {
    name: 'organizationName',
    value: 'Test'
  }, {
    shortName: 'OU',
    value: 'Test'
  }]
  cert.setSubject(attrs)
  cert.setIssuer(attrs)

  cert.setExtensions([{
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }, {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true
  }, {
    name: 'nsCertType',
    client: true,
    server: true,
    email: true,
    objsign: true,
    sslCA: true,
    emailCA: true,
    objCA: true
  }, {
    name: 'subjectAltName',
    altNames: []
  }, {
    name: 'subjectKeyIdentifier'
  }])

  cert.sign(keys.privateKey)

  const _cert = pki.certificateToPem(cert)
  return {
    cert: _cert,
    key: key.private
  }
}

/**
 * Gets a peer-id from a TLSSocket
 *
 * @param {TLS.TLSSocket} socket - TLS socket (if the socket is from a server "requestCert" must have been true)
 * @param {cb(err, (PeerId) id)} cb - Callback that gets called with either the id or the error
 * @return {undefined}
 */
function getPeerIdFromSocket(socket, cb) {
  try {
    const _cert = socket.getPeerCertificate()
    if (!_cert) return cb(new Error("No certificate found (requestCert: false ?)"))
    const cert = loadDERForge(_cert.raw)
    getPeerId(cert, cb)
  } catch(e) {
    cb(e)
  }
}

/**
  * Creates a magic value and packet
  *
  * @return {Object{packet, value}}
  */
function createMagic() {
  const value = getRandomInt(0, MAGIC_MAX)
  return {
    value,
    packet: packet.encode({
      magic: value,
      fin: true
    })
  }
}

/**
  * Gets a magic value from a raw packet buffer
  *
  * @param {Buffer} packet - The magic packet
  * @return {Object} the value of the packet (if invalid false is returned)
  */
function getMagic(_packet) {
  let pres
  try {
    pres = packet.decode(_packet)
  } catch (e) {

  }
  if (!pres || !pres.fin) return false
  return pres
}

module.exports = {selfSignedCert, getPeerIdFromSocket, createMagic, getMagic}
