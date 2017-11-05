'use strict'

process.on("uncaughtException", e => console.error(e))

const tls = require("tls")

const toPull = require("stream-to-pull-stream")
const sslConfig = require("ssl-config")("modern")

const crypto = require("libp2p-crypto")
const Id = require("peer-id")

const debug = require("debug")
const log = debug("libp2p:tls")

const toSocket = require("pull-stream-to-net-socket")
const handshake = require("pull-handshake")

const deferred = require('pull-defer')

const forge = require("node-forge")
const pki = forge.pki
const pemToJwk = require('pem-jwk').pem2jwk
const jwkToPem = require('pem-jwk').jwk2pem

const protobuf = require("protons")

const MAGIC_MAX = 10000000000 //until tls1.3 - needed to determine which client is going to be the server

const packet = protobuf('message Packet { required int64 magic = 1; required bool fin = 2; }').Packet

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

function toPem(key) {
  return {
    private: jwkToPem(key._key),
    public: jwkToPem(key._publicKey)
  }
}

function loadDER(crt) {
  const bytes = forge.util.createBuffer(crt)
  const asn1 = forge.asn1.fromDer(bytes)
  return forge.pki.certificateFromAsn1(asn1)
}

function getPeerId(cert, cb) {
  if (!cert.verify(cert)) throw new Error("Certificate invalid!")
  const _id = cert.subject.getField("CN").value
  const _key = pemToJwk(pki.publicKeyToPem(cert.publicKey))
  const key = new crypto.keys.supportedKeys.rsa.RsaPublicKey(_key)
  Id.createFromPubKey(key.bytes, (err, id) => {
    if (err) return cb(err)
    if (id.toB58String() != _id) return cb(new Error("ID is not matching"))
    return cb(null, id)
  })
}

function selfSignedCert(key, id) {
  log('0.1 - create self-signed certificate for %s', id.toB58String())

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

  return pki.certificateToPem(cert)
}

module.exports = class TLS {
  constructor(local, key, timeout) {
    log('0 - init')

    this.secure = deferred.duplex()
    this.id = local
    this.msg = []

    this.magic = getRandomInt(0, MAGIC_MAX)

    this.shake = handshake({
      timeout
    })

    this.handshake = this.shake.handshake

    this.handshake.write(packet.encode({
      magic: this.magic,
      fin: true
    }))

    this.pemKey = toPem(key)
    this.cert = selfSignedCert(this.pemKey, this.id)

    this.tlsOptions = {
      requestCert: true,
      rejectUnauthorized: false,
      key: this.pemKey.private,
      cert: this.cert,
      ciphers: sslConfig.ciphers,
      honorCipherOrder: true,
      secureOptions: sslConfig.minimumTLSVersion
    }
  }
  readFromHandshake(cb, state) {
    if (!state) {
      log('1 - handshake')
      state = []
    }
    this.handshake.read(1, (err, res) => {
      log('1.%s - reading (err=%s, res=%s, bytes=%s/8?)', state.length + 1, err, !!res, state.length)
      if (err) return cb(err)
      if (state.length >= 9) return cb(new Error("E_PACKET_TOO_LONG: No valid data after 15 bytes"))
      if (!res || !res.length) return this.readFromHandshake(cb, state)

      state.push(res)
      let pres
      try {
        pres = packet.decode(Buffer.concat(state))
      } catch (e) {

      }
      if (!pres || !pres.fin) return this.readFromHandshake(cb, state)

      cb(null, pres.magic)
    })
  }
  establishConnection(conn, isServer, cb) {
    const opt = isServer ? {
      createServer: () => tls.createServer(this.tlsOptions),
      prefire: true,
      inverse: true
    } : {
      createClient: dest => tls.connect(Object.assign(dest, this.tlsOptions)),
      prefire: true
    }
    toSocket(conn, opt, (err, conn) => {
      if (err) return cb(err)
      log('2.1 - determine peer identity')
      const cert = loadDER(conn.getPeerCertificate().raw)
      try {
        getPeerId(cert, (err, id) => {
          if (err) return cb(err)
          log('2.2 - indentified peer as %s', id.toB58String())
          conn = toPull.duplex(conn)
          conn.id = id
          return cb(null, conn)
        })
      } catch(e) {
        return cb(e)
      }
    })
  }
  encrypt(cb) {
    this.readFromHandshake((err, res) => {
      if (err) return cb(err)
      log('1.9 - magic: ours=%s, theirs=%s', this.magic, res)
      if (res === this.magic) return cb(new Error("E_MAGIC_MATCH: The magic number matches! Please try to be more lucky next time!")) //TODO: try again instead of failure
      this.isServer = res < this.magic
      log('2 - establish tls connection (server %s)', this.isServer)
      this.establishConnection(this.handshake.rest(), this.isServer, (err, conn) => {
        if (err) return cb(err)
        log('3 - finalize')
        this.secure.resolve(conn)
      })
    })
  }
}
