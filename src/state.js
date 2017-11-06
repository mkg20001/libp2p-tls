'use strict'

const sslConfig = require("ssl-config")("modern")

const debug = require("debug")
const log = debug("libp2p:tls")

const handshake = require("pull-handshake")
const {
  selfSignedCert,
  createMagic,
  getMagic
} = require("./core")

const deferred = require('pull-defer')

module.exports = class State {
  constructor(local, key, timeout) {
    log('0 - init')

    this.secure = deferred.duplex()
    this.id = local
    this.msg = []

    this.magic = createMagic()

    this.shake = handshake({
      timeout
    })

    this.handshake = this.shake.handshake

    this.handshake.write(this.magic.packet)

    log('0.1 - create self-signed certificate for %s', this.id.toB58String())
    this.cert = selfSignedCert(this.id)

    this.tlsOptions = {
      requestCert: true,
      rejectUnauthorized: false,
      key: this.cert.key,
      cert: this.cert.cert,
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
      if (state.length >= 15) return cb(new Error("E_PACKET_TOO_LONG: No valid data after 15 bytes"))
      if (!res || !res.length) return this.readFromHandshake(cb, state)

      state.push(res)
      const pres = getMagic(Buffer.concat(state))
      if (!pres) return this.readFromHandshake(cb, state)

      cb(null, pres.magic)
    })
  }
}
