'use strict'

process.on("uncaughtException", e => console.error(e))

const tls = require("tls")

const toPull = require("stream-to-pull-stream")
const sslConfig = require("ssl-config")("modern")

const debug = require("debug")
const log = debug("libp2p:tls")

const toSocket = require("pull-stream-to-net-socket")
const handshake = require("pull-handshake")
const {
  selfSignedCert,
  getPeerIdFromSocket,
  createMagic,
  getMagic
} = require("./core")

const deferred = require('pull-defer')

module.exports = class TLS {
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
      if (state.length >= 9) return cb(new Error("E_PACKET_TOO_LONG: No valid data after 15 bytes"))
      if (!res || !res.length) return this.readFromHandshake(cb, state)

      state.push(res)
      const pres = getMagic(Buffer.concat(state))
      if (!pres) return this.readFromHandshake(cb, state)

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
      getPeerIdFromSocket(conn, (err, id) => {
        log('2.2 - indentified peer as %s', id.toB58String())
        conn = toPull.duplex(conn)
        conn.id = id
        return cb(null, conn)
      })
    })
  }
  encrypt(cb) {
    this.readFromHandshake((err, res) => {
      if (err) return cb(err)
      log('1.9 - magic: ours=%s, theirs=%s', this.magic, res)
      if (res === this.magic) return cb(new Error("E_MAGIC_MATCH: The magic number matches! Please try to be more lucky next time!")) //TODO: try again instead of failure
      this.isServer = res < this.magic.value
      log('2 - establish tls connection (server %s)', this.isServer)
      this.establishConnection(this.handshake.rest(), this.isServer, (err, conn) => {
        if (err) return cb(err)
        log('3 - finalize')
        this.secure.resolve(conn)
      })
    })
  }
}
