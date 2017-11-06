'use strict'

const tls = require('tls')
const toSocket = require("pull-stream-to-net-socket")
const toPull = require("stream-to-pull-stream")
const {
  getPeerIdFromSocket
} = require('./core')

const debug = require("debug")
const log = debug("libp2p:tls")

module.exports = (conn, tlsOptions, isServer, cb) => {
  const opt = isServer ? {
    createServer: () => tls.createServer(tlsOptions),
    prefire: true,
    inverse: true
  } : {
    createClient: dest => tls.connect(Object.assign(dest, tlsOptions)),
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
