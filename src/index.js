'use strict'

const pull = require("pull-stream")
const Connection = require('interface-connection').Connection
const TLS = require('./tls')

module.exports = {
  tag: '/tls/1.0.0',
  encrypt (local, key, insecure, callback) {
    if (!local) {
      throw new Error('no local id provided')
    }

    if (!key) {
      throw new Error('no local private key provided')
    }

    if (!insecure) {
      throw new Error('no insecure stream provided')
    }

    if (!callback) {
      callback = (err) => {
        if (err) {
          console.error(err)
        }
      }
    }

    const tls = new TLS(local, key, 60 * 1000 * 5)

    pull(
      tls.shake,
      insecure,
      tls.shake
    )

    tls.encrypt(callback)

    return new Connection(tls.secure, insecure)
  }
}
