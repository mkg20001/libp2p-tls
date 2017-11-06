'use strict'

module.exports = (conn, tlsOptions, isServer, cb) => {
  cb(new Error('Browser is currently not supported!'))
}
