'use strict'

const debug = require("debug")
const log = debug("libp2p:tls")
const wrapper = require("./wrapper") //will be replaced by browser version if in browser

module.exports = (state, cb) => {
  state.readFromHandshake((err, res) => {
    if (err) return cb(err)
    log('1.9 - magic: ours=%s, theirs=%s', state.magic.value, res)
    if (res === state.magic.value) return cb(new Error("E_MAGIC_MATCH: The magic number matches! Please try to be more lucky next time!")) //TODO: try again instead of failure
    state.isServer = res < state.magic.value
    log('2 - establish tls connection (server %s)', state.isServer)
    wrapper(state.handshake.rest(), state.tlsOptions, state.isServer, (err, conn) => {
      if (err) return cb(err)
      log('3 - finalize')
      state.secure.resolve(conn)
    })
  })
}
