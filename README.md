# js-libp2p-tls

[![](https://img.shields.io/badge/made%20by-mkg20001-blue.svg?style=flat-square)](https://mkg20001.github.io/)
[![](https://img.shields.io/badge/project-IPFS-blue.svg?style=flat-square)](http://ipfs.io/)
[![standard-readme compliant](https://img.shields.io/badge/standard--readme-OK-green.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)
[![Coverage Status](https://coveralls.io/repos/github/mkg20001/libp2p-tls/badge.svg?branch=master)](https://coveralls.io/github/mkg20001/libp2p-tls?branch=master)
[![Travis CI](https://travis-ci.org/mkg20001/libp2p-tls.svg?branch=master)](https://travis-ci.org/mkg20001/libp2p-tls)
![](https://img.shields.io/badge/npm-%3E%3D3.0.0-orange.svg?style=flat-square)
![](https://img.shields.io/badge/Node.js-%3E%3D6.0.0-orange.svg?style=flat-square)


> TLS/SSL crypto for libp2p

This repo contains an experimental TLS/SSL transport for libp2p. Currently there is no browser support (planned - [see Roadmap](#roadmap))

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [API](#api)
- [Roadmap](#roadmap)
- [Contribute](#contribute)
- [License](#license)

## Install

```sh
npm install libp2p-tls
```

## Usage

```js
const tls = require('libp2p-tls')
```

## API

### `tag`

The current `tls` tag, usable in `multistream`.

### `encrypt(id, key, insecure[, callback])`

- `id: PeerId` - The id of the node.
- `key: RSAPrivateKey` - The private key of the node.
- `insecure: PullStream` - The insecure connection.
- `callback: Function` - Called if an error happens during the initialization.

Returns the `insecure` connection provided, wrapped with secio. This is a pull-stream.

### This module uses `pull-streams`

We expose a streaming interface based on `pull-streams`, rather then on the Node.js core streams implementation (aka Node.js streams). `pull-streams` offers us a better mechanism for error handling and flow control guarantees. If you would like to know more about why we did this, see the discussion at this [issue](https://github.com/ipfs/js-ipfs/issues/362).

You can learn more about pull-streams at:

- [The history of Node.js streams, nodebp April 2014](https://www.youtube.com/watch?v=g5ewQEuXjsQ)
- [The history of streams, 2016](http://dominictarr.com/post/145135293917/history-of-streams)
- [pull-streams, the simple streaming primitive](http://dominictarr.com/post/149248845122/pull-streams-pull-streams-are-a-very-simple)
- [pull-streams documentation](https://pull-stream.github.io/)

#### Converting `pull-streams` to Node.js Streams

If you are a Node.js streams user, you can convert a pull-stream to a Node.js stream using the module [`pull-stream-to-stream`](https://github.com/pull-stream/pull-stream-to-stream), giving you an instance of a Node.js stream that is linked to the pull-stream. For example:

```js
const pullToStream = require('pull-stream-to-stream')

const nodeStreamInstance = pullToStream(pullStreamInstance)
// nodeStreamInstance is an instance of a Node.js Stream
```

To learn more about this utility, visit https://pull-stream.github.io/#pull-stream-to-stream.


## Roadmap
 - [ ] Add backwards-compatible tls1.3 support
 - [ ] Add a parameter to let the clients choose between ECC and RSA crypto?
 - [ ] Add browser support


## Contribute

Feel free to join in. All welcome. Open an [issue](https://github.com/mkg20001/libp2p-tls/issues)!

## License

[MIT](LICENSE)
