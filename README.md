[![Build Status](https://travis-ci.org/ba0f3/scram.nim.svg?branch=master)](https://travis-ci.org/ba0f3/scram.nim)

# scram.nim
Salted Challenge Response Authentication Mechanism (SCRAM)


### Supported Mechanisms:
* SCRAM-SHA-1
* SCRAM-SHA-1-PLUS
* SCRAM-SHA-256
* SCRAM-SHA-256-PLUS
* SCRAM-SHA-384
* SCRAM-SHA-384-PLUS
* SCRAM-SHA-512
* SCRAM-SHA-512-PLUS
* SCRAM-SHA3-512
* SCRAM-SHA3-512-PLUS

### Supported Channel Binding Types
* TLS_UNIQUE
* TLS_SERVER_END_POINT

### Standards

`RFC 5802 <https://tools.ietf.org/html/rfc5802>`_
  Describes SCRAM.
`RFC 7677 <https://datatracker.ietf.org/doc/html/rfc7677>`_
  Registers SCRAM-SHA-256 and SCRAM-SHA-256-PLUS.
`draft-melnikov-scram-sha-512-02 <https://datatracker.ietf.org/doc/html/draft-melnikov-scram-sha-512>`_
  Registers SCRAM-SHA-512 and SCRAM-SHA-512-PLUS.
`draft-melnikov-scram-sha3-512 <https://datatracker.ietf.org/doc/html/draft-melnikov-scram-sha3-512>`_
  Registers SCRAM-SHA3-512 and SCRAM-SHA3-512-PLUS.
`RFC 5929 <https://datatracker.ietf.org/doc/html/rfc5929>`_
  Channel Bindings for TLS.
`RFC 9266 <https://datatracker.ietf.org/doc/html/rfc9266>`_
  Defines the ``tls-exporter`` channel binding, which is `not yet supported by scram.nim

### Examples

#### Client
```nim
var client = newScramClient[Sha256Digest]()
assert client.prepareFirstMessage(user) == cfirst, "incorrect first message"
let fmsg = client.prepareFinalMessage(password, sfirst)
assert fmsg == cfinal, "incorrect final message"
assert client.verifyServerFinalMessage(sfinal), "incorrect server final message"
```

#### Channel Binding

Helper proc `getChannelBindingData` added to helps you getting channel binding data from existing Socket/AsyncSocket

```nim
var
  ctx = newContext()
  socket = newSocket()
ctx.wrapSocket(socket)
socket.connect(...)
# ....
let cbData = getChannelBindingData(TLS_UNIQUE, socket)

var client = newScramClient[Sha256Digest]()
client.setChannelBindingType(TLS_UNIQUE)
client.setChannelBindingData(cbData)
echo client.prepareFirstMessage(user)
```
