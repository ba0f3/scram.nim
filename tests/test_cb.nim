import unittest, scram/[server,client], nimSHA2
import checksums/sha1
import scram/private/types

const FAKE_CBDATA = "xxxxxxxxxxxxxxxx"

proc test[T](user, password: string, clientChannel = TLS_NONE, serverChannel = TLS_NONE, clientCbData = FAKE_CBDATA, serverCbData = FAKE_CBDATA) =
  var client = newScramClient[T]()
  var server = newScramServer[T]()

  if clientChannel != TLS_NONE:
    client.setChannelBindingType(clientChannel)
    client.setChannelBindingData(clientCbData)

  if serverChannel != TLS_NONE:
    server.setChannelBindingType(serverChannel)
    server.setChannelBindingData(serverCbData)

  let cfirst = client.prepareFirstMessage(user)
  assert server.handleClientFirstMessage(cfirst) == user, "incorrect detected username"
  assert server.getState() == FIRST_CLIENT_MESSAGE_HANDLED, "incorrect state"
  let sfirst = server.prepareFirstMessage(initUserData(T, password))
  let cfinal = client.prepareFinalMessage(password, sfirst)
  let sfinal = server.prepareFinalMessage(cfinal)
  assert client.verifyServerFinalMessage(sfinal), "incorrect server final message"

suite "Scram Channel Binding tests":
  test "SCRAM-SHA1-PLUS tls-unique":
    test[Sha1Digest](
      "user",
      "pencil",
      TLS_UNIQUE,
      TLS_UNIQUE
    )

  test "SCRAM-SHA256-PLUS: tls-unique":
    test[Sha256Digest](
      "bob",
      "secret",
      TLS_UNIQUE,
      TLS_UNIQUE
    )

  test "SCRAM-SHA1-PLUS tls-server-end-point":
    test[Sha1Digest](
      "user",
      "pencil",
      TLS_SERVER_END_POINT,
      TLS_SERVER_END_POINT
    )

  test "SCRAM-SHA256-PLUS: tls-server-end-point":
    test[Sha256Digest](
      "bob",
      "secret",
      TLS_SERVER_END_POINT,
      TLS_SERVER_END_POINT
    )

  test "client-support-server-do-not":
    expect ScramError:
      test[Sha256Digest](
        "bob",
        "secret",
        TLS_UNIQUE
      )

  test "client-do-not-support-server-do":
    expect ScramError:
      test[Sha256Digest](
        "bob",
        "secret",
        TLS_NONE,
        TLS_UNIQUE
      )

  test "server-do-not-suport-client-channel-binding-type":
    expect ScramError:
      test[Sha256Digest](
        "bob",
        "secret",
        TLS_UNIQUE,
        TLS_SERVER_END_POINT
      )

  test "channel-bindings-dont-match":
    expect ScramError:
      test[Sha256Digest](
        "bob",
        "secret",
        TLS_UNIQUE,
        TLS_UNIQUE,
        "xxxx",
        "zzzz"
      )