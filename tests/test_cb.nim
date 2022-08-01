import unittest, scram/[server,client], sha1, nimSHA2
import scram/private/types

const FAKE_CBDATA = "xxxxxxxxxxxxxxxx"

proc test[T](user, password: string) =
  var client = newScramClient[T]()
  var server = newScramServer[T]()

  client.setCBindType(TLS_UNIQUE)
  client.setCBindData(FAKE_CBDATA)

  server.setCBindType(TLS_UNIQUE)
  server.setCBindData(FAKE_CBDATA)

  let cfirst = client.prepareFirstMessage(user)
  assert server.handleClientFirstMessage(cfirst) == user, "incorrect detected username"
  assert server.getState() == FIRST_CLIENT_MESSAGE_HANDLED, "incorrect state"
  let sfirst = server.prepareFirstMessage(initUserData(T, password))
  let cfinal = client.prepareFinalMessage(password, sfirst)
  let sfinal = server.prepareFinalMessage(cfinal)
  assert client.verifyServerFinalMessage(sfinal), "incorrect server final message"

suite "Scram Client-Server tests":
  test "SCRAM-SHA1-PLUS":
    test[Sha1Digest](
      "user",
      "pencil"
    )

  test "SCRAM-SHA256-PLUS":
    test[Sha256Digest](
      "bob",
      "secret"
    )