import unittest, scram/server, scram/client, sha1, nimSHA2, base64, scram/private/[utils,types]


proc test[T](user, password: string) =
  var client = newScramClient[T]()
  var server = new ScramServer[T]
  let cfirst = client.prepareFirstMessage(user)
  assert server.handleClientFirstMessage(cfirst) == user, "incorrect detected username"
  assert server.state == FIRST_CLIENT_MESSAGE_HANDLED, "incorrect state"
  let sfirst = server.prepareFirstMessage(initUserData(T, password))
  let cfinal = client.prepareFinalMessage(password, sfirst)
  let sfinal = server.prepareFinalMessage(cfinal)
  assert client.verifyServerFinalMessage(sfinal), "incorrect server final message"

suite "Scram Client-Server tests":
  test "SCRAM-SHA1":
    test[Sha1Digest](
      "user",
      "pencil"
    )

  test "SCRAM-SHA256":
    test[Sha256Digest](
      "bob",
      "secret"
    )
