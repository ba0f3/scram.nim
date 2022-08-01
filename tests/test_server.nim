import unittest, scram/server, sha1, nimSHA2, base64
import scram/private/[utils, types]

proc test[T](user, password, nonce, salt, cfirst, sfirst, cfinal, sfinal: string) =
  var server = newScramServer[T]()
  assert server.handleClientFirstMessage(cfirst) == user, "incorrect detected username"
  assert server.getState() == FIRST_CLIENT_MESSAGE_HANDLED, "incorrect state"
  server.setServerNonce(nonce)
  let
    iterations = 4096
    decodedSalt = base64.decode(salt)
    saltedPassword = hi[T](password, decodedSalt, iterations)
    clientKey = HMAC[T]($%saltedPassword, CLIENT_KEY)
    storedKey = HASH[T]($%clientKey)
    serverKey = HMAC[T]($%saltedPassword, SERVER_KEY)
    ud = UserData(
      salt: base64.encode(decodedSalt),
      iterations: iterations,
      storedKey: base64.encode($%storedKey),
      serverKey: base64.encode($%serverKey))
  assert ud.salt == salt, "Incorrect salt initialization"
  assert server.prepareFirstMessage(ud) == sfirst, "incorrect first message"
  assert server.prepareFinalMessage(cfinal) == sfinal, "incorrect last message"

suite "Scram Server tests":
  test "SCRAM-SHA1":
    test[Sha1Digest](
      "user",
      "pencil",
      "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j",
      "QSXCR+Q6sek8bf92",
      "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
      "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
      "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
      "v=rmF9pqV8S7suAoZWja4dJRkFsKQ="
    )

  test "SCRAM-SHA256":
    test[Sha256Digest](
      "bob",
      "secret",
      "VeAOLsQ22fn/tjalHQIz7cQTmeE5qJh8qKEe8wALMut1",
      "ldZSefTzKxPNJhP73AmW/A==",
      "n,,n=bob,r=VeAOLsQ22fn/tjalHQIz7cQT",
      "r=VeAOLsQ22fn/tjalHQIz7cQTmeE5qJh8qKEe8wALMut1,s=ldZSefTzKxPNJhP73AmW/A==,i=4096",
      "c=biws,r=VeAOLsQ22fn/tjalHQIz7cQTmeE5qJh8qKEe8wALMut1,p=AtNtxGzsMA8evcWBM0MXFjxN8OcG1KRkLkFyoHlupOU=",
      "v=jeEn7M7PgnBZ7GRd+f3Ikaj40dw4EGKZ0x8FcQztLLs="
    )
