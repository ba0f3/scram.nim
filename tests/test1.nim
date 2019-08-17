import unittest, scram/client


proc test[T](user, password, nonce, cfirst, sfirst, cfinal, sfinal: string) =
  var client = newScramClient[T]()
  client.clientNonce = nonce
  assert client.prepareFirstMessage(user) == cfirst, "incorrect first message"
  let fmsg = client.prepareFinalMessage(password, sfirst)
  echo fmsg
  assert fmsg == cfinal, "incorrect final message"
  assert client.verifyServerFinalMessage(sfinal), "incorrect server final message"

suite "Scram Client tests":
  test "SCRAM-SHA1":
    test[Sha1Digest](
      "user",
      "pencil",
      "fyko+d2lbbFgONRv9qkxdawL",
      "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
      "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
      "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
      "v=rmF9pqV8S7suAoZWja4dJRkFsKQ="
    )

  test "SCRAM-SHA256":
    test[Sha256Digest](
      "bob",
      "secret",
      "VeAOLsQ22fn/tjalHQIz7cQT",
      "n,,n=bob,r=VeAOLsQ22fn/tjalHQIz7cQT",
      "r=VeAOLsQ22fn/tjalHQIz7cQTmeE5qJh8qKEe8wALMut1,s=ldZSefTzKxPNJhP73AmW/A==,i=4096",
      "c=biws,r=VeAOLsQ22fn/tjalHQIz7cQTmeE5qJh8qKEe8wALMut1,p=AtNtxGzsMA8evcWBM0MXFjxN8OcG1KRkLkFyoHlupOU=",
      "v=jeEn7M7PgnBZ7GRd+f3Ikaj40dw4EGKZ0x8FcQztLLs="
    )
