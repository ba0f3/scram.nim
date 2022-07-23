import strformat
import base64, pegs, strutils, hmac, sha1, nimSHA2, md5, private/[utils,types]

export MD5Digest, SHA1Digest, SHA224Digest, SHA256Digest, SHA384Digest, SHA512Digest, Keccak512Digest

type
  ScramClient[T] = ref object of RootObj
    clientNonce*: string
    clientFirstMessageBare: string
    state: ScramState
    isSuccessful: bool
    serverSignature: T

when compileOption("threads"):
  var
    SERVER_FIRST_MESSAGE_VAL: ptr Peg
    SERVER_FINAL_MESSAGE_VAL: ptr Peg
  template SERVER_FIRST_MESSAGE: Peg =
    if SERVER_FIRST_MESSAGE_VAL.isNil:
      SERVER_FIRST_MESSAGE_VAL = cast[ptr Peg](allocShared0(sizeof(Peg)))
      SERVER_FIRST_MESSAGE_VAL[] = peg"'r='{[^,]*}',s='{[^,]*}',i='{\d+}$"
    SERVER_FIRST_MESSAGE_VAL[]
  template SERVER_FINAL_MESSAGE: Peg =
    if SERVER_FINAL_MESSAGE_VAL.isNil:
      SERVER_FINAL_MESSAGE_VAL = cast[ptr Peg](allocShared0(sizeof(Peg)))
      SERVER_FINAL_MESSAGE_VAL[] = peg"'v='{[^,]*}$"
    SERVER_FINAL_MESSAGE_VAL[]
else:
  let
    SERVER_FIRST_MESSAGE = peg"'r='{[^,]*}',s='{[^,]*}',i='{\d+}$"
    SERVER_FINAL_MESSAGE = peg"'v='{[^,]*}$"

proc newScramClient*[T](): ScramClient[T] =
  result = new(ScramClient[T])
  result.clientNonce = makeNonce()

proc prepareFirstMessage*(s: ScramClient, username: string): string {.raises: [ScramError]} =
  if username.len == 0:
    raise newException(ScramError, "username cannot be nil or empty")
  var username = username.replace("=", "=3D").replace(",", "=2C")
  s.clientFirstMessageBare = "n="
  s.clientFirstMessageBare.add(username)
  s.clientFirstMessageBare.add(",r=")
  s.clientFirstMessageBare.add(s.clientNonce)

  s.state = FIRST_PREPARED
  GS2_HEADER & s.clientFirstMessageBare

proc prepareFinalMessage*[T](s: ScramClient[T], password, serverFirstMessage: string): string =
  if s.state != FIRST_PREPARED:
    raise newException(ScramError, "First message have not been prepared, call prepareFirstMessage() first")
  var
    nonce, salt: string
    iterations: int
  var matches: array[3, string]
  if match(serverFirstMessage, SERVER_FIRST_MESSAGE, matches):
    for kv in serverFirstMessage.split(','):
      if kv[0..1] == "i=":
        iterations = parseInt(kv[2..^1])
      elif kv[0..1] == "r=":
        nonce = kv[2..^1]
      elif kv[0..1] == "s=":
        salt = base64.decode(kv[2..^1])
  else:
    s.state = ENDED
    return ""

  if not nonce.startsWith(s.clientNonce):
    raise newException(ScramError, "Security error: invalid nonce received from server. Possible man-in-the-middle attack.")
  if iterations < 0:
    s.state = ENDED
    return ""

  let
    saltedPassword = hi[T](password, salt, iterations)
    clientKey = HMAC[T]($%saltedPassword, CLIENT_KEY)
    storedKey = HASH[T]($%clientKey)
    serverKey = HMAC[T]($%saltedPassword, SERVER_KEY)
    clientFinalMessageWithoutProof = "c=biws,r=" & nonce
    authMessage =[s.clientFirstMessageBare, serverFirstMessage, clientFinalMessageWithoutProof].join(",")
    clientSignature = HMAC[T]($%storedKey, authMessage)
  s.serverSignature = HMAC[T]($%serverKey, authMessage)
  var clientProof = clientKey
  clientProof ^= clientSignature
  s.state = FINAL_PREPARED
  when NimMajor >= 1 and (NimMinor >= 1 or NimPatch >= 2):
    clientFinalMessageWithoutProof & ",p=" & base64.encode(clientProof)
  else:
    clientFinalMessageWithoutProof & ",p=" & base64.encode(clientProof, newLine="")

proc verifyServerFinalMessage*(s: ScramClient, serverFinalMessage: string): bool =
  if s.state != FINAL_PREPARED:
    raise newException(ScramError, "You can call this method only once after calling prepareFinalMessage()")
  s.state = ENDED
  var matches: array[1, string]
  if match(serverFinalMessage, SERVER_FINAL_MESSAGE, matches):
    var proposedServerSignature: string
    for kv in serverFinalMessage.split(','):
      if kv[0..1] == "v=":
        proposedServerSignature = base64.decode(kv[2..^1])
    s.isSuccessful = proposedServerSignature == $%s.serverSignature
  s.isSuccessful

proc isSuccessful*(s: ScramClient): bool =
  if s.state != ENDED:
    raise newException(ScramError, "You cannot call this method before authentication is ended")
  s.isSuccessful

proc isEnded*(s: ScramClient): bool =
  s.state == ENDED

proc getState*(s: ScramClient): ScramState =
  s.state

when isMainModule:
  var s = newScramClient[Sha256Digest]()
  s.clientNonce = "VeAOLsQ22fn/tjalHQIz7cQT"

  echo "test 1"
  let firstMessage = s.prepareFirstMessage("bob")
  # echo firstMessage
  let finalMessage = s.prepareFinalMessage("secret", "r=VeAOLsQ22fn/tjalHQIz7cQTmeE5qJh8qKEe8wALMut1,s=ldZSefTzKxPNJhP73AmW/A==,i=4096")
  # echo finalMessage
  assert(finalMessage == "c=biws,r=VeAOLsQ22fn/tjalHQIz7cQTmeE5qJh8qKEe8wALMut1,p=AtNtxGzsMA8evcWBM0MXFjxN8OcG1KRkLkFyoHlupOU=")
  echo "  passed"

  # test from RFC 5802, see https://tools.ietf.org/html/rfc5802  part 5
  #
  # (username 'user' and password 'pencil' are used):
  #    C: n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL
  #    S: r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,
  #       i=4096
  #    C: c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,
  #       p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
  #    S: v=rmF9pqV8S7suAoZWja4dJRkFsKQ=
  #
  echo "test 2"
  var rfc = newScramClient[Sha1Digest]()
  rfc.clientNonce = "fyko+d2lbbFgONRv9qkxdawL" # override for sake of test
  let rfcC1 = rfc.prepareFirstMessage("user")
  assert(rfcC1 == "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
  let rfcS1 = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"
  # NOTE: the example in the RFC uses a password of "pencil", for applications such as
  #       MongoDb, the "password" is an MD5 of <username>:mongodb:<password>. Such
  #       manipulation occurs before 'prepareFinalMessage' is called.
  let rfcC2 = rfc.prepareFinalMessage("pencil", rfcS1)
  echo rfcC2
  assert(rfcC2 == "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
  echo "  passed"
