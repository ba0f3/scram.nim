import base64, pegs, random, strutils, hmac, sha1, nimSHA2, md5, private/[utils,types]

export MD5Digest, SHA1Digest, SHA256Digest, SHA512Digest

type
  ScramClient[T] = ref object of RootObj
    clientNonce: string
    clientFirstMessageBare: string
    state: ScramState
    isSuccessful: bool
    serverSignature: T

let
  SERVER_FIRST_MESSAGE = peg"'r='{[^,]*}',s='{[^,]*}',i='{\d+}$"
  SERVER_FINAL_MESSAGE = peg"'v='{[^,]*}$"


proc newScramClient*[T](): ScramClient[T] =
  result = new(ScramClient[T])
  result.state = INITIAL
  result.clientNonce = makeNonce()
  result.isSuccessful = false

proc prepareFirstMessage*(s: ScramClient, username: string): string {.raises: [ScramError]} =
  if username.isNilOrEmpty:
    raise newException(ScramError, "username cannot be nil or empty")
  var username = username.replace("=", "=3D").replace(",", "=2C")
  s.clientFirstMessageBare = "n="
  s.clientFirstMessageBare.add(username)
  s.clientFirstMessageBare.add(",r=")
  s.clientFirstMessageBare.add(s.clientNonce)

  result = GS2_HEADER & s.clientFirstMessageBare
  s.state = FIRST_PREPARED

proc prepareFinalMessage*[T](s: ScramClient[T], password, serverFirstMessage: string): string {.raises: [ScramError, OverflowError, ValueError].} =
  if s.state != FIRST_PREPARED:
    raise newException(ScramError, "First message have not been prepared, call prepareFirstMessage() first")
  var
    nonce, salt: string
    iterations: int
  var matches: array[3, string]
  if match(serverFirstMessage, SERVER_FIRST_MESSAGE, matches):
    nonce = matches[0]
    salt = base64.decode(matches[1])
    iterations = parseInt(matches[2])
  else:
    s.state = ENDED
    return nil

  if not nonce.startsWith(s.clientNonce) or iterations < 0:
    s.state = ENDED
    return nil

  let
    saltedPassword = hi[T](password, salt, iterations)
    clientKey = HMAC[T]($saltedPassword, CLIENT_KEY)
    storedKey = HASH[T]($clientKey)
    serverKey = HMAC[T]($saltedPassword, SERVER_KEY)
    clientFinalMessageWithoutProof = "c=" & base64.encode(GS2_HEADER) & ",r=" & nonce
    authMessage = s.clientFirstMessageBare & "," & serverFirstMessage & "," & clientFinalMessageWithoutProof
    clientSignature = HMAC[T]($storedKey, authMessage)
  s.serverSignature = HMAC[T]($serverKey, authMessage)
  var clientProof = clientKey
  clientProof ^= clientSignature
  s.state = FINAL_PREPARED
  result = clientFinalMessageWithoutProof & ",p=" & base64.encode(clientProof, newLine="")

proc verifyServerFinalMessage*(s: ScramClient, serverFinalMessage: string): bool =
  if s.state != FINAL_PREPARED:
    raise newException(ScramError, "You can call this method only once after calling prepareFinalMessage()")
  s.state = ENDED
  var matches: array[1, string]
  if match(serverFinalMessage, SERVER_FINAL_MESSAGE, matches):
    let proposedServerSignature = base64.decode(matches[0])
    s.isSuccessful = proposedServerSignature == $s.serverSignature
  result = s.isSuccessful

proc isSuccessful*(s: ScramClient): bool =
  if s.state != ENDED:
    raise newException(ScramError, "You cannot call this method before authentication is ended")
  return s.isSuccessful

proc isEnded*(s: ScramClient): bool =
  result = s.state == ENDED

proc getState*(s: ScramClient): ScramState =
  result = s.state

when isMainModule:
  var s = newScramClient[Sha256Digest]()
  s.clientNonce = "VeAOLsQ22fn/tjalHQIz7cQT"

  echo s.prepareFirstMessage("bob")
  let finalMessage = s.prepareFinalMessage("secret", "r=VeAOLsQ22fn/tjalHQIz7cQTmeE5qJh8qKEe8wALMut1,s=ldZSefTzKxPNJhP73AmW/A==,i=4096")
  echo finalMessage
  assert(finalMessage == "c=biws,r=VeAOLsQ22fn/tjalHQIz7cQTmeE5qJh8qKEe8wALMut1,p=AtNtxGzsMA8evcWBM0MXFjxN8OcG1KRkLkFyoHlupOU=")
