import base64, pegs, random, strutils, hmac, nimSHA2, securehash, md5, private/[utils,types]

export MD5Digest, Sha256Digest, Sha512Digest

type
  ScramClient[T] = ref object of RootObj
    clientNonce: string
    clientFirstBareMessage: string
    state: ScramState
    isSuccessful: bool
    serverSignature: T

const
  GS2_HEADER = "n,,"
  INT_1 = "\x0\x0\x0\x1"
  CLIENT_KEY = "Client Key"
  SERVER_KEY = "Server Key"

let
  SERVER_FIRST_MESSAGE = peg"'r='{[^,]*}',s='{[^,]*}',i='{\d+}$"
  SERVER_FINAL_MESSAGE = peg"'v='{[^,]*}$"


proc HMAC[T](password, salt: string): T =
  when T is MD5Digest:
    result = hmac_md5(password, salt)
  elif T is Sha1Digest:
    result = Sha1Digest(hmac_sha1(password, salt))
  elif T is Sha256Digest:
    result = hmac_sha256(password, salt)
  elif T is Sha512Digest:
    result = hmac_sha512(password, salt)

proc HASH[T](s: string): T =
  when T is MD5Digest:
    result = hash_md5(s)
  elif T is Sha1Digest:
    result = Sha1Digest(hash_sha1(s))
  elif T is Sha256Digest:
    result = hash_sha256(s)
  elif T is Sha512Digest:
    result = hash_sha512(s)


proc hi[T](s: ScramClient[T], password, salt: string, iterations: int): T =
  var previous: T
  result = HMAC[T](password, salt & INT_1)
  previous = result
  for _ in 1..<iterations:
    previous = HMAC[T](password, $previous)
    result ^= previous

proc newScramClient*[T](): ScramClient[T] =
  result = new(ScramClient[T])
  result.state = INITIAL
  result.clientNonce = makeNonce()
  result.isSuccessful = false

proc prepareFirstMessage*(s: ScramClient, username: string): string {.raises: [ScramError]} =
  if username.isNilOrEmpty:
    raise newException(ScramError, "username cannot be nil or empty")
  var username = username.replace("=", "=3D").replace(",", "=2C")
  s.clientFirstBareMessage = "n="
  s.clientFirstBareMessage.add(username)
  s.clientFirstBareMessage.add(",r=")
  s.clientFirstBareMessage.add(s.clientNonce)

  result = GS2_HEADER & s.clientFirstBareMessage
  s.state = FIRST_PREPARED

proc prepareFinalMessage*[T](s: ScramClient[T], password, serverFirstMessage: string): string {.raises: [ScramError, OverflowError, ValueError].} =
  if s.state != FIRST_PREPARED:
    raise newException(ScramError, "First message have not been prepared, call prepareFirstMessage() first")

  var
    nonce, salt: string
    iterations: int

  var matches: array[3, string]
  if match(serverFirstMessage, SERVER_FIRST_MESSAGE, matches):
#  if serverFirstMessage =~ SERVER_FIRST_MESSAGE:
    nonce = matches[0]
    salt = decode(matches[1])
    iterations = parseInt(matches[2])
  else:
    s.state = ENDED
    return nil

  if not nonce.startsWith(s.clientNonce) or iterations < 0:
    s.state = ENDED
    return nil

  let
    saltedPassword = s.hi(password, salt, iterations)
    clientKey = HMAC[T]($saltedPassword, CLIENT_KEY)
    storedKey = HASH[T]($clientKey)
    serverKey = HMAC[T]($saltedPassword, SERVER_KEY)
    clientFinalMessageWithoutProof = "c=" & encode(GS2_HEADER) & ",r=" & nonce
    authMessage = s.clientFirstBareMessage & "," & serverFirstMessage & "," & clientFinalMessageWithoutProof
    clientSignature = HMAC[T]($storedKey, authMessage)

  s.serverSignature = HMAC[T]($serverKey, authMessage)

  var clientProof = clientKey
  clientProof ^= clientSignature
  s.state = FINAL_PREPARED
  result = clientFinalMessageWithoutProof & ",p=" & encode(clientProof, newLine="")

proc verifyServerFinalMessage*(s: ScramClient, serverFinalMessage: string): bool =
  if s.state != FINAL_PREPARED:
    raise newException(ScramError, "You can call this method only once after calling prepareFinalMessage()")
  s.state = ENDED
  var matches: array[1, string]
  if match(serverFinalMessage, SERVER_FINAL_MESSAGE, matches):
    let proposedServerSignature = decode(matches[0])
    s.isSuccessful = proposedServerSignature == s.serverSignature
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
