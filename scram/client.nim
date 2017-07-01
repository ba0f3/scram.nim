import base64, pegs, random, strutils, hmac, nimSHA2, private/utils

type
  ScramError* = object of SystemError

  ScramState = enum
    INITIAL
    FIRST_PREPARED
    FINAL_PREPARED
    ENDED

  DigestType* = enum
    SHA1
    SHA256
    SHA512

  ScramClient = ref object of RootObj
    clientNonce: string
    clientFirstBareMessage: string
    digestType: DigestType
    state: ScramState
    isSuccessful: bool
    serverSignature: string

const
  GS2_HEADER = "n,,"
  INT_1 = "\x0\x0\x0\x1"
  CLIENT_KEY = "Client Key"
  SERVER_KEY = "Server Key"

let
  SERVER_FIRST_MESSAGE = peg"'r='{[^,]*}',s='{[^,]*}',i='{\d+}$"
  SERVER_FINAL_MESSAGE = peg"'v='{[^,]*}$"

proc hi(s: ScramClient, password, salt: string, iterations: int): string =
  var previous: string
  result = $hmac_sha256(password, salt & INT_1)
  previous = result
  for _ in 1..<iterations:
    previous = $hmac_sha256(password, previous)
    result ^= previous

proc newScramClient*(digestType: DigestType): ScramClient =
  result = new(ScramClient)
  result.state = INITIAL
  result.digestType = digestType
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

proc prepareFinalMessage*(s: ScramClient, password, serverFirstMessage: string): string {.raises: [ScramError, OverflowError, ValueError].} =
  var
    nonce, salt: string
    iterations: int

  if s.state != FIRST_PREPARED:
    raise newException(ScramError, "First message have not been prepared, call prepareFirstMessage() first")

  if serverFirstMessage =~ SERVER_FIRST_MESSAGE:
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
    clientKey = $hmac_sha256(saltedPassword, CLIENT_KEY)
    storedKey = $computeSHA256(clientKey)
    serverKey = $hmac_sha256(saltedPassword, SERVER_KEY)
    clientFinalMessageWithoutProof = "c=" & encode(GS2_HEADER) & ",r=" & nonce
    authMessage = s.clientFirstBareMessage & "," & serverFirstMessage & "," & clientFinalMessageWithoutProof
    clientSignature = $hmac_sha256(storedKey, authMessage)

  s.serverSignature = $hmac_sha256(serverKey, authMessage)

  var clientProof = clientKey
  clientProof ^= clientSignature
  s.state = FINAL_PREPARED
  result = clientFinalMessageWithoutProof & ",p=" & encode(clientProof, newLine="")

proc verifyServerFinalMessage*(s: ScramClient, serverFinalMessage: string): bool =
  if s.state != FINAL_PREPARED:
    raise newException(ScramError, "You can call this method only once after calling prepareFinalMessage()")
  s.state = ENDED
  if serverFinalMessage =~ SERVER_FINAL_MESSAGE:
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
  var s = newScramClient(SHA256)
  s.clientNonce = "VeAOLsQ22fn/tjalHQIz7cQT"

  echo s.prepareFirstMessage("bob")
  let finalMessage = s.prepareFinalMessage("secret", "r=VeAOLsQ22fn/tjalHQIz7cQTmeE5qJh8qKEe8wALMut1,s=ldZSefTzKxPNJhP73AmW/A==,i=4096")
  echo finalMessage
  assert(finalMessage == "c=biws,r=VeAOLsQ22fn/tjalHQIz7cQTmeE5qJh8qKEe8wALMut1,p=AtNtxGzsMA8evcWBM0MXFjxN8OcG1KRkLkFyoHlupOU=")
