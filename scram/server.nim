import base64, pegs, random, strutils, hmac, nimSHA2, securehash, md5, private/[utils,types]

type
  ScramServer*[T] = ref object of RootObj
    serverNonce: string
    clientFirstMessageBare: string
    serverFirstMessage: string
    state: ScramState
    isSuccessful: bool
    userData: UserData

  UserData* = object
    salt: string
    iterations: int
    serverKey: string
    storedKey: string

let
  CLIENT_FIRST_MESSAGE = peg"^([pny]'='?([^,]*)','([^,]*)','){('m='([^,]*)',')?'n='{[^,]*}',r='{[^,]*}(','(.*))*}$"
  CLIENT_FINAL_MESSAGE = peg"{'c='{[^,]*}',r='{[^,]*}}',p='{.*}$"

proc initUserData*(password: string, iterations = 4096): UserData =
  var iterations = iterations
  var password = password
  if password.isNilOrEmpty:
    password =""
    iterations = 1

  let
    salt = makeNonce()[0..24]
    saltedPassword = hi[SHA256Digest](password, salt, iterations)
    clientKey = HMAC[SHA256Digest]($saltedPassword, CLIENT_KEY)
    storedKey = HASH[SHA256Digest]($clientKey)
    serverKey = HMAC[SHA256Digest]($saltedPassword, SERVER_KEY)

  result.salt = base64.encode(salt)
  result.iterations = iterations
  result.storedKey = base64.encode($storedKey)
  result.serverKey = base64.encode($serverKey)

proc initUserData*(salt: string, iterations: int, serverKey, storedKey: string): UserData =
  result.salt = salt
  result.iterations = iterations
  result.serverKey = serverKey
  result.storedKey = storedKey

proc newScramServer*[T](salt: string = nil, iterations = 4096): ScramServer[T] =
  result = new(ScramServer[T])
  result.state = INITIAL
  result.isSuccessful = false

proc handleClientFirstMessage*[T](s: ScramServer[T],clientFirstMessage: string): string =
  var matches: array[3, string]
  if not match(clientFirstMessage, CLIENT_FIRST_MESSAGE, matches):
    s.state = ENDED
    return nil
  s.clientFirstMessageBare = matches[0]
  s.serverNonce = matches[2] & makeNonce()
  s.state = FIRST_CLIENT_MESSAGE_HANDLED
  result = matches[1] # username

proc prepareFirstMessage*(s: ScramServer, userData: UserData): string =
  s.state = FIRST_PREPARED
  s.userData = userData
  s.serverFirstMessage = "r=$#,s=$#,i=$#" % [s.serverNonce, userData.salt, $userData.iterations]
  result = s.serverFirstMessage

proc prepareFinalMessage*[T](s: ScramServer[T], clientFinalMessage: string): string =
  var matches: array[4, string]
  if not match(clientFinalMessage, CLIENT_FINAL_MESSAGE, matches):
    s.state = ENDED
    return nil
  let
    clientFinalMessageWithoutProof = matches[0]
    nonce = matches[2]
    proof = matches[3]

  if nonce != s.serverNonce:
    s.state = ENDED
    return nil

  let
    authMessage = join([s.clientFirstMessageBare, s.serverFirstMessage, clientFinalMessageWithoutProof], ",")
    storedKey = base64.decode(s.userData.storedKey)
    clientSignature = HMAC[T](storedKey, authMessage)
    serverSignature = HMAC[T](decode(s.userData.serverKey), authMessage)
    decodedProof = base64.decode(proof)
  var clientKey = $clientSignature
  clientKey ^= decodedProof

  let resultKey = $HASH[T](clientKey)
  if resultKey != storedKey:
    return nil

  s.isSuccessful = true
  s.state = ENDED
  result = "v=" & base64.encode(serverSignature, newLine="")


proc isSuccessful*(s: ScramServer): bool =
  if s.state != ENDED:
    raise newException(ScramError, "You cannot call this method before authentication is ended")
    return s.isSuccessful

proc isEnded*(s: ScramServer): bool =
  result = s.state == ENDED

proc getState*(s: ScramServer): ScramState =
  result = s.state

when isMainModule:
  import client as c
  var
    username = "bob"
    password = "secret"
    userdata = initUserData(password)

    server = newScramServer[SHA256Digest]()
    client = newScramClient[SHA256Digest]()

  let clientFirstMessage = client.prepareFirstMessage(username)
  echo "Client first message: ", clientFirstMessage

  let username1 = server.handleClientFirstMessage(clientFirstMessage)
  assert(username1 == username)

  let serverFirstMessage = server.prepareFirstMessage(userdata)
  echo "Server first message: ", serverFirstMessage

  let clientFinalMessage = client.prepareFinalMessage(password, serverFirstMessage)
  echo "Client final mesage: ", clientFinalMessage

  let serverFinalMessage = server.prepareFinalMessage(clientFinalMessage)
  echo "Server final mesage: ", serverFinalMessage

  assert client.verifyServerFinalMessage(serverFinalMessage) == true
  echo "Client is successful: ", client.isSuccessful() == true





