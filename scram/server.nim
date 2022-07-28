import strformat, strutils, base64, pegs, hmac, nimSHA2, private/[utils,types]

type
  ScramServer[T] = ref object of RootObj
    serverNonce: string
    clientFirstMessageBare: string
    serverFirstMessage: string
    state: ScramState
    isSuccessful: bool
    userData: UserData
    cbType: ChannelType
    cbData: string

  UserData* = object
    salt*: string
    iterations*: int
    serverKey*: string
    storedKey*: string

let
  CLIENT_FIRST_MESSAGE = peg"^([pny]'='?([^,]*)','([^,]*)','){('m='([^,]*)',')?'n='{[^,]*}',r='{[^,]*}(','(.*))*}$"
  CLIENT_FINAL_MESSAGE = peg"{'c='{[^,]*}',r='{[^,]*}}',p='{.*}$"

proc initUserData*[T](typ: typedesc[T], password: string, iterations = 4096): UserData =
  var iterations = iterations
  if password.len == 0:
    iterations = 1
  let
    salt = makeNonce()[0..24]
    saltedPassword = hi[T](password, salt, iterations)
    clientKey = HMAC[T]($%saltedPassword, CLIENT_KEY)
    storedKey = HASH[T]($%clientKey)
    serverKey = HMAC[T]($%saltedPassword, SERVER_KEY)

  result.salt = base64.encode(salt)
  result.iterations = iterations
  result.storedKey = base64.encode($%storedKey)
  result.serverKey = base64.encode($%serverKey)

proc initUserData*(password: string, iterations = 4096): UserData =
  initUserData(Sha256Digest, password, iterations)

proc initUserData*(salt: string, iterations: int, serverKey, storedKey: string): UserData =
  result.salt = salt
  result.iterations = iterations
  result.serverKey = serverKey
  result.storedKey = storedKey

proc newScramServer*[T](): ScramServer[T] =
  result = new ScramServer[T]
  result.state = INITIAL
  result.isSuccessful = false
  result.cbType = TLS_NONE

proc newScramServer*[T](channel = TLS_UNIQUE, socket: AnySocket): ScramServer[T] =
  result = newScramServer[T]()
  validateCB(channel, socket)
  result.cbType = channel
  result.cbData = getCBData(channel, socket)

proc handleClientFirstMessage*[T](s: ScramServer[T],clientFirstMessage: string): string =
  let parts = clientFirstMessage.split(',', 2)
  #var matches: array[3, string]
  #if not match(clientFirstMessage, CLIENT_FIRST_MESSAGE, matches) or not parts.len == 3:
  #  s.state = ENDED
  #  return

  #if (gs2Header == "n"):


  s.clientFirstMessageBare = parts[2]
  for kv in s.clientFirstMessageBare.split(','):
    if kv[0..1] == "n=":
      result = kv[2..^1]
    elif kv[0..1] == "r=":
      s.serverNonce = kv[2..^1] & makeNonce()

  s.state = FIRST_CLIENT_MESSAGE_HANDLED

proc prepareFirstMessage*(s: ScramServer, userData: UserData): string =
  s.state = FIRST_PREPARED
  s.userData = userData
  s.serverFirstMessage = "r=$#,s=$#,i=$#" % [s.serverNonce, userData.salt, $userData.iterations]
  s.serverFirstMessage

proc prepareFinalMessage*[T](s: ScramServer[T], clientFinalMessage: string): string =
  var matches: array[4, string]
  if not match(clientFinalMessage, CLIENT_FINAL_MESSAGE, matches):
    s.state = ENDED
    return
  var clientFinalMessageWithoutProof, nonce, proof: string
  for kv in clientFinalMessage.split(','):
    if kv[0..1] == "p=":
      proof = kv[2..^1]
    else:
      if clientFinalMessageWithoutProof.len > 0:
        clientFinalMessageWithoutProof.add(',')
      clientFinalMessageWithoutProof.add(kv)
      if kv[0..1] == "r=":
        nonce = kv[2..^1]

  if nonce != s.serverNonce:
    s.state = ENDED
    return

  let
    authMessage = join([s.clientFirstMessageBare, s.serverFirstMessage, clientFinalMessageWithoutProof], ",")
    storedKey = base64.decode(s.userData.storedKey)
    clientSignature = HMAC[T](storedKey, authMessage)
    serverSignature = HMAC[T](decode(s.userData.serverKey), authMessage)
    decodedProof = base64.decode(proof)
    clientKey = custom_xor(clientSignature, decodedProof)
  let resultKey = HASH[T](clientKey).raw_str

  # SECURITY: constant time HMAC check
  if not constantTimeEqual(resultKey, storedKey):
    let k1 = base64.encode(resultKey)
    let k2 = base64.encode(storedKey)
    return

  s.isSuccessful = true
  s.state = ENDED
  when NimMajor >= 1 and (NimMinor >= 1 or NimPatch >= 2):
    result = "v=" & base64.encode(serverSignature)
  else:
    result = "v=" & base64.encode(serverSignature, newLine="")


proc isSuccessful*(s: ScramServer): bool =
  if s.state != ENDED:
    raise newException(ScramError, "You cannot call this method before authentication is ended")
  s.isSuccessful

proc isEnded*(s: ScramServer): bool =
  s.state == ENDED

proc getState*(s: ScramServer): ScramState =
  s.state

when isMainModule:
  import client as c, net
  var
    username = "bob"
    password = "secret"
    userdata = initUserData(password)

    server = newScramServer[SHA256Digest]()
    client = newScramClient[SHA256Digest]()

  assert(server.state == INITIAL)
  assert(server.isSuccessful == false)

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

  var
    socket = newSocket()
    server1 = newScramServer[SHA256Digest](TLS_UNIQUE, socket)
