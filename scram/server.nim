import base64, strformat, strutils, hmac, nimSHA2, private/[utils,types]
import checksums/[sha1, md5]

export MD5Digest, SHA1Digest, SHA224Digest, SHA256Digest, SHA384Digest, SHA512Digest, Keccak512Digest
export getChannelBindingData

type
  ScramServer[T] = ref object of RootObj
    serverNonce: string
    clientFirstMessageBare: string
    serverFirstMessage: string
    state: ScramState
    isSuccessful: bool
    userData: UserData
    serverError: ServerError
    serverErrorValueExt: string
    cbType: ChannelType
    cbData: string

  UserData* = object
    salt*: string
    iterations*: int
    serverKey*: string
    storedKey*: string

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

proc setChannelBindingType*[T](s: ScramServer[T], channel: ChannelType) = s.cbType = channel

proc setChannelBindingData*[T](s: ScramServer[T], data: string) = s.cbData = data

proc setServerNonce*[T](s: ScramServer[T], nonce: string) = s.serverNonce = nonce

proc handleClientFirstMessage*[T](s: ScramServer[T], clientFirstMessage: string): string =
  let parts = clientFirstMessage.split(',', 2)
  if parts.len != 3:
    s.state = ENDED
    return

  let gs2CBindFlag = parts[0]
  if (gs2CBindFlag[0] == 'n'):
    if s.cbType != TLS_NONE:
      s.serverError = SERVER_ERROR_SERVER_DOES_SUPPORT_CHANNEL_BINDING
  elif (gs2CBindFlag[0] == 'y'):
    if s.cbType != TLS_NONE:
      s.serverError = SERVER_ERROR_SERVER_DOES_SUPPORT_CHANNEL_BINDING
  elif (gs2CBindFlag[0] == 'p'):
    if s.cbType == TLS_NONE:
      s.serverError = SERVER_ERROR_CHANNEL_BINDING_NOT_SUPPORTED
    let cbName = gs2CBindFlag.split("=")[1]
    if cbName != $s.cbType:
      s.serverError = SERVER_ERROR_UNSUPPORTED_CHANNEL_BINDING_TYPE
  else:
    s.serverError = SERVER_ERROR_OTHER_ERROR
    s.serverErrorValueExt = "Invalid GS2 flag: " & gs2CBindFlag[0]

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


proc makeError(error: ServerError, ext: string = ""): string =
  if error != SERVER_ERROR_NO_ERROR:
    result = "e=" & $error
    if ext.len != 0:
      result &= " " & ext

proc prepareFinalMessage*[T](s: ScramServer[T], clientFinalMessage: string): string =

  if s.serverError != SERVER_ERROR_NO_ERROR:
    result = makeError(s.serverError, s.serverErrorValueExt)
    s.state = ENDED
    return

  var clientFinalMessageWithoutProof, nonce, proof, cbind: string

  for kv in clientFinalMessage.split(','):
    if kv[0..1] == "p=":
      proof = kv[2..^1]
    else:
      if clientFinalMessageWithoutProof.len > 0:
        clientFinalMessageWithoutProof.add(',')
      clientFinalMessageWithoutProof.add(kv)
      if kv[0..1] == "r=":
        nonce = kv[2..^1]
      elif kv[0..1] == "c=":
        cbind = kv

  if cbind != makeCBind(s.cbType, s.cbData):
    result = makeError(SERVER_ERROR_CHANNEL_BINDINGS_DONT_MATCH)
    s.state = ENDED
    return

  if nonce != s.serverNonce:
    result = makeError(SERVER_ERROR_OTHER_ERROR, "Server nonce does not match")
    s.state = ENDED
    return

  let
    authMessage = join([s.clientFirstMessageBare, s.serverFirstMessage, clientFinalMessageWithoutProof], ",")
    storedKey = base64.decode(s.userData.storedKey)
    clientSignature = HMAC[T](storedKey, authMessage)
    serverSignature = HMAC[T](decode(s.userData.serverKey), authMessage)
    decodedProof = base64.decode(proof)
    clientKey = custom_xor(clientSignature, decodedProof)
    resultKey = HASH[T](clientKey).raw_str

  # SECURITY: constant time HMAC check
  if not constantTimeEqual(resultKey, storedKey):
    result = makeError(SERVER_ERROR_OTHER_ERROR, "constant time hmac check failed")
    s.state = ENDED
    return

  s.isSuccessful = true
  s.state = ENDED
  result = "v=" & base64.encode(serverSignature)


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
