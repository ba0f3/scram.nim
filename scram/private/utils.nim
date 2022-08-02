import random, base64, strutils, types, hmac, bitops, openssl, net, asyncnet
from md5 import MD5Digest
from sha1 import Sha1Digest
from nimSHA2 import Sha224Digest, Sha256Digest, Sha384Digest, Sha512Digest


#from net import Socket
#from asyncnet import AsyncSocket

#export Socket, AsyncSocket

type
  AnySocket* = Socket|AsyncSocket

const
  NID_md5 = 4
  NID_md5_sha1 = 114
  EVP_MAX_MD_SIZE = 64

{.push cdecl, dynlib: DLLSSLName, importc.}

proc SSL_get_finished(ssl: SslPtr, buf: cstring, count: csize_t): csize_t
proc SSL_get_peer_finished(ssl: SslPtr, buf: cstring, count: csize_t): csize_t

proc SSL_get_certificate(ssl: SslPtr): PX509
proc SSL_get_peer_certificate(ssl: SslPtr): PX509

proc X509_get_signature_nid(x: PX509): int32
proc OBJ_find_sigid_algs(signature: int32, pdigest: pointer, pencryption: pointer): int32
proc OBJ_nid2sn(n: int): cstring

proc EVP_sha256(): PEVP_MD
proc EVP_get_digestbynid(): PEVP_MD

proc X509_digest(data: PX509, kind: PEVP_MD, md: ptr char, len: ptr uint32): int32

{.pop.}

randomize()

proc `$%`*[T](input: T): string =
  result = newString(input.len)
  for i in 0..<input.len:
    result[i] = input[i].char

template makeNonce*(): string =
  base64.encode(hmac_sha1($rand(int.high), "scram.nim"))

template `^=`*[T](a, b: T) =
  for x in 0..<a.len:
    when T is Sha1Digest or T is Keccak512Digest or T is SHA256Digest:
      a[x] = (a[x].int32 xor b[x].int32).uint8
    else:
      a[x] = (a[x].int32 xor b[x].int32).char

proc custom_xor*[T](bytes: T, str: string): string =
  if bytes.len != str.len:
    raise newException(RangeDefect, "xor must have both arguments of the same size")
  result = str
  for x in 0..<bytes.len:
    result[x] = (bytes[x].uint8 xor str[x].uint8).char

proc constantTimeEqual*(a, b: string): bool =
  if a.len != b.len:
    raise newException(RangeDefect, "must have both arguments of the same size")
  var res: uint8 = 0
  for x in 0..<a.len:
    res = bitor(res, bitxor(a[x].uint8, b[x].uint8))
  result = (res == 0)

proc HMAC*[T](password, salt: string): T =
  when T is MD5Digest:
    result = hmac_md5(password, salt)
  elif T is Sha1Digest:
    result = hmac_sha1(password, salt)
  elif T is Sha224Digest:
    result = hmac_sha224(password, salt)
  elif T is Sha256Digest:
    result = hmac_sha256(password, salt)
  elif T is Sha384Digest:
    result = hmac_sha384(password, salt)
  elif T is Sha512Digest:
    result = hmac_sha512(password, salt)
  elif T is Keccak512Digest:
    result = hmac_keccak512(password, salt)

proc raw_str*[T](digest: T): string =
  when T is Sha1Digest:
    for c in digest: result.add(char(c))
  else:
    result = $digest

proc HASH*[T](s: string): T =
  when T is MD5Digest:
    result = hash_md5(s)
  elif T is Sha1Digest:
    result = hash_sha1(s)
  elif T is Sha224Digest:
    result = hash_sha224(s)
  elif T is Sha256Digest:
    result = hash_sha256(s)
  elif T is Sha384Digest:
    result = hmac_sha384(s)
  elif T is Sha512Digest:
    result = hash_sha512(s)
  elif T is Keccak512Digest:
    result = hash_keccak512(s)

proc debug[T](s: T): string =
  result = ""
  for x in s:
    result.add strutils.toHex(x.uint8).toLowerAscii

proc hi*[T](password, salt: string, iterations: int): T =
  var previous = HMAC[T](password, salt & INT_1)
  result = previous
  for _ in 1..<iterations:
    previous = HMAC[T](password, $%previous)
    result ^= previous

proc makeGS2Header*(channel: ChannelType): string =
  result = case channel
    of TLS_UNIQUE: "p=tls-unique,,"
    of TLS_SERVER_END_POINT: "p=tls-server-end-point,,"
    of TLS_UNIQUE_FOR_TELNET: "p=tls-server-for-telnet,,"
    of TLS_EXPORT: "p=tls-export,,"
    else: "n,,"

proc makeCBind*(channel: ChannelType, data: string = ""): string =
  if channel == TLS_NONE:
    result = "c=biws"
  else:
    result = "c=" & base64.encode(makeGS2Header(channel) & data)


proc validateChannelBinding*(channel: ChannelType, socket: AnySocket) =
  if channel == TLS_NONE:
    return

  if channel > TLS_EXPORT:
    raise newException(ScramError, "Channel type " & $channel & " is not supported")

  if socket.isNil:
    raise newException(ScramError, "Socket is not initialized")

  if not socket.isSsl or socket.sslHandle() == nil:
    raise newException(ScramError, "Socket is not wrapped in a SSL context")

proc getChannelBindingData*(channel: ChannelType, socket: AnySocket, isServer = true): string =
  # Ref: https://paquier.xyz/postgresql-2/channel-binding-openssl/

  validateChannelBinding(channel, socket)

  result = newString(EVP_MAX_MD_SIZE)
  if channel == TLS_UNIQUE:
    var ret: csize_t
    if isServer:
      ret = SSL_get_peer_finished(socket.sslHandle(), result.cstring, EVP_MAX_MD_SIZE)
    else:
      ret = SSL_get_finished(socket.sslHandle(), result.cstring, EVP_MAX_MD_SIZE)

    if ret == 0:
      raise newException(ScramError, "SSLError: handshake has not reached the finished message")
    result.setLen(ret)

  elif channel == TLS_SERVER_END_POINT:
    var
      serverCert: PX509
      algoNid: int32
      algoType: PEVP_MD
      hash: array[EVP_MAX_MD_SIZE, char]
      hashSize: int32

    if isServer:
      serverCert = cast[PX509](SSL_get_certificate(socket.sslHandle()))
    else:
      serverCert = cast[PX509](SSL_get_peer_certificate(socket.sslHandle()))

    if serverCert == nil:
      raise newException(ScramError, "SSLError: could not load server certtificate")

    if OBJ_find_sigid_algs(X509_get_signature_nid(serverCert), addr algoNid, nil) == 0:
      raise newException(ScramError, "SSLError: could not determine server certificate signature algorithm")

    if algoNid == NID_md5 or algoNid == NID_md5_sha1:
      algoType = EVP_sha256()
    else:
      algoType = EVP_get_digestbynid(algoNid)
      if algoType == nil:
        raise newException(ScramError, "SSLError: could not find digest for NID " & OBJ_nid2sn(algoNid))

    if X509_digest(serverCert, algoType, hash, addr hashSize) == 0:
      raise newException(ScramError, "SSLError: could not generate server certificate hash")

    copyMem(addr result[0], hash, hashSize)
    result.setLen(hashSize)

  else:
    raise newException(ScramError, "Channel " & $channel & " is not supported yet")