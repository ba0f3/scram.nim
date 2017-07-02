import random, base64, strutils, types, hmac
randomize()

proc `$`*(sha: Sha1Digest): string =
  result = ""
  for v in sha:
    result.add(toHex(int(v), 2))

proc makeNonce*(): string {.inline.} = result = base64.encode($random(1.0))[0..^3]

template `^=`*[T](a, b: T) =
  for x in 0..<a.len:
    when T is Sha1Digest:
      a[x] = (a[x].int32 xor b[x].int32).uint8
    else:
      a[x] = (a[x].int32 xor b[x].int32).char

proc HMAC*[T](password, salt: string): T =
  when T is MD5Digest:
    result = hmac_md5(password, salt)
  elif T is Sha1Digest:
    result = Sha1Digest(hmac_sha1(password, salt))
  elif T is Sha256Digest:
    result = hmac_sha256(password, salt)
  elif T is Sha512Digest:
    result = hmac_sha512(password, salt)

proc HASH*[T](s: string): T =
  when T is MD5Digest:
    result = hash_md5(s)
  elif T is Sha1Digest:
    result = Sha1Digest(hash_sha1(s))
  elif T is Sha256Digest:
    result = hash_sha256(s)
  elif T is Sha512Digest:
    result = hash_sha512(s)

proc hi*[T](password, salt: string, iterations: int): T =
  var previous: T
  result = HMAC[T](password, salt & INT_1)
  previous = result
  for _ in 1..<iterations:
    previous = HMAC[T](password, $previous)
    result ^= previous

proc debug*[T](s: T): string =
  result = ""
  for x in s:
    result.add x.uint8.toHex & " "
