import random, base64, strutils, types
randomize()

proc `$`*(sha: Sha1Digest): string =
  result = ""
  for v in sha:
    result.add(toHex(int(v), 2))

proc makeNonce*(): string {.inline.} = result = encode($random(1.0))[0..^3]

template `^=`*[T](a, b: T) =
  for x in 0..<sizeof(a):
    when T is Sha1Digest:
      a[x] = (a[x].int32 xor b[x].int32).uint8
    else:
      a[x] = (a[x].int32 xor b[x].int32).char
