import random, base64
randomize()

proc makeNonce*(): string {.inline.} = result = encode($random(1.0))[0..^3]

template `^=`*[T](a, b: T) =
  for x in 0..<a.len:
    a[x] = (a[x].int32 xor b[x].int32).char
