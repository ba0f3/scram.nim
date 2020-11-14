type
  ScramError* = object of CatchableError

  DigestType* = enum
    MD5
    SHA_1
    SHA_224
    SHA_256
    SHA_384
    SHA_512
    SHA3_512

  ScramState* = enum
    INITIAL
    FIRST_PREPARED
    FINAL_PREPARED
    FIRST_CLIENT_MESSAGE_HANDLED
    ENDED

const
  GS2_HEADER* = "n,,"
  INT_1* = "\x00\x00\x00\x01"
  CLIENT_KEY* = "Client Key"
  SERVER_KEY* = "Server Key"
