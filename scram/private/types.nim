type
  ScramError* = object of Exception

  DigestType* = enum
    MD5
    SHA1
    SHA256
    SHA512

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
