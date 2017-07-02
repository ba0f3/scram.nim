type
  ScramError* = object of SystemError

  Sha1Digest* = array[20, uint8]
  
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
  INT_1* = "\x0\x0\x0\x1"
  CLIENT_KEY* = "Client Key"
  SERVER_KEY* = "Server Key"
