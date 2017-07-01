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
    ENDED
