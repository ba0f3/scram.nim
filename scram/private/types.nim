from net import Socket
from asyncnet import AsyncSocket

export Socket, AsyncSocket

type
  ScramError* = object of CatchableError

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

  AnySocket* = Socket|AsyncSocket

  ChannelType* = enum
    TLS_NONE
    TLS_SERVER_END_POINT
    TLS_UNIQUE
    TLS_UNIQUE_FOR_TELNET
    TLS_EXPORT

const
  GS2_HEADER* = "n,,"
  INT_1* = "\x00\x00\x00\x01"
  CLIENT_KEY* = "Client Key"
  SERVER_KEY* = "Server Key"