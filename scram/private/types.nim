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
    TLS_NONE = ""
    TLS_SERVER_END_POINT = "tls-server-end-point"
    TLS_UNIQUE = "tls-unique"
    TLS_UNIQUE_FOR_TELNET = "tls-server-for-telnet"
    TLS_EXPORT = "tls-export"

  ServerError* = enum
    SERVER_ERROR_NO_ERROR = ""
    SERVER_ERROR_INVALID_ENCODING = "invalid-encoding"
    SERVER_ERROR_EXTENSIONS_NOT_SUPPORTED = "extensions-not-supported"
    SERVER_ERROR_INVALID_PROOF = "invalid-proof"
    SERVER_ERROR_CHANNEL_BINDINGS_DONT_MATCH = "channel-bindings-dont-match"
    SERVER_ERROR_SERVER_DOES_SUPPORT_CHANNEL_BINDING = "server-does-support-channel-binding"
    SERVER_ERROR_CHANNEL_BINDING_NOT_SUPPORTED = "channel-binding-not-supported"
    SERVER_ERROR_UNSUPPORTED_CHANNEL_BINDING_TYPE = "unsupported-channel-binding-type"
    SERVER_ERROR_UNKNOWN_USER = "unknown-user"
    SERVER_ERROR_INVALID_USERNAME_ENCODING = "invalid-username-encoding"
    SERVER_ERROR_NO_RESOURCES = "no-resources"
    SERVER_ERROR_OTHER_ERROR = "other-error"


const
  INT_1* = "\x00\x00\x00\x01"
  CLIENT_KEY* = "Client Key"
  SERVER_KEY* = "Server Key"
